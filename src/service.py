from uuid import uuid4

from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError, PermissionDenied, ScopeViolation, ValidationError
from .repository import utcnow
from .rules import RuleEngine, valid_grant_window


FETCH_ROLES = ("admin", "committee", "applicant")
RECONCILE_ROLES = ("auditor", "admin", "committee")


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None, idempotency_key=None):
        if action == "reclassify":
            return self.reclassify(
                actor,
                entity_id,
                (data or {}).get("fields"),
                expected_version,
                idempotency_key,
            )
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if expected_version is not None and int(expected_version) != entity["version"]:
            raise ConflictError(
                "version conflict: expected %s, found %s"
                % (expected_version, entity["version"])
            )
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return updated

    def reclassify(self, actor, dataset_id, fields, expected_version=None, idempotency_key=None):
        entity = self.repository.get_entity(dataset_id)
        if not entity:
            raise NotFoundError("entity not found: " + dataset_id)
        if entity["kind"] != "dataset":
            raise ValidationError("reclassify only applies to datasets")
        self.rules.validate_reclassify(actor, entity, {"fields": fields})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                dataset = self.repository.get_entity(existing)
                if dataset and dataset["kind"] == "dataset":
                    self.repository.reconcile_grant_scopes(existing)
                    return dataset
        current_version = int(entity["data"].get("classification_version", 1))
        target_version = current_version + 1
        updated = self.repository.transactional_reclassify(
            dataset_id, expected_version, fields, target_version, actor
        )
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, dataset_id)
        return updated

    def fetch(self, actor, grant_id, fields=None):
        grant = self.repository.get_entity(grant_id)
        if not grant:
            raise NotFoundError("grant not found: " + grant_id)
        if grant["kind"] != "grant":
            raise ValidationError("fetch target is not a grant")
        self.rules._ensure_role(actor, FETCH_ROLES)
        if grant["status"] != "active":
            raise PermissionDenied("grant is not active")
        if not valid_grant_window(grant["data"].get("expires_at"), utcnow()):
            raise PermissionDenied("grant has expired")
        scope = grant["data"].get("field_scope") or []
        requested = list(scope) if fields is None else fields
        if not isinstance(requested, list):
            raise ValidationError("fields must be a list")
        out_of_scope = [name for name in requested if name not in scope]
        if out_of_scope:
            raise ScopeViolation("field out of scope: " + ", ".join(out_of_scope))
        self.audit.record(
            grant_id,
            actor,
            "fetch",
            grant["status"],
            grant["status"],
            {"fields": requested, "granted": list(scope)},
        )
        return {
            "grant_id": grant_id,
            "fields": {name: "demo:" + name for name in requested},
            "scope": scope,
            "classification_version": grant["data"].get("classification_version", 1),
        }

    def reconcile(self, actor, grant_id):
        grant = self.repository.get_entity(grant_id)
        if not grant or grant["kind"] != "grant":
            raise NotFoundError("grant not found: " + grant_id)
        self.rules._ensure_role(actor, RECONCILE_ROLES)
        dataset = self.repository.get_entity(grant["data"].get("dataset_id"))
        return self._reconcile_grant(grant, dataset)

    def reconcile_dataset(self, actor, dataset_id):
        dataset = self.repository.get_entity(dataset_id)
        if not dataset or dataset["kind"] != "dataset":
            raise NotFoundError("dataset not found: " + dataset_id)
        self.rules._ensure_role(actor, RECONCILE_ROLES)
        grants = [
            grant
            for grant in self.repository.list_entities(kind="grant")
            if grant["data"].get("dataset_id") == dataset_id
        ]
        return {
            "dataset_id": dataset_id,
            "classification_version": dataset["data"].get("classification_version", 1),
            "grants": [self._reconcile_grant(grant, dataset) for grant in grants],
        }

    @staticmethod
    def _reconcile_grant(grant, dataset):
        scope = grant["data"].get("field_scope") or []
        clearance = int(grant["data"].get("clearance_level", 2))
        classification = dataset["data"].get("fields") if dataset else []
        dataset_version = (
            dataset["data"].get("classification_version", 1) if dataset else None
        )
        grant_version = int(grant["data"].get("classification_version", 1))
        by_name = {item["name"]: item["sensitivity"] for item in classification}
        drift = []
        for name in scope:
            if name not in by_name:
                drift.append({"field": name, "issue": "removed_from_dataset"})
            elif by_name[name] > clearance:
                drift.append(
                    {
                        "field": name,
                        "issue": "upgraded_beyond_clearance",
                        "current_sensitivity": by_name[name],
                        "clearance_level": clearance,
                    }
                )
        stale = dataset_version is not None and grant_version < dataset_version
        return {
            "grant_id": grant["id"],
            "scope": scope,
            "clearance_level": clearance,
            "classification_version": dataset_version,
            "grant_classification_version": grant_version,
            "stale": stale,
            "valid": not drift and not stale,
            "drift": drift,
        }

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
