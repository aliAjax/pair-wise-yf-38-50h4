from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, InvalidTransition, NotFoundError, ValidationError
from .rules import RuleEngine, compute_scope


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
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        payload = self.rules.validate_create(actor, kind, dict(data or {}), self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def create_batch(self, actor, kind, items, batch_id=None):
        kind = self.rules.normalize_kind(kind)
        if not batch_id:
            raise ValidationError("batch_id is required")
        if not isinstance(items, list) or not items:
            raise ValidationError("items must be a non-empty list")
        status = self.rules.initial_status(kind)
        prepared = []
        for index, item in enumerate(items):
            payload = self.rules.validate_create(actor, kind, dict(item or {}), self._lookup)
            entity_id = str(payload.pop("id", "") or uuid4())
            item_key = payload.pop("idempotency_key", None)
            prepared.append({
                "id": entity_id,
                "kind": kind,
                "status": status,
                "data": payload,
                "actor_id": actor.user_id,
                "idem_key": "batch:%s:%s" % (batch_id, item_key if item_key is not None else index),
            })
        landed = self.repository.create_entities_batch(prepared)
        entities = []
        for entity_id, created in landed:
            entity = self.repository.get_entity(entity_id)
            if created:
                self.audit.record(
                    entity_id, actor, "create", None, entity["status"],
                    {"kind": kind, "batch_id": batch_id},
                )
            entities.append(entity)
        return entities

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        if entity["kind"] == "dataset" and action == "reclassify":
            return self._reclassify_dataset(actor, entity, action, next_status, merged, expected, patch)
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

    def _reclassify_dataset(self, actor, entity, action, next_status, merged, expected, patch):
        """Recompute every live grant scope in the same transaction as the dataset update."""
        dataset_id = entity["id"]
        field_levels = merged.get("field_levels") or {}
        classification_version = merged.get("classification_version", 1)
        grants = [
            grant
            for grant in self.repository.find_entities("grant", "dataset_id", dataset_id)
            if grant["status"] in ("issued", "active")
        ]
        updates = [{
            "id": dataset_id,
            "expected_version": expected,
            "status": next_status,
            "data": merged,
        }]
        for grant in grants:
            grant_data = dict(grant["data"])
            grant_data.update({
                "scope": compute_scope(field_levels, grant["data"].get("approved_level", "public")),
                "classification_version": classification_version,
                "scope_version": int(grant["data"].get("scope_version", 1)) + 1,
            })
            updates.append({
                "id": grant["id"],
                "expected_version": grant["version"],
                "status": grant["status"],
                "data": grant_data,
            })
        self.repository.update_entities_batch(updates)
        self.audit.record(
            dataset_id, actor, action, entity["status"], next_status,
            {"patch": patch, "grants_recomputed": len(grants)},
        )
        for update, grant in zip(updates[1:], grants):
            self.audit.record(
                update["id"], actor, "scope_recompute", grant["status"], grant["status"],
                {
                    "dataset_id": dataset_id,
                    "classification_version": classification_version,
                    "old_scope": grant["data"].get("scope") or [],
                    "new_scope": update["data"]["scope"],
                },
            )
        return self.repository.get_entity(dataset_id)

    def fetch(self, actor, grant_id, fields=None):
        entity = self.repository.get_entity(grant_id)
        if not entity:
            raise NotFoundError("entity not found: " + grant_id)
        if entity["kind"] != "grant":
            raise ValidationError("only grants can fetch data")
        if entity["status"] != "active":
            raise InvalidTransition("cannot fetch from status " + entity["status"])
        returned = self.rules.validate_fetch(actor, entity, fields)
        self.audit.record(
            grant_id, actor, "fetch", entity["status"], entity["status"],
            {"fields": returned, "scope_version": entity["data"].get("scope_version", 1)},
        )
        return {
            "grant_id": grant_id,
            "dataset_id": entity["data"].get("dataset_id"),
            "fields": returned,
            "scope": list(entity["data"].get("scope") or []),
            "scope_version": entity["data"].get("scope_version", 1),
            "classification_version": entity["data"].get("classification_version", 1),
        }

    def reconcile(self, actor, dataset_id, external_field_levels):
        external = self.rules.validate_reconcile(actor, external_field_levels)
        dataset = self.repository.get_entity(dataset_id)
        if not dataset or dataset["kind"] != "dataset":
            raise NotFoundError("dataset not found: " + str(dataset_id))
        grants = [
            grant
            for grant in self.repository.find_entities("grant", "dataset_id", dataset_id)
            if grant["status"] in ("issued", "active")
        ]
        discrepancies = []
        for grant in grants:
            expected = compute_scope(external, grant["data"].get("approved_level", "public"))
            scope = list(grant["data"].get("scope") or [])
            overreach = sorted(set(scope) - set(expected))
            missing = sorted(set(expected) - set(scope))
            if overreach or missing:
                discrepancies.append({
                    "grant_id": grant["id"],
                    "status": grant["status"],
                    "approved_level": grant["data"].get("approved_level", "public"),
                    "overreach": overreach,
                    "missing": missing,
                    "scope_version": grant["data"].get("scope_version", 1),
                })
        self.audit.record(
            dataset_id, actor, "reconcile", dataset["status"], dataset["status"],
            {"checked": len(grants), "discrepancies": len(discrepancies)},
        )
        return {
            "dataset_id": dataset_id,
            "checked": len(grants),
            "discrepancies": discrepancies,
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
