from datetime import datetime, timedelta, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)

SENSITIVITY_LEVELS = ("public", "internal", "sensitive", "restricted")


def level_rank(level):
    try:
        return SENSITIVITY_LEVELS.index(str(level))
    except ValueError:
        raise ValidationError("unknown sensitivity level: " + str(level))


def compute_scope(field_levels, max_level):
    """Readable fields are those classified at or below max_level."""
    if not field_levels:
        return []
    rank = level_rank(max_level)
    return sorted(
        field for field, level in field_levels.items() if level_rank(level) <= rank
    )


def _validate_field_levels(field_levels):
    if not isinstance(field_levels, dict):
        raise ValidationError("field_levels must map field names to sensitivity levels")
    for field, level in field_levels.items():
        if not str(field).strip():
            raise ValidationError("field name must not be empty")
        level_rank(level)
    return dict(field_levels)


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")
    if data.get("field_levels") is not None:
        _validate_field_levels(data.get("field_levels"))


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")
    if data.get("requested_level") is not None:
        level_rank(data.get("requested_level"))


def _validate_grant(actor, data, lookup):
    application = _find_one(lookup, "application", "id", data.get("application_id"))
    if not application:
        raise ValidationError("application does not exist")
    if application.get("status") not in ("approved", "scope_confirmed"):
        raise ValidationError("application is not approved")
    if data.get("dataset_id") != application.get("data", {}).get("dataset_id"):
        raise ValidationError("dataset does not match application")
    approved = application.get("data", {})
    return {
        "approved_level": approved.get("approved_level", "public"),
        "scope": list(approved.get("field_scope") or []),
        "classification_version": approved.get("classification_version", 1),
        "scope_version": 1,
    }


def _scope_snapshot(entity, lookup, approved_level=None):
    entity_data = entity.get("data", {})
    dataset = _find_one(lookup, "dataset", "id", entity_data.get("dataset_id"))
    dataset_data = (dataset or {}).get("data", {})
    field_levels = dataset_data.get("field_levels") or {}
    level = (
        approved_level
        or entity_data.get("approved_level")
        or entity_data.get("requested_level")
        or "public"
    )
    return {
        "approved_level": level,
        "field_scope": compute_scope(field_levels, level),
        "scope_classification": dict(field_levels),
        "classification_version": dataset_data.get("classification_version", 1),
    }


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")
    return _scope_snapshot(entity, lookup, approved_level=data.get("approved_level"))


def _validate_confirm_scope(actor, entity, data, lookup):
    if entity.get("data", {}).get("field_scope") is not None:
        return {}
    return _scope_snapshot(entity, lookup)


def _validate_reclassify(actor, entity, data, lookup):
    field_levels = _validate_field_levels(data.get("field_levels"))
    current = entity.get("data", {}).get("classification_version", 1)
    return {"field_levels": field_levels, "classification_version": int(current) + 1}


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    return {"activated_by": actor.user_id}


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application, 'grant': _validate_grant}
CUSTOM_TRANSITIONS = {('application', 'approve'): _validate_approve, ('application', 'confirm_scope'): _validate_confirm_scope, ('dataset', 'reclassify'): _validate_reclassify, ('grant', 'activate'): _validate_grant_activate}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {'dataset': {'restrict': (('registered',), 'restricted'), 'publish': (('restricted',), 'published'), 'reclassify': (('registered', 'restricted', 'published'), None)}, 'application': {'submit': (('draft',), 'submitted'), 'review': (('submitted',), 'under_review'), 'approve': (('under_review',), 'approved'), 'confirm_scope': (('approved',), 'scope_confirmed'), 'reject': (('under_review',), 'rejected'), 'withdraw': (('submitted', 'under_review'), 'withdrawn')}, 'grant': {'activate': (('issued',), 'active'), 'revoke': (('active',), 'revoked'), 'expire': (('active',), 'expired')}}
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('dataset', 'reclassify'): ('field_levels', 'reason'), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'reclassify': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'confirm_scope': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee')}

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        extra = custom(actor, data, lookup) if custom else None
        merged = dict(data)
        if extra:
            merged.update(extra)
        return merged

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        if next_status is None:
            next_status = entity["status"]
        return next_status, patch

    def validate_fetch(self, actor, entity, fields):
        self._ensure_role(actor, ("admin", "applicant"))
        data = entity.get("data", {})
        recipient = data.get("recipient")
        if actor.role != "admin" and recipient and actor.user_id != recipient:
            raise PermissionDenied("only the grant recipient can fetch data")
        expires_at = data.get("expires_at")
        if expires_at and not valid_grant_window(
            expires_at, datetime.now(timezone.utc).date().isoformat()
        ):
            raise PermissionDenied("grant window has expired")
        scope = list(data.get("scope") or [])
        requested = [str(field) for field in fields] if fields else list(scope)
        outside = sorted(set(requested) - set(scope))
        if outside:
            raise PermissionDenied("fields outside grant scope: " + ", ".join(outside))
        return requested

    def validate_reconcile(self, actor, external_field_levels):
        self._ensure_role(actor, ("auditor", "admin"))
        return _validate_field_levels(external_field_levels or {})


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
