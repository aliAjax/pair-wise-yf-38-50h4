from datetime import datetime, timezone

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


# 字段敏感度分级：数字越大越敏感。外单位默认 clearance=2，内单位默认 clearance=3。
SENSITIVITY_LEVELS = {"public": 1, "internal": 2, "sensitive": 3, "restricted": 4}
DEFAULT_FIELDS = [
    {"name": "sample_id", "sensitivity": 1},
    {"name": "phenotype", "sensitivity": 2},
    {"name": "diagnosis", "sensitivity": 2},
    {"name": "variant", "sensitivity": 3},
    {"name": "raw_sequence", "sensitivity": 4},
]
DEFAULT_CLEARANCE = {"internal": 3, "external": 2}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_fields(fields):
    if not isinstance(fields, list) or not fields:
        raise ValidationError("fields must be a non-empty list")
    seen = set()
    normalized = []
    for item in fields:
        if not isinstance(item, dict):
            raise ValidationError("each field must be an object with name and sensitivity")
        name = str(item.get("name", "")).strip()
        if not name:
            raise ValidationError("field name is required")
        if name in seen:
            raise ValidationError("duplicate field: " + name)
        sensitivity = item.get("sensitivity")
        if isinstance(sensitivity, str):
            sensitivity = SENSITIVITY_LEVELS.get(str(sensitivity).strip().lower())
        if not isinstance(sensitivity, int) or sensitivity < 1 or sensitivity > 4:
            raise ValidationError("field sensitivity must be between 1 and 4")
        seen.add(name)
        normalized.append({"name": name, "sensitivity": sensitivity})
    return normalized


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")
    if data.get("fields"):
        data["fields"] = _normalize_fields(data["fields"])
    elif "fields" not in data:
        data["fields"] = [dict(item) for item in DEFAULT_FIELDS]
    data.setdefault("classification_version", 1)


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")
    fields = dataset["data"].get("fields") or DEFAULT_FIELDS
    names = {item["name"] for item in fields}
    requested = data.get("requested_fields")
    if requested is not None:
        if not isinstance(requested, list):
            raise ValidationError("requested_fields must be a list")
        unknown = [item for item in requested if item not in names]
        if unknown:
            raise ValidationError("requested fields not in dataset: " + ", ".join(unknown))
    org_type = str(data.get("org_type", "external")).strip().lower()
    if org_type not in ("internal", "external"):
        raise ValidationError("org_type must be internal or external")
    data["org_type"] = org_type
    if "clearance_level" not in data or data.get("clearance_level") is None:
        data["clearance_level"] = DEFAULT_CLEARANCE[org_type]
    else:
        level = data["clearance_level"]
        if not isinstance(level, int) or level < 1 or level > 4:
            raise ValidationError("clearance_level must be between 1 and 4")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")
    app_data = entity["data"]
    dataset = _find_one(lookup, "dataset", "id", app_data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    fields = dataset["data"].get("fields") or DEFAULT_FIELDS
    clearance = int(app_data.get("clearance_level", 2))
    requested = app_data.get("requested_fields")
    scope = [
        item["name"]
        for item in fields
        if item["sensitivity"] <= clearance
        and (not requested or item["name"] in requested)
    ]
    if not scope:
        raise ValidationError("no fields within clearance for this application")
    return {
        "field_scope": scope,
        "scope_frozen_at": utcnow(),
        "scope_classification_version": dataset["data"].get("classification_version", 1),
    }


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    if not entity["data"].get("field_scope"):
        raise ValidationError("cannot activate grant with empty field scope")
    return {"activated_by": actor.user_id}


def _validate_grant_create(actor, data, lookup):
    application = _find_one(lookup, "application", "id", data.get("application_id"))
    if not application:
        raise ValidationError("application does not exist")
    if application["status"] != "approved":
        raise ValidationError("application must be approved before issuing a grant")
    dataset = _find_one(lookup, "dataset", "id", application["data"].get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    scope = application["data"].get("field_scope")
    if not scope:
        raise ValidationError("application has no approved field scope")
    return {
        "field_scope": list(scope),
        "clearance_level": application["data"].get("clearance_level", 2),
        "scope_frozen_at": utcnow(),
        "classification_version": dataset["data"].get("classification_version", 1),
    }


def _validate_reclassify(actor, entity, data, lookup):
    RuleEngine._ensure_role(actor, ("admin", "committee"))
    return {"fields": _normalize_fields(data.get("fields"))}


CUSTOM_CREATE = {
    'dataset': _validate_dataset,
    'application': _validate_application,
    'grant': _validate_grant_create,
}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('grant', 'activate'): _validate_grant_activate,
}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued'}
    TRANSITIONS = {'dataset': {'restrict': (('registered',), 'restricted'), 'publish': (('restricted',), 'published')}, 'application': {'submit': (('draft',), 'submitted'), 'review': (('submitted',), 'under_review'), 'approve': (('under_review',), 'approved'), 'reject': (('under_review',), 'rejected'), 'withdraw': (('submitted', 'under_review'), 'withdrawn')}, 'grant': {'activate': (('issued',), 'active'), 'revoke': (('active',), 'revoked'), 'expire': (('active',), 'expired')}}
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient')}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee')}

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
        if custom:
            extra = custom(actor, data, lookup) or {}
            data.update(extra)
        return dict(data)

    def validate_reclassify(self, actor, entity, data):
        return _validate_reclassify(actor, entity, data, None)

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
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
