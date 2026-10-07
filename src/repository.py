import json
import sqlite3
from datetime import datetime, timezone

from .domain import ConflictError, NotFoundError, ValidationError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
            """)

    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT version FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True

    def transactional_reclassify(self, dataset_id, expected_version, fields, target_version, actor):
        """One transaction: update the dataset classification and recompute every grant scope.

        Any version conflict rolls the whole batch back so the caller can retry.
        """
        now = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (dataset_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + dataset_id)
            dataset = self._entity_from_row(row)
            if dataset["kind"] != "dataset":
                raise ValidationError("reclassify only applies to datasets")
            if expected_version is not None and dataset["version"] != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, dataset["version"])
                )
            new_data = dict(dataset["data"])
            new_data["fields"] = fields
            new_data["classification_version"] = target_version
            payload = json.dumps(new_data, ensure_ascii=False, sort_keys=True)
            cur = connection.execute(
                "UPDATE entities SET data = ?, version = version + 1, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (payload, now, dataset_id, dataset["version"]),
            )
            if cur.rowcount != 1:
                raise ConflictError("version conflict while updating dataset")
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dataset_id,
                    actor.user_id,
                    actor.role,
                    "reclassify",
                    dataset["status"],
                    dataset["status"],
                    json.dumps(
                        {"classification_version": target_version, "fields": fields},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            self._recompute_grants_on(
                connection, dataset_id, fields, target_version, actor, now
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(dataset_id)

    def reconcile_grant_scopes(self, dataset_id):
        """Idempotent retry: recompute only grants still behind the dataset's classification version."""
        now = utcnow()
        connection = self._connect()
        updated = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (dataset_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + dataset_id)
            dataset = self._entity_from_row(row)
            if dataset["kind"] != "dataset":
                raise ValidationError("reconcile only applies to datasets")
            target = int(dataset["data"].get("classification_version", 1))
            fields = dataset["data"].get("fields") or []
            updated = self._recompute_grants_on(
                connection,
                dataset_id,
                fields,
                target,
                _SystemActor(),
                now,
                only_behind=True,
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return updated

    def _recompute_grants_on(self, connection, dataset_id, fields, target_version, actor, now, only_behind=False):
        updated = []
        grant_rows = connection.execute(
            "SELECT * FROM entities WHERE kind = 'grant' ORDER BY id"
        ).fetchall()
        for grow in grant_rows:
            grant = self._entity_from_row(grow)
            if grant["data"].get("dataset_id") != dataset_id:
                continue
            current_version = int(grant["data"].get("classification_version", 1))
            if only_behind and current_version >= target_version:
                continue
            old_scope = grant["data"].get("field_scope") or []
            clearance = int(grant["data"].get("clearance_level", 2))
            new_scope = [
                item["name"]
                for item in fields
                if item["name"] in old_scope and item["sensitivity"] <= clearance
            ]
            gdata = dict(grant["data"])
            gdata["field_scope"] = new_scope
            gdata["classification_version"] = target_version
            new_status = grant["status"]
            if not new_scope and grant["status"] in ("issued", "active"):
                new_status = "revoked"
                gdata["revoke_reason"] = "reclassification: no fields within approved scope"
            gpayload = json.dumps(gdata, ensure_ascii=False, sort_keys=True)
            cur = connection.execute(
                "UPDATE entities SET data = ?, status = ?, version = version + 1, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (gpayload, new_status, now, grant["id"], grant["version"]),
            )
            if cur.rowcount != 1:
                raise ConflictError(
                    "version conflict while recomputing grant " + grant["id"]
                )
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    grant["id"],
                    actor.user_id,
                    actor.role,
                    "reclassify_scope",
                    grant["status"],
                    new_status,
                    json.dumps(
                        {
                            "field_scope": new_scope,
                            "classification_version": target_version,
                            "revoked": new_status != grant["status"],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    now,
                ),
            )
            updated.append(grant["id"])
        return updated


class _SystemActor:
    user_id = "system"
    role = "system"
