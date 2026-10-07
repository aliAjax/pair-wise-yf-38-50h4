import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, ConflictError, PermissionDenied, ScopeViolation, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class ScopeLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.applicant = Actor("applicant", "applicant")
        self.auditor = Actor("auditor", "auditor")
        self.viewer = Actor("viewer", "viewer")

    def tearDown(self):
        self.tmp.cleanup()

    def _dataset(self, fields):
        return self.service.create(self.admin, "dataset", {
            "name": "D", "access_policy": "controlled", "fields": fields,
        })

    def _application(self, dataset_id, org_type="external", requested=None):
        data = {
            "dataset_id": dataset_id, "applicant_id": "APP-1",
            "purpose": "analysis", "org_type": org_type,
        }
        if requested is not None:
            data["requested_fields"] = requested
        app = self.service.create(self.admin, "application", data)
        self.service.transition(self.admin, app["id"], "submit", {})
        self.service.transition(self.admin, app["id"], "review", {"committee_id": "c1"})
        return self.service.transition(self.admin, app["id"], "approve", {
            "approvals": ["r1", "r2", "r3"], "terms": "noncommercial", "expires_at": "2099-01-01",
        })

    def _grant(self, app_id, dataset_id, activate=True):
        grant = self.service.create(self.admin, "grant", {
            "application_id": app_id, "dataset_id": dataset_id, "recipient": "researcher-1",
        })
        if activate:
            self.service.transition(self.admin, grant["id"], "activate", {
                "starts_at": "2026-01-01", "expires_at": "2099-01-01",
            })
        return grant

    def test_approve_freezes_scope_from_current_classification(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
            {"name": "c", "sensitivity": 3},
        ])
        app = self._application(ds["id"], org_type="external")
        self.assertEqual(app["data"]["field_scope"], ["a", "b"])
        app2 = self._application(ds["id"], org_type="internal")
        self.assertEqual(app2["data"]["field_scope"], ["a", "b", "c"])

    def test_requested_fields_subset(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
            {"name": "c", "sensitivity": 3},
        ])
        app = self._application(ds["id"], org_type="internal", requested=["a", "c"])
        self.assertEqual(app["data"]["field_scope"], ["a", "c"])

    def test_grant_issuance_fixes_scope(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        self.assertEqual(grant["data"]["field_scope"], ["a", "b"])
        self.assertEqual(grant["data"]["classification_version"], 1)

    def test_fetch_only_returns_in_scope_fields(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
            {"name": "c", "sensitivity": 3},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        result = self.service.fetch(self.admin, grant["id"])
        self.assertEqual(set(result["fields"].keys()), {"a", "b"})
        result = self.service.fetch(self.admin, grant["id"], ["a"])
        self.assertEqual(set(result["fields"].keys()), {"a"})

    def test_fetch_out_of_scope_rejected_not_filtered(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
            {"name": "c", "sensitivity": 3},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        with self.assertRaises(ScopeViolation):
            self.service.fetch(self.admin, grant["id"], ["c"])
        with self.assertRaises(ScopeViolation):
            self.service.fetch(self.admin, grant["id"], ["a", "c"])

    def test_fetch_requires_role(self):
        ds = self._dataset([{"name": "a", "sensitivity": 1}])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        with self.assertRaises(PermissionDenied):
            self.service.fetch(self.viewer, grant["id"])

    def test_reclassify_recomputes_grant_scope(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        self.service.reclassify(self.admin, ds["id"], [
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 3},
        ], expected_version=ds["version"])
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["data"]["field_scope"], ["a"])
        self.assertEqual(grant["data"]["classification_version"], 2)
        self.assertEqual(grant["status"], "active")

    def test_reclassify_empties_scope_revokes_grant(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        self.service.reclassify(self.admin, ds["id"], [
            {"name": "a", "sensitivity": 4},
            {"name": "b", "sensitivity": 4},
        ], expected_version=ds["version"])
        grant = self.service.get(grant["id"])
        self.assertEqual(grant["data"]["field_scope"], [])
        self.assertEqual(grant["status"], "revoked")

    def test_queued_grant_recomputed_with_new_scope(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        queued = self._grant(app["id"], ds["id"], activate=False)
        self.assertEqual(queued["status"], "issued")
        self.service.reclassify(self.admin, ds["id"], [
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 4},
        ], expected_version=ds["version"])
        queued = self.service.get(queued["id"])
        self.assertEqual(queued["data"]["field_scope"], ["a"])
        self.assertEqual(queued["status"], "issued")

    def test_concurrent_approve_later_gets_conflict_version(self):
        ds = self._dataset([{"name": "a", "sensitivity": 1}])
        app = self.service.create(self.admin, "application", {
            "dataset_id": ds["id"], "applicant_id": "APP-1", "purpose": "x",
        })
        self.service.transition(self.admin, app["id"], "submit", {})
        self.service.transition(self.admin, app["id"], "review", {"committee_id": "c1"})
        version = self.service.get(app["id"])["version"]
        first = self.service.transition(self.admin, app["id"], "approve", {
            "approvals": ["r1", "r2", "r3"], "terms": "t", "expires_at": "2099-01-01",
        }, expected_version=version)
        self.assertEqual(first["status"], "approved")
        with self.assertRaises(ConflictError):
            self.service.transition(self.admin, app["id"], "approve", {
                "approvals": ["r1", "r2", "r3"], "terms": "t2", "expires_at": "2099-01-01",
            }, expected_version=version)

    def test_failed_batch_rolls_back_and_retry_fills_missing(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        g1 = self._grant(app["id"], ds["id"])
        app2 = self._application(ds["id"])
        g2 = self._grant(app2["id"], ds["id"])
        new_fields = [
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 3},
        ]
        with self.assertRaises(ConflictError):
            self.service.reclassify(self.admin, ds["id"], new_fields, expected_version=999)
        g1 = self.service.get(g1["id"]); g2 = self.service.get(g2["id"])
        self.assertEqual(g1["data"]["classification_version"], 1)
        self.assertEqual(g2["data"]["classification_version"], 1)
        self.assertEqual(g1["data"]["field_scope"], ["a", "b"])
        ds = self.service.reclassify(self.admin, ds["id"], new_fields,
                                     expected_version=ds["version"], idempotency_key="rc-1")
        g1 = self.service.get(g1["id"]); g2 = self.service.get(g2["id"])
        self.assertEqual(g1["data"]["field_scope"], ["a"])
        self.assertEqual(g2["data"]["field_scope"], ["a"])
        self.assertEqual(g1["data"]["classification_version"], 2)
        # retry with same key is a no-op, not an error
        ds = self.service.reclassify(self.admin, ds["id"], new_fields,
                                     expected_version=ds["version"], idempotency_key="rc-1")
        self.assertEqual(ds["data"]["classification_version"], 2)

    def test_reconcile_detects_drift(self):
        ds = self._dataset([
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 2},
        ])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        rep = self.service.reconcile(self.auditor, grant["id"])
        self.assertTrue(rep["valid"])
        # inject an out-of-sync scope (b upgraded beyond clearance)
        row = self.repo.get_entity(grant["id"])
        gdata = dict(row["data"]); gdata["field_scope"] = ["a", "b"]
        self.repo.update_entity(grant["id"], row["version"], row["status"], gdata)
        self.service.reclassify(self.admin, ds["id"], [
            {"name": "a", "sensitivity": 1},
            {"name": "b", "sensitivity": 4},
        ], expected_version=ds["version"])
        row = self.repo.get_entity(grant["id"])
        gdata = dict(row["data"]); gdata["field_scope"] = ["a", "b"]
        self.repo.update_entity(grant["id"], row["version"], row["status"], gdata)
        rep = self.service.reconcile(self.auditor, grant["id"])
        self.assertFalse(rep["valid"])
        self.assertTrue(any(d["field"] == "b" and d["issue"] == "upgraded_beyond_clearance"
                            for d in rep["drift"]))

    def test_reconcile_requires_auditor_role(self):
        ds = self._dataset([{"name": "a", "sensitivity": 1}])
        app = self._application(ds["id"])
        grant = self._grant(app["id"], ds["id"])
        with self.assertRaises(PermissionDenied):
            self.service.reconcile(self.viewer, grant["id"])

    def test_invalid_sensitivity_rejected(self):
        ds = self._dataset([{"name": "a", "sensitivity": 1}])
        with self.assertRaises(ValidationError):
            self.service.reclassify(self.admin, ds["id"],
                                    [{"name": "a", "sensitivity": 9}],
                                    expected_version=ds["version"])


if __name__ == "__main__":
    unittest.main()
