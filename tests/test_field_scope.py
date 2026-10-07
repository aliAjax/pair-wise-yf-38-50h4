import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import (
    Actor,
    ConflictError,
    InvalidTransition,
    PermissionDenied,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService

LEVELS = {"sample_id": "public", "diagnosis": "sensitive", "genotype": "restricted"}


class FieldScopeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.admin = Actor("admin", "admin")
        self.auditor = Actor("auditor-1", "auditor")

    def tearDown(self):
        self.tmp.cleanup()

    def _dataset(self, levels=LEVELS):
        data = {"name": "Cohort", "access_policy": "controlled"}
        if levels is not None:
            data["field_levels"] = levels
        return self.service.create(self.admin, "dataset", data)

    def _approved_application(self, dataset_id, requested_level="sensitive"):
        application = self.service.create(
            self.admin,
            "application",
            {
                "dataset_id": dataset_id,
                "applicant_id": "APP-1",
                "purpose": "variant analysis",
                "requested_level": requested_level,
            },
        )
        self.service.transition(self.admin, application["id"], "submit", {})
        self.service.transition(
            self.admin, application["id"], "review", {"committee_id": "c1"}
        )
        return self.service.transition(
            self.admin,
            application["id"],
            "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "noncommercial", "expires_at": "2099-01-01"},
        )

    def _active_grant(self, application, dataset_id, recipient="researcher-1"):
        grant = self.service.create(
            self.admin,
            "grant",
            {
                "application_id": application["id"],
                "dataset_id": dataset_id,
                "recipient": recipient,
            },
        )
        self.service.transition(
            self.admin,
            grant["id"],
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        return self.service.get(grant["id"])

    def test_scope_fixed_at_approval_and_issuance(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        self.assertEqual(application["data"]["field_scope"], ["diagnosis", "sample_id"])
        self.assertEqual(application["data"]["approved_level"], "sensitive")
        self.assertEqual(application["data"]["classification_version"], 1)

        grant = self._active_grant(application, dataset["id"])
        self.assertEqual(grant["data"]["scope"], ["diagnosis", "sample_id"])
        self.assertEqual(grant["data"]["scope_version"], 1)

    def test_fetch_returns_only_in_scope_fields(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        grant = self._active_grant(application, dataset["id"])
        recipient = Actor("researcher-1", "applicant")

        result = self.service.fetch(recipient, grant["id"], ["sample_id"])
        self.assertEqual(result["fields"], ["sample_id"])

        full = self.service.fetch(recipient, grant["id"])
        self.assertEqual(full["fields"], ["diagnosis", "sample_id"])

        with self.assertRaises(PermissionDenied):
            self.service.fetch(recipient, grant["id"], ["genotype"])
        with self.assertRaises(PermissionDenied):
            self.service.fetch(Actor("someone-else", "applicant"), grant["id"], ["sample_id"])

    def test_fetch_requires_active_grant(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        grant = self.service.create(
            self.admin,
            "grant",
            {
                "application_id": application["id"],
                "dataset_id": dataset["id"],
                "recipient": "researcher-1",
            },
        )
        with self.assertRaises(InvalidTransition):
            self.service.fetch(Actor("researcher-1", "applicant"), grant["id"], ["sample_id"])

    def test_reclassify_recomputes_live_grants(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        active_grant = self._active_grant(application, dataset["id"])
        queued_application = self._approved_application(dataset["id"])
        queued_grant = self.service.create(
            self.admin,
            "grant",
            {
                "application_id": queued_application["id"],
                "dataset_id": dataset["id"],
                "recipient": "researcher-2",
            },
        )

        self.service.transition(
            self.admin,
            dataset["id"],
            "reclassify",
            {
                "field_levels": {"sample_id": "public", "diagnosis": "restricted", "genotype": "public"},
                "reason": "annual review",
            },
        )

        updated_active = self.service.get(active_grant["id"])
        self.assertEqual(updated_active["data"]["scope"], ["genotype", "sample_id"])
        self.assertEqual(updated_active["data"]["classification_version"], 2)
        self.assertEqual(updated_active["data"]["scope_version"], 2)

        # 排队没取数的授权也一起按新范围执行
        updated_queued = self.service.get(queued_grant["id"])
        self.assertEqual(updated_queued["data"]["scope"], ["genotype", "sample_id"])
        self.service.transition(
            self.admin,
            queued_grant["id"],
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        result = self.service.fetch(Actor("researcher-2", "applicant"), queued_grant["id"])
        self.assertEqual(result["fields"], ["genotype", "sample_id"])

        # 申请侧保留获批时的历史快照，授权侧已按新分级重算
        self.assertEqual(
            self.service.get(application["id"])["data"]["field_scope"],
            ["diagnosis", "sample_id"],
        )
        with self.assertRaises(PermissionDenied):
            self.service.fetch(
                Actor("researcher-1", "applicant"), active_grant["id"], ["diagnosis"]
            )

        actions = [row["action"] for row in self.service.audit_log(active_grant["id"])]
        self.assertIn("scope_recompute", actions)

    def test_concurrent_scope_confirmation_first_write_wins(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        version = application["version"]
        barrier = threading.Barrier(2)
        main_ident = threading.get_ident()
        waited = set()
        lock = threading.Lock()
        original_get = self.repo.get_entity

        def synced_get(entity_id):
            result = original_get(entity_id)
            ident = threading.get_ident()
            if entity_id == application["id"] and ident != main_ident:
                with lock:
                    first = ident not in waited
                    waited.add(ident)
                if first:
                    barrier.wait(timeout=10)
            return result

        self.repo.get_entity = synced_get
        outcomes = []
        try:
            def confirm(user):
                try:
                    entity = self.service.transition(
                        Actor(user, "committee"),
                        application["id"],
                        "confirm_scope",
                        {},
                        expected_version=version,
                    )
                    outcomes.append(("ok", entity["status"]))
                except ConflictError as exc:
                    outcomes.append(("conflict", exc.conflict_id))

            threads = [
                threading.Thread(target=confirm, args=("committee-1",)),
                threading.Thread(target=confirm, args=("committee-2",)),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)
        finally:
            self.repo.get_entity = original_get

        outcomes.sort(key=lambda item: item[0])
        self.assertEqual(len(outcomes), 2)
        self.assertEqual(outcomes[0][0], "conflict")
        self.assertTrue(outcomes[0][1].startswith("cnf-"))
        self.assertEqual(outcomes[1], ("ok", "scope_confirmed"))

    def test_stale_version_gets_conflict_number(self):
        dataset = self._dataset()
        stale = dataset["version"]
        self.service.transition(
            self.admin,
            dataset["id"],
            "reclassify",
            {"field_levels": dict(LEVELS), "reason": "first"},
            expected_version=stale,
        )
        with self.assertRaises(ConflictError) as ctx:
            self.service.transition(
                Actor("committee-2", "committee"),
                dataset["id"],
                "reclassify",
                {"field_levels": dict(LEVELS), "reason": "second"},
                expected_version=stale,
            )
        self.assertTrue(ctx.exception.conflict_id.startswith("cnf-"))

    def test_batch_rollback_and_idempotent_retry(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        existing = self.service.create(
            self.admin,
            "grant",
            {
                "application_id": application["id"],
                "dataset_id": dataset["id"],
                "recipient": "r0",
            },
        )

        def item(entity_id, recipient):
            return {
                "id": entity_id,
                "application_id": application["id"],
                "dataset_id": dataset["id"],
                "recipient": recipient,
            }

        items = [item("g-1", "r1"), item(existing["id"], "r2"), item("g-3", "r3")]
        with self.assertRaises(ConflictError):
            self.service.create_batch(self.admin, "grant", items, batch_id="batch-1")
        # 写库失败后整批撤回
        self.assertIsNone(self.repo.get_entity("g-1"))
        self.assertIsNone(self.repo.get_entity("g-3"))

        # 修正后重试：同一 batch_id 只补没落下的授权
        items[1] = item("g-2", "r2")
        landed = self.service.create_batch(self.admin, "grant", items, batch_id="batch-1")
        self.assertEqual([entity["id"] for entity in landed], ["g-1", "g-2", "g-3"])

        again = self.service.create_batch(self.admin, "grant", items, batch_id="batch-1")
        self.assertEqual([entity["id"] for entity in again], ["g-1", "g-2", "g-3"])
        grants = self.repo.find_entities("grant", "dataset_id", dataset["id"])
        self.assertEqual(len(grants), 4)
        creates = [
            row for row in self.service.audit_log()
            if row["action"] == "create" and row["entity_id"] in ("g-1", "g-2", "g-3")
        ]
        self.assertEqual(len(creates), 3)

    def test_auditor_reconcile_against_external_levels(self):
        dataset = self._dataset()
        application = self._approved_application(dataset["id"])
        grant = self._active_grant(application, dataset["id"])

        report = self.service.reconcile(
            self.auditor,
            dataset["id"],
            {"sample_id": "public", "diagnosis": "restricted", "genotype": "restricted"},
        )
        self.assertEqual(report["checked"], 1)
        self.assertEqual(len(report["discrepancies"]), 1)
        self.assertEqual(report["discrepancies"][0]["grant_id"], grant["id"])
        self.assertEqual(report["discrepancies"][0]["overreach"], ["diagnosis"])

        clean = self.service.reconcile(self.auditor, dataset["id"], dict(LEVELS))
        self.assertEqual(clean["discrepancies"], [])

        with self.assertRaises(PermissionDenied):
            self.service.reconcile(Actor("x", "applicant"), dataset["id"], dict(LEVELS))

        actions = [row["action"] for row in self.service.audit_log(dataset["id"])]
        self.assertIn("reconcile", actions)


if __name__ == "__main__":
    unittest.main()
