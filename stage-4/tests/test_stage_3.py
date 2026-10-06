import copy
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.service import TablekeeperService


def make_test_fixture():
    return {
        "users": [
            {"id": "u_ada", "email": "ada@example.com", "password": "correct horse", "display_name": "Ada"},
            {"id": "u_bob", "email": "bob@example.com", "password": "correct horse", "display_name": "Bob"},
        ],
        "restaurants": [
            {
                "id": "r_anker",
                "name": "Zum Anker",
                "timezone": "Europe/Berlin",
                "slot_minutes": 30,
                "reservation_duration_minutes": 90,
                "cancellation_cutoff_minutes": 60,
                "opening_hours": [
                    {"weekday": day, "opens": "08:00", "closes": "23:00"}
                    for day in ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
                ],
                "tables": [
                    {"id": "t_1", "label": "1", "capacity": 2},
                    {"id": "t_2", "label": "2", "capacity": 4},
                    {"id": "t_3", "label": "3", "capacity": 6},
                ],
                "manager_user_ids": ["u_ada"],
            }
        ],
        "reservations": [],
    }


class Stage3CompleteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.api = TablekeeperService()
        reset_res = await self.api.handle("POST", "/_test/reset", {}, make_test_fixture())
        self.assertEqual(reset_res.status, 204)

        login_ada = await self.api.handle(
            "POST", "/auth/login", {}, {"email": "ada@example.com", "password": "correct horse"}
        )
        self.assertEqual(login_ada.status, 200)
        self.ada_token = login_ada.body["token"]

        login_bob = await self.api.handle(
            "POST", "/auth/login", {}, {"email": "bob@example.com", "password": "correct horse"}
        )
        self.assertEqual(login_bob.status, 200)
        self.bob_token = login_bob.body["token"]

    async def test_availability_explain_validation_and_output(self):
        # 1. Invalid explain values -> 422
        for val in ["false", "1", "", "yes"]:
            res = await self.api.handle(
                "GET", f"/availability?restaurant_id=r_anker&date=2026-09-24&party_size=4&explain={val}", {}
            )
            self.assertEqual(res.status, 422, f"Failed for explain={val}")

        # 2. Without explain -> stage 1 shape, no explain field
        res_plain = await self.api.handle(
            "GET", "/availability?restaurant_id=r_anker&date=2026-09-24&party_size=4", {}
        )
        self.assertEqual(res_plain.status, 200)
        self.assertTrue(len(res_plain.body["slots"]) > 0)
        self.assertNotIn("explain", res_plain.body["slots"][0])

        # 3. With explain=true -> includes explanation for every table
        res_explain = await self.api.handle(
            "GET", "/availability?restaurant_id=r_anker&date=2026-09-24&party_size=4&explain=true", {}
        )
        self.assertEqual(res_explain.status, 200)
        slot0 = res_explain.body["slots"][0]
        self.assertIn("explain", slot0)
        explain = slot0["explain"]
        # Check all fixture tables appear in order
        self.assertEqual([e["table_id"] for e in explain], ["t_1", "t_2", "t_3"])
        # t_1 has capacity 2, party_size is 4 -> capacity rule false, available false
        self.assertEqual(explain[0]["table_id"], "t_1")
        self.assertFalse(explain[0]["available"])
        self.assertEqual(explain[0]["rules"][0], {"rule": "capacity", "holds": False})
        self.assertEqual(explain[0]["rules"][1], {"rule": "no_overlap", "holds": True})
        # t_2 has capacity 4 -> holds
        self.assertTrue(explain[1]["available"])
        self.assertEqual(explain[1]["rules"][0], {"rule": "capacity", "holds": True})
        self.assertEqual(explain[1]["rules"][1], {"rule": "no_overlap", "holds": True})

    async def test_history_and_decision_lifecycle_and_security(self):
        # Book reservation for Bob on 2026-10-10 at 19:00
        headers_bob = {"authorization": f"Bearer {self.bob_token}", "idempotency-key": "bob-book-1"}
        payload = {
            "restaurant_id": "r_anker",
            "table_id": "t_2",
            "starts_at_local": "2026-10-10T19:00",
            "party_size": 4,
        }
        res_book = await self.api.handle("POST", "/reservations", headers_bob, payload)
        self.assertEqual(res_book.status, 201)
        ref = res_book.body["reference"]
        self.assertEqual(res_book.body["revision"], 1)
        self.assertEqual(res_book.body["accepted_terms"]["policy_version"], 0)

        # Decision & history access:
        # Unauthenticated -> 404 (not 401!)
        res_dec_unauth = await self.api.handle("GET", f"/reservations/{ref}/decision", {})
        self.assertEqual(res_dec_unauth.status, 404)
        res_hist_unauth = await self.api.handle("GET", f"/reservations/{ref}/history", {})
        self.assertEqual(res_hist_unauth.status, 404)

        # Another user (Ada) -> 404
        headers_ada = {"authorization": f"Bearer {self.ada_token}"}
        res_dec_ada = await self.api.handle("GET", f"/reservations/{ref}/decision", headers_ada)
        self.assertEqual(res_dec_ada.status, 404)
        res_hist_ada = await self.api.handle("GET", f"/reservations/{ref}/history", headers_ada)
        self.assertEqual(res_hist_ada.status, 404)

        # Bob (owner) -> 200
        res_dec_bob = await self.api.handle("GET", f"/reservations/{ref}/decision", headers_bob)
        self.assertEqual(res_dec_bob.status, 200)
        self.assertEqual(res_dec_bob.body["reference"], ref)
        self.assertEqual(res_dec_bob.body["revision"], 1)
        self.assertEqual(res_dec_bob.body["accepted_terms"]["policy_version"], 0)

        res_hist_bob = await self.api.handle("GET", f"/reservations/{ref}/history", headers_bob)
        self.assertEqual(res_hist_bob.status, 200)
        self.assertEqual(len(res_hist_bob.body["entries"]), 1)
        entry1 = res_hist_bob.body["entries"][0]
        self.assertEqual(entry1["seq"], 1)
        self.assertEqual(entry1["event"], "created")
        self.assertEqual(entry1["revision"], 1)
        self.assertEqual(
            entry1["changes"],
            [
                {"field": "table_id", "from": None, "to": "t_2"},
                {"field": "starts_at_local", "from": None, "to": "2026-10-10T19:00"},
                {"field": "party_size", "from": None, "to": 4},
            ],
        )

        # No-op amendment -> revision and history unchanged
        res_noop = await self.api.handle(
            "PATCH", f"/reservations/{ref}", headers_bob, {"party_size": 4, "table_id": "t_2"}
        )
        self.assertEqual(res_noop.status, 200)
        self.assertEqual(res_noop.body["revision"], 1)
        res_hist_after_noop = await self.api.handle("GET", f"/reservations/{ref}/history", headers_bob)
        self.assertEqual(len(res_hist_after_noop.body["entries"]), 1)

        # Stale revision rejection -> 409
        res_stale = await self.api.handle(
            "PATCH", f"/reservations/{ref}", headers_bob, {"expected_revision": 99, "party_size": 3}
        )
        self.assertEqual(res_stale.status, 409)

        # Invalid expected_revision -> 422
        res_inv_rev = await self.api.handle(
            "PATCH", f"/reservations/{ref}", headers_bob, {"expected_revision": "1", "party_size": 3}
        )
        self.assertEqual(res_inv_rev.status, 422)

        # Real amendment with matching expected_revision
        res_amend = await self.api.handle(
            "PATCH", f"/reservations/{ref}", headers_bob, {"expected_revision": 1, "party_size": 3, "table_id": "t_3"}
        )
        self.assertEqual(res_amend.status, 200)
        self.assertEqual(res_amend.body["revision"], 2)
        self.assertEqual(res_amend.body["party_size"], 3)
        self.assertEqual(res_amend.body["table_id"], "t_3")

        res_hist2 = await self.api.handle("GET", f"/reservations/{ref}/history", headers_bob)
        self.assertEqual(len(res_hist2.body["entries"]), 2)
        entry2 = res_hist2.body["entries"][1]
        self.assertEqual(entry2["seq"], 2)
        self.assertEqual(entry2["event"], "changed")
        self.assertEqual(entry2["revision"], 2)
        self.assertEqual(
            entry2["changes"],
            [
                {"field": "table_id", "from": "t_2", "to": "t_3"},
                {"field": "party_size", "from": 4, "to": 3},
            ],
        )

        # Cancel reservation -> revision increments to 3, history records event cancelled with empty changes
        res_cancel = await self.api.handle("POST", f"/reservations/{ref}/cancel", headers_bob, {})
        self.assertEqual(res_cancel.status, 200)
        self.assertEqual(res_cancel.body["status"], "cancelled")
        self.assertEqual(res_cancel.body["revision"], 3)

        res_hist3 = await self.api.handle("GET", f"/reservations/{ref}/history", headers_bob)
        self.assertEqual(len(res_hist3.body["entries"]), 3)
        entry3 = res_hist3.body["entries"][2]
        self.assertEqual(entry3["seq"], 3)
        self.assertEqual(entry3["event"], "cancelled")
        self.assertEqual(entry3["revision"], 3)
        self.assertEqual(entry3["changes"], [])

        # Repeated cancel is idempotent no-op (no revision increment, no additional history entry)
        res_cancel_repeat = await self.api.handle("POST", f"/reservations/{ref}/cancel", headers_bob, {})
        self.assertEqual(res_cancel_repeat.status, 200)
        self.assertEqual(res_cancel_repeat.body["revision"], 3)
        res_hist4 = await self.api.handle("GET", f"/reservations/{ref}/history", headers_bob)
        self.assertEqual(len(res_hist4.body["entries"]), 3)

    async def test_recurring_series_adoption_and_lifecycle(self):
        # 1. Book anchor reservation for Bob
        headers_bob = {"authorization": f"Bearer {self.bob_token}"}
        res_anchor = await self.api.handle(
            "POST",
            "/reservations",
            {**headers_bob, "idempotency-key": "anchor-key-1"},
            {
                "restaurant_id": "r_anker",
                "table_id": "t_3",
                "starts_at_local": "2026-10-15T18:00",
                "party_size": 4,
            },
        )
        self.assertEqual(res_anchor.status, 201)
        anchor_ref = res_anchor.body["reference"]

        # 2. Adopt into recurring series: 4 occurrences, 1 week apart
        res_series = await self.api.handle(
            "POST",
            "/series",
            {**headers_bob, "idempotency-key": "series-key-1"},
            {"anchor_reference": anchor_ref, "count": 4, "interval_weeks": 1},
        )
        self.assertEqual(res_series.status, 201)
        series_id = res_series.body["series_id"]
        self.assertEqual(res_series.body["revision"], 1)
        self.assertEqual(res_series.body["interval_weeks"], 1)
        self.assertEqual(len(res_series.body["occurrences"]), 4)

        # Occurrence 0 is anchor unchanged
        occ0 = res_series.body["occurrences"][0]
        self.assertEqual(occ0["index"], 0)
        self.assertEqual(occ0["reference"], anchor_ref)
        self.assertFalse(occ0["exception"])

        # Occurrence 1 is 1 week later
        occ1 = res_series.body["occurrences"][1]
        self.assertEqual(occ1["index"], 1)
        self.assertNotEqual(occ1["reference"], anchor_ref)
        self.assertEqual(occ1["reservation"]["starts_at_local"], "2026-10-22T18:00")
        self.assertFalse(occ1["exception"])

        # 3. GET /series/{series_id}
        # Non-owner / unauthenticated gives 404
        self.assertEqual((await self.api.handle("GET", f"/series/{series_id}", {})).status, 404)
        self.assertEqual(
            (await self.api.handle("GET", f"/series/{series_id}", {"authorization": f"Bearer {self.ada_token}"})).status,
            404,
        )

        # Owner Bob gives 200
        get_series = await self.api.handle("GET", f"/series/{series_id}", headers_bob)
        self.assertEqual(get_series.status, 200)
        self.assertEqual(len(get_series.body["occurrences"]), 4)

        # 4. PATCH occurrence 1 -> becomes exception: true, increments series revision
        occ1_ref = occ1["reference"]
        res_patch_occ1 = await self.api.handle(
            "PATCH", f"/reservations/{occ1_ref}", headers_bob, {"party_size": 2}
        )
        self.assertEqual(res_patch_occ1.status, 200)

        get_series2 = await self.api.handle("GET", f"/series/{series_id}", headers_bob)
        self.assertEqual(get_series2.body["revision"], 2)
        self.assertTrue(get_series2.body["occurrences"][1]["exception"])
        self.assertFalse(get_series2.body["occurrences"][0]["exception"])

        # 5. Cancel occurrence 2 -> increments series revision, does not mark exception
        occ2_ref = res_series.body["occurrences"][2]["reference"]
        res_cancel_occ2 = await self.api.handle("POST", f"/reservations/{occ2_ref}/cancel", headers_bob, {})
        self.assertEqual(res_cancel_occ2.status, 200)

        get_series3 = await self.api.handle("GET", f"/series/{series_id}", headers_bob)
        self.assertEqual(get_series3.body["revision"], 3)
        self.assertFalse(get_series3.body["occurrences"][2]["exception"])
        self.assertEqual(get_series3.body["occurrences"][2]["reservation"]["status"], "cancelled")

    async def test_reservation_moves_with_policies_and_agreements(self):
        # Create 2 reservations for Bob
        headers_bob = {"authorization": f"Bearer {self.bob_token}"}
        res1 = await self.api.handle(
            "POST",
            "/reservations",
            {**headers_bob, "idempotency-key": "move-bk-1"},
            {"restaurant_id": "r_anker", "table_id": "t_2", "starts_at_local": "2026-10-18T18:00", "party_size": 3},
        )
        res2 = await self.api.handle(
            "POST",
            "/reservations",
            {**headers_bob, "idempotency-key": "move-bk-2"},
            {"restaurant_id": "r_anker", "table_id": "t_3", "starts_at_local": "2026-10-18T18:00", "party_size": 5},
        )
        ref1 = res1.body["reference"]
        ref2 = res2.body["reference"]

        # Swap their tables using /reservation-moves with expected_revision
        moves_payload = {
            "moves": [
                {"reference": ref1, "table_id": "t_3", "party_size": 3, "expected_revision": 1},
                {"reference": ref2, "table_id": "t_2", "party_size": 4, "expected_revision": 1},
            ]
        }
        res_moves = await self.api.handle(
            "POST", "/reservation-moves", {**headers_bob, "idempotency-key": "swap-1"}, moves_payload
        )
        self.assertEqual(res_moves.status, 201)
        self.assertEqual(len(res_moves.body["reservations"]), 2)
        # Check both have incremented revision
        self.assertEqual(res_moves.body["reservations"][0]["revision"], 2)
        self.assertEqual(res_moves.body["reservations"][1]["revision"], 2)
