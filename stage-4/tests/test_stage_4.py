import copy
import sys
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from app.service import TablekeeperService


def make_stage4_fixture():
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
                "combinable": [["t_1", "t_2"], ["t_2", "t_3"]],
                "manager_user_ids": ["u_ada"],
            }
        ],
        "reservations": [],
    }


class Stage4TargetedTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.api = TablekeeperService()
        reset_res = await self.api.handle("POST", "/_test/reset", {}, make_stage4_fixture())
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

        self.booking_date = (date.today() + timedelta(days=7)).isoformat()

    def ada_headers(self, key="k1"):
        return {"authorization": f"Bearer {self.ada_token}", "idempotency-key": key}

    def bob_headers(self, key="k2"):
        return {"authorization": f"Bearer {self.bob_token}", "idempotency-key": key}

    async def test_available_options_lists_singles_then_pairs(self):
        resp = await self.api.handle(
            "GET",
            f"/availability?restaurant_id=r_anker&date={self.booking_date}&party_size=4",
            {},
            None,
        )
        self.assertEqual(resp.status, 200)
        slot = next(s for s in resp.body["slots"] if s["starts_at_local"].endswith("19:00"))
        got = [(tuple(o["table_ids"]), o["capacity"]) for o in slot["available_options"]]
        self.assertEqual(got, [(("t_2",), 4), (("t_3",), 6), (("t_1", "t_2"), 6), (("t_2", "t_3"), 10)])
        self.assertEqual(slot["available_table_ids"], ["t_2", "t_3"])

    async def test_booking_declared_pair_and_single_table(self):
        # Book declared pair
        res = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_pair"),
            {
                "restaurant_id": "r_anker",
                "table_ids": ["t_1", "t_2"],
                "starts_at_local": f"{self.booking_date}T19:00",
                "party_size": 6,
            },
        )
        self.assertEqual(res.status, 201)
        self.assertEqual(res.body["table_ids"], ["t_1", "t_2"])
        self.assertNotIn("table_id", res.body)

        # Book single table
        res_single = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_single"),
            {
                "restaurant_id": "r_anker",
                "table_id": "t_3",
                "starts_at_local": f"{self.booking_date}T19:00",
                "party_size": 4,
            },
        )
        self.assertEqual(res_single.status, 201)
        self.assertEqual(res_single_table_ids := res_single.body["table_ids"], ["t_3"])
        self.assertEqual(res_single.body["table_id"], "t_3")

        # Non-transitive combination fails
        res_invalid = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_invalid"),
            {
                "restaurant_id": "r_anker",
                "table_ids": ["t_1", "t_3"],
                "starts_at_local": f"{self.booking_date}T20:00",
                "party_size": 8,
            },
        )
        self.assertEqual(res_invalid.status, 422)
        self.assertEqual(res_invalid.body["error"]["code"], "combination_not_allowed")

        # Both table_id and table_ids fails
        res_both = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_both"),
            {
                "restaurant_id": "r_anker",
                "table_id": "t_1",
                "table_ids": ["t_1", "t_2"],
                "starts_at_local": f"{self.booking_date}T20:00",
                "party_size": 2,
            },
        )
        self.assertEqual(res_both.status, 422)
        self.assertEqual(res_both.body["error"]["code"], "validation_failed")

    async def test_replan_preview_and_apply(self):
        # Seed booking at t_2
        res = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_seed"),
            {
                "restaurant_id": "r_anker",
                "table_id": "t_2",
                "starts_at_local": f"{self.booking_date}T19:00",
                "party_size": 4,
            },
        )
        self.assertEqual(res.status, 201)
        ref = res.body["reference"]

        # Check restaurant revision after 1 booking -> 1
        rest_resp = await self.api.handle("GET", "/restaurants/r_anker", {}, None)
        self.assertEqual(rest_resp.status, 200)
        self.assertEqual(rest_resp.body["revision"], 1)

        # Preview closure on t_2 from 18:00 to 22:00
        preview = await self.api.handle(
            "POST",
            "/restaurants/r_anker/replans",
            self.ada_headers("k_preview"),
            {
                "table_id": "t_2",
                "from": f"{self.booking_date}T18:00:00+02:00",
                "to": f"{self.booking_date}T22:00:00+02:00",
            },
        )
        self.assertEqual(preview.status, 201)
        plan = preview.body
        self.assertTrue(plan["plan_id"])
        self.assertEqual(plan["restaurant_revision"], 1)
        self.assertEqual(plan["moved_count"], 1)
        self.assertEqual(len(plan["assignments"]), 1)
        self.assertEqual(plan["assignments"][0]["reference"], ref)
        # Should be reassigned to single table t_3 (capacity 6 >= 4)
        self.assertEqual(plan["assignments"][0]["table_ids"], ["t_3"])
        self.assertTrue(plan["assignments"][0]["changed"])

        # Preview did NOT increment restaurant revision
        rest_resp2 = await self.api.handle("GET", "/restaurants/r_anker", {}, None)
        self.assertEqual(rest_resp2.body["revision"], 1)

        # Non-manager cannot apply
        bad_apply = await self.api.handle(
            "POST",
            f"/restaurants/r_anker/replans/{plan['plan_id']}/apply",
            self.bob_headers("k_apply_bad"),
            {},
        )
        self.assertEqual(bad_apply.status, 403)

        # Apply plan
        applied = await self.api.handle(
            "POST",
            f"/restaurants/r_anker/replans/{plan['plan_id']}/apply",
            self.ada_headers("k_apply_ok"),
            {},
        )
        self.assertEqual(applied.status, 201)
        self.assertEqual(applied.body["plan_id"], plan["plan_id"])
        self.assertEqual(applied.body["restaurant_revision"], 2)
        self.assertEqual(len(applied.body["reservations"]), 1)
        self.assertEqual(applied.body["reservations"][0]["table_ids"], ["t_3"])
        self.assertEqual(applied.body["reservations"][0]["table_id"], "t_3")
        self.assertEqual(applied.body["reservations"][0]["revision"], 2)

        # History has 'reassigned' with plan_id
        hist = await self.api.handle(
            "GET",
            f"/reservations/{ref}/history",
            {"authorization": f"Bearer {self.bob_token}"},
            None,
        )
        self.assertEqual(hist.status, 200)
        self.assertEqual(len(hist.body["entries"]), 2)
        reassign_entry = hist.body["entries"][1]
        self.assertEqual(reassign_entry["event"], "reassigned")
        self.assertEqual(reassign_entry["plan_id"], plan["plan_id"])
        self.assertEqual(reassign_entry["changes"], [{"field": "table_ids", "from": ["t_2"], "to": ["t_3"]}])

        # Replay apply returns 200
        replay = await self.api.handle(
            "POST",
            f"/restaurants/r_anker/replans/{plan['plan_id']}/apply",
            self.ada_headers("k_apply_ok"),
            {},
        )
        self.assertEqual(replay.status, 200)

        # Applied again under different key gives 409 plan_already_applied
        diff_key = await self.api.handle(
            "POST",
            f"/restaurants/r_anker/replans/{plan['plan_id']}/apply",
            self.ada_headers("k_apply_diff"),
            {},
        )
        self.assertEqual(diff_key.status, 409)
        self.assertEqual(diff_key.body["error"]["code"], "plan_already_applied")

        # Table t_2 is now closed during [18:00, 22:00)
        closed_book = await self.api.handle(
            "POST",
            "/reservations",
            self.bob_headers("k_closed_try"),
            {
                "restaurant_id": "r_anker",
                "table_id": "t_2",
                "starts_at_local": f"{self.booking_date}T19:30",
                "party_size": 2,
            },
        )
        self.assertEqual(closed_book.status, 409)
        self.assertEqual(closed_book.body["error"]["code"], "table_unavailable")

    async def test_series_amend_clock_time(self):
        # Create anchor booking
        anchor_res = await self.api.handle(
            "POST",
            "/reservations",
            self.ada_headers("k_anchor"),
            {
                "restaurant_id": "r_anker",
                "table_id": "t_1",
                "starts_at_local": f"{self.booking_date}T19:00",
                "party_size": 2,
            },
        )
        self.assertEqual(anchor_res.status, 201)
        anchor_ref = anchor_res.body["reference"]

        # Create recurring series (2 occurrences)
        made = await self.api.handle(
            "POST",
            "/series",
            self.ada_headers("k_series"),
            {
                "anchor_reference": anchor_ref,
                "count": 2,
                "interval_weeks": 1,
            },
        )
        self.assertEqual(made.status, 201)
        series_id = made.body["series_id"]
        self.assertEqual(made.body["revision"], 1)

        # Non-owner cannot amend
        bad_owner = await self.api.handle(
            "POST",
            f"/series/{series_id}/amend",
            self.bob_headers("k_amend_bob"),
            {"expected_revision": 1, "from_index": 0, "local_time": "20:00"},
        )
        self.assertEqual(bad_owner.status, 404)

        # Stale revision gives 409 stale_revision
        stale = await self.api.handle(
            "POST",
            f"/series/{series_id}/amend",
            self.ada_headers("k_stale"),
            {"expected_revision": 99, "from_index": 0, "local_time": "20:00"},
        )
        self.assertEqual(stale.status, 409)
        self.assertEqual(stale.body["error"]["code"], "stale_revision")

        # Successful series amendment
        amend_res = await self.api.handle(
            "POST",
            f"/series/{series_id}/amend",
            self.ada_headers("k_amend_ok"),
            {"expected_revision": 1, "from_index": 0, "local_time": "20:00"},
        )
        self.assertEqual(amend_res.status, 201)
        self.assertEqual(amend_res.body["revision"], 2)
        for occ in amend_res.body["occurrences"]:
            self.assertTrue(occ["reservation"]["starts_at_local"].endswith("T20:00"))
            self.assertFalse(occ["exception"], "series amendments do not mark exceptions")

        # Idempotent replay returns 200
        replay = await self.api.handle(
            "POST",
            f"/series/{series_id}/amend",
            self.ada_headers("k_amend_ok"),
            {"expected_revision": 1, "from_index": 0, "local_time": "20:00"},
        )
        self.assertEqual(replay.status, 200)


if __name__ == "__main__":
    unittest.main()
