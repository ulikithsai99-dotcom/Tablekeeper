"""Stage 1 Tablekeeper HTTP behavior, implemented on the existing state store."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .domain import DomainError
from .security import hash_password, is_valid_password_hash, issue_token, verify_password
from .state import ServiceState, StateStore
from .time_rules import resolve_local, rfc3339
from .validation import canonical_json

UTC = timezone.utc
WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
REFERENCE_RE = re.compile(r"^[A-Z0-9]{6,12}$")
LOCAL_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_RE = re.compile(r"^\d{2}:\d{2}$")
DECIMAL_RE = re.compile(r"^[0-9]+$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")
REFERENCE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
MISSING = object()


@dataclass(frozen=True)
class ApiResponse:
    status: int
    body: Any = None
    content_type: str = "application/json; charset=utf-8"


def _error(status: int, code: str, message: str) -> DomainError:
    return DomainError(status, code, message)


def _invalid(message: str = "validation failed") -> DomainError:
    return _error(422, "validation_failed", message)


def _not_found() -> DomainError:
    return _error(404, "not_found", "not found")


def _require_object(value: Any, *, missing_is_malformed: bool = True) -> dict[str, Any]:
    if value is None and missing_is_malformed:
        raise _error(400, "malformed_request", "request body must be a JSON object")
    if not isinstance(value, dict):
        raise _error(400, "malformed_request", "request body must be a JSON object")
    return value


def _required_string(value: dict[str, Any], name: str) -> str:
    if name not in value:
        raise _invalid(f"{name} is required")
    field = value[name]
    if not isinstance(field, str):
        raise _error(400, "malformed_request", f"{name} must be a string")
    return field


def _required_id(value: dict[str, Any], name: str) -> str:
    result = _required_string(value, name)
    if not result or len(result) > 64:
        raise _invalid(f"{name} must contain 1 to 64 characters")
    return result


def _party_size(value: dict[str, Any], *, required: bool = True, default: int | None = None) -> int:
    if "party_size" not in value:
        if required:
            raise _invalid("party_size is required")
        assert default is not None
        return default
    result = value["party_size"]
    # This field has a specific Stage 1 rule: even a string or boolean is 422.
    if isinstance(result, bool) or not isinstance(result, int) or result < 1:
        raise _invalid("party_size must be a positive integer")
    return result


def _parse_local(value: Any) -> datetime:
    if not isinstance(value, str):
        raise _error(400, "malformed_request", "starts_at_local must be a string")
    if not LOCAL_DATETIME_RE.fullmatch(value):
        raise _invalid("starts_at_local must be YYYY-MM-DDTHH:MM")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M")
    except ValueError as exc:
        raise _invalid("invalid local date or time") from exc


def _strict_date(value: str) -> date:
    if not DATE_RE.fullmatch(value):
        raise _invalid("date must be YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise _invalid("invalid date") from exc


def _parse_hhmm(value: Any, name: str) -> time:
    if not isinstance(value, str):
        if value is MISSING:
            raise _invalid(f"{name} is required")
        raise _error(400, "malformed_request", f"{name} must be a string")
    if not TIME_RE.fullmatch(value):
        raise _invalid(f"{name} must be HH:MM")
    try:
        return time.fromisoformat(value)
    except ValueError as exc:
        raise _invalid(f"{name} must be HH:MM") from exc


def _integer(value: Any, name: str, *, minimum: int) -> int:
    if value is MISSING:
        raise _invalid(f"{name} is required")
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(400, "malformed_request", f"{name} must be an integer")
    if value < minimum:
        raise _invalid(f"{name} must be an integer of at least {minimum}")
    return value


def _fixture_string(value: Any, name: str, *, nonempty: bool = False) -> str:
    if value is MISSING:
        raise _invalid(f"{name} is required")
    if not isinstance(value, str):
        raise _error(400, "malformed_request", f"{name} must be a string")
    if nonempty and not value:
        raise _invalid(f"{name} must not be empty")
    return value


def _json_shape(value: Any) -> Any:
    """Ensure parsed request JSON follows JSON's finite-number rules."""
    if isinstance(value, float) and not (float("-inf") < value < float("inf")):
        raise _error(400, "malformed_request", "invalid JSON number")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise _error(400, "malformed_request", "invalid JSON object")
            _json_shape(child)
    elif isinstance(value, list):
        for child in value:
            _json_shape(child)
    return value


def _aware(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise _invalid("invalid timestamp in state") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _invalid("timestamp must include an offset")
    return parsed


def _instant(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _overlap(start_a: datetime, end_a: datetime, start_b: datetime, end_b: datetime) -> bool:
    return _instant(start_a) < _instant(end_b) and _instant(start_b) < _instant(end_a)


def _make_error_response(error: DomainError) -> ApiResponse:
    return ApiResponse(error.status, error.error_body())


def _fixture_state(fixture: Any) -> ServiceState:
    if not isinstance(fixture, dict):
        raise _invalid("fixture must be an object")
    users_data = fixture.get("users", [])
    restaurants_data = fixture.get("restaurants", [])
    reservations_data = fixture.get("reservations", [])
    if not isinstance(users_data, list) or not isinstance(restaurants_data, list) or not isinstance(reservations_data, list):
        raise _error(400, "malformed_request", "fixture collections must be arrays")

    state = ServiceState()
    for item in users_data:
        if not isinstance(item, dict):
            raise _error(400, "malformed_request", "each user must be an object")
        user_id = _fixture_id(item.get("id", MISSING), "user id")
        email = _fixture_string(item.get("email", MISSING), "email")
        password = _fixture_string(item.get("password", MISSING), "password")
        display_name = _fixture_string(item.get("display_name", MISSING), "display_name")
        if not email:
            raise _invalid("email must not be empty")
        email_key = email.casefold()
        if user_id in state.users or any(user["email"].casefold() == email_key for user in state.users.values()):
            raise _invalid("duplicate user id or email")
        state.users[user_id] = {
            "id": user_id,
            "email": email,
            "password_hash": hash_password(password),
            "display_name": display_name,
        }

    for item in restaurants_data:
        if not isinstance(item, dict):
            raise _error(400, "malformed_request", "each restaurant must be an object")
        restaurant_id = _fixture_id(item.get("id", MISSING), "restaurant id")
        if restaurant_id in state.restaurants:
            raise _invalid("duplicate restaurant id")
        name = _fixture_string(item.get("name", MISSING), "name")
        timezone_name = _fixture_string(item.get("timezone", MISSING), "timezone", nonempty=True)
        try:
            ZoneInfo(timezone_name)
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise _invalid("invalid restaurant timezone") from exc
        slot_minutes = _integer(item.get("slot_minutes", MISSING), "slot_minutes", minimum=1)
        duration = _integer(item.get("reservation_duration_minutes", MISSING), "reservation_duration_minutes", minimum=1)
        cutoff = _integer(item.get("cancellation_cutoff_minutes", MISSING), "cancellation_cutoff_minutes", minimum=0)
        hours = item.get("opening_hours", MISSING)
        tables = item.get("tables", MISSING)
        if hours is MISSING or tables is MISSING:
            raise _invalid("opening_hours and tables are required")
        if not isinstance(hours, list) or not isinstance(tables, list):
            raise _error(400, "malformed_request", "opening_hours and tables must be arrays")
        normalized_hours = []
        seen_weekdays: set[str] = set()
        for opening in hours:
            if not isinstance(opening, dict):
                raise _error(400, "malformed_request", "each opening hour must be an object")
            weekday = _fixture_string(opening.get("weekday", MISSING), "weekday")
            if weekday not in WEEKDAYS or weekday in seen_weekdays:
                raise _invalid("invalid or duplicate weekday")
            opens = _parse_hhmm(opening.get("opens", MISSING), "opens")
            closes = _parse_hhmm(opening.get("closes", MISSING), "closes")
            if closes <= opens:
                raise _invalid("closes must be later than opens")
            seen_weekdays.add(weekday)
            normalized_hours.append({"weekday": weekday, "opens": opens.strftime("%H:%M"), "closes": closes.strftime("%H:%M")})
        normalized_tables = []
        seen_table_ids: set[str] = set()
        for table in tables:
            if not isinstance(table, dict):
                raise _error(400, "malformed_request", "each table must be an object")
            table_id = _fixture_id(table.get("id", MISSING), "table id")
            label = _fixture_string(table.get("label", MISSING), "label")
            capacity = _integer(table.get("capacity", MISSING), "capacity", minimum=1)
            if table_id in seen_table_ids:
                raise _invalid("invalid or duplicate table")
            seen_table_ids.add(table_id)
            normalized_tables.append({"id": table_id, "label": label, "capacity": capacity})
        manager_user_ids = []
        if "manager_user_ids" in item:
            raw_managers = item["manager_user_ids"]
            if not isinstance(raw_managers, list):
                raise _error(400, "malformed_request", "manager_user_ids must be an array")
            seen_managers: set[str] = set()
            for m in raw_managers:
                if not isinstance(m, str) or not (1 <= len(m) <= 64):
                    raise _invalid("manager user id must be 1 to 64 characters")
                if m in seen_managers:
                    raise _invalid("duplicate manager user id")
                if state.users and m not in state.users:
                    raise _invalid("manager user does not exist")
                seen_managers.add(m)
                manager_user_ids.append(m)

        combinable_pairs = []
        if "combinable" in item:
            raw_comb = item["combinable"]
            if not isinstance(raw_comb, list):
                raise _error(400, "malformed_request", "combinable must be an array")
            for pair in raw_comb:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise _invalid("each combinable pair must have 2 table ids")
                p1, p2 = pair[0], pair[1]
                if not isinstance(p1, str) or not isinstance(p2, str) or p1 == p2:
                    raise _invalid("invalid combinable pair")
                if p1 not in seen_table_ids or p2 not in seen_table_ids:
                    raise _invalid("combinable table not found")
                combinable_pairs.append([p1, p2])

        state.restaurants[restaurant_id] = {
            "id": restaurant_id,
            "name": name,
            "timezone": timezone_name,
            "slot_minutes": slot_minutes,
            "reservation_duration_minutes": duration,
            "cancellation_cutoff_minutes": cutoff,
            "opening_hours": normalized_hours,
            "tables": normalized_tables,
            "manager_user_ids": manager_user_ids,
            "combinable": combinable_pairs,
            "closures": [],
            "revision": 0,
            "policies": [],
        }

    now = rfc3339(datetime.now(UTC))
    seen_reservation_ids: set[str] = set()
    seen_references: set[str] = set()
    for item in reservations_data:
        if not isinstance(item, dict):
            raise _error(400, "malformed_request", "each reservation must be an object")
        has_table = ("table_id" in item) or ("table_ids" in item)
        if not (has_table and all(name in item for name in ("restaurant_id", "starts_at_local", "party_size"))):
            raise _invalid("seeded reservation is missing required fields")
        reservation_id = _fixture_id(item.get("id", MISSING), "reservation id")
        reference = item.get("reference", MISSING)
        user_id = item.get("user_id", MISSING)
        if reference is MISSING or user_id is MISSING:
            raise _invalid("seeded reservation is missing identity fields")
        if not isinstance(reference, str):
            raise _error(400, "malformed_request", "reservation reference must be a string")
        if not REFERENCE_RE.fullmatch(reference):
            raise _invalid("invalid reservation reference")
        if not isinstance(user_id, str):
            raise _error(400, "malformed_request", "reservation user_id must be a string")
        if user_id not in state.users:
            raise _invalid("reservation user does not exist")
        if reservation_id in seen_reservation_ids or reference in seen_references:
            raise _invalid("duplicate reservation id or reference")
        try:
            res_payload = {
                "restaurant_id": item.get("restaurant_id"),
                "starts_at_local": item.get("starts_at_local"),
                "party_size": item.get("party_size"),
            }
            if "table_id" in item:
                res_payload["table_id"] = item.get("table_id")
            if "table_ids" in item:
                res_payload["table_ids"] = item.get("table_ids")
            record = _new_reservation(
                state,
                user_id,
                res_payload,
                reservation_id=reservation_id,
                reference=reference,
                created_at=now,
            )
        except DomainError as exc:
            if exc.status == 400:
                raise
        if item.get("status") == "cancelled":
            record["status"] = "cancelled"
            record["revision"] = 2
            record["history"].append({
                "seq": 2,
                "at": now,
                "event": "cancelled",
                "revision": 2,
                "accepted_terms": copy.deepcopy(record["accepted_terms"]),
                "changes": [],
            })
        state.reservations[reference] = record
        seen_reservation_ids.add(reservation_id)
        seen_references.add(reference)
    return state


def _fixture_id(value: Any, name: str) -> str:
    if value is MISSING:
        raise _invalid(f"{name} is required")
    if not isinstance(value, str):
        raise _error(400, "malformed_request", f"{name} must be a string")
    if not value or len(value) > 64:
        raise _invalid(f"{name} must contain 1 to 64 characters")
    return value


def get_policy_0(restaurant: dict[str, Any]) -> dict[str, Any]:
    """Policy 0 is the original fixture's rules and applies before any published policy."""
    return {
        "policy_version": 0,
        "effective_from": None,
        "slot_minutes": restaurant["slot_minutes"],
        "reservation_duration_minutes": restaurant["reservation_duration_minutes"],
        "cancellation_cutoff_minutes": restaurant["cancellation_cutoff_minutes"],
        "opening_hours": copy.deepcopy(restaurant["opening_hours"]),
        "capacities": {table["id"]: table["capacity"] for table in restaurant["tables"]},
    }


def get_effective_policy(restaurant: dict[str, Any], local_date: date | str) -> dict[str, Any]:
    """
    Selects the effective policy for a restaurant on local_date.
    For a booking's local start date, choose the greatest effective_from not later than
    that date; ties choose the greatest policy_version. If no published policy is applicable,
    Policy 0 applies.
    """
    if isinstance(local_date, date):
        date_str = local_date.isoformat()
    elif isinstance(local_date, str):
        date_str = local_date.split("T")[0]
    else:
        raise _invalid("invalid local date")

    applicable = [
        p for p in restaurant.get("policies", [])
        if p.get("effective_from") is not None and p["effective_from"] <= date_str
    ]
    if not applicable:
        return get_policy_0(restaurant)

    best = max(applicable, key=lambda p: (p["effective_from"], p["policy_version"]))
    return copy.deepcopy(best)


def extract_accepted_terms(policy: dict[str, Any]) -> dict[str, Any]:
    """A snapshot of the entire selected policy, excluding effective_from."""
    return {
        "policy_version": policy["policy_version"],
        "slot_minutes": policy["slot_minutes"],
        "reservation_duration_minutes": policy["reservation_duration_minutes"],
        "cancellation_cutoff_minutes": policy["cancellation_cutoff_minutes"],
        "opening_hours": copy.deepcopy(policy["opening_hours"]),
        "capacities": copy.deepcopy(policy["capacities"]),
    }


def _validate_policy_payload(restaurant: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    required_fields = {
        "effective_from",
        "slot_minutes",
        "reservation_duration_minutes",
        "cancellation_cutoff_minutes",
        "opening_hours",
        "capacities",
    }
    if not isinstance(payload, dict):
        raise _invalid("policy must be an object")
    if not required_fields.issubset(payload.keys()):
        raise _invalid("policy is missing required fields")

    effective_from_val = payload["effective_from"]
    if not isinstance(effective_from_val, str) or not DATE_RE.fullmatch(effective_from_val):
        raise _invalid("effective_from must be a YYYY-MM-DD date")
    try:
        date.fromisoformat(effective_from_val)
    except ValueError as exc:
        raise _invalid("invalid effective_from date") from exc

    slot_minutes = payload["slot_minutes"]
    if isinstance(slot_minutes, bool) or not isinstance(slot_minutes, int) or not (1 <= slot_minutes <= 1440):
        raise _invalid("slot_minutes must be an integer between 1 and 1440")

    duration = payload["reservation_duration_minutes"]
    if isinstance(duration, bool) or not isinstance(duration, int) or not (1 <= duration <= 1440):
        raise _invalid("reservation_duration_minutes must be an integer between 1 and 1440")

    cutoff = payload["cancellation_cutoff_minutes"]
    if isinstance(cutoff, bool) or not isinstance(cutoff, int) or not (0 <= cutoff <= 10080):
        raise _invalid("cancellation_cutoff_minutes must be an integer between 0 and 10080")

    hours_val = payload["opening_hours"]
    if not isinstance(hours_val, list):
        raise _invalid("opening_hours must be an array")
    normalized_hours = []
    seen_weekdays: set[str] = set()
    for opening in hours_val:
        if not isinstance(opening, dict):
            raise _invalid("each opening hour must be an object")
        weekday = opening.get("weekday")
        if not isinstance(weekday, str) or weekday not in WEEKDAYS or weekday in seen_weekdays:
            raise _invalid("invalid or duplicate weekday in opening_hours")
        opens_raw = opening.get("opens")
        closes_raw = opening.get("closes")
        if not isinstance(opens_raw, str) or not isinstance(closes_raw, str):
            raise _invalid("opens and closes must be strings")
        opens = _parse_hhmm(opens_raw, "opens")
        closes = _parse_hhmm(closes_raw, "closes")
        if closes <= opens:
            raise _invalid("closes must be later than opens")
        seen_weekdays.add(weekday)
        normalized_hours.append({
            "weekday": weekday,
            "opens": opens.strftime("%H:%M"),
            "closes": closes.strftime("%H:%M"),
        })

    capacities_val = payload["capacities"]
    if not isinstance(capacities_val, dict):
        raise _invalid("capacities must be an object")
    expected_tables = {t["id"] for t in restaurant["tables"]}
    if set(capacities_val.keys()) != expected_tables:
        raise _invalid("capacities must name exactly the restaurant's table ids")
    normalized_capacities = {}
    for table_id in sorted(expected_tables):
        cap = capacities_val[table_id]
        if isinstance(cap, bool) or not isinstance(cap, int) or not (1 <= cap <= 100):
            raise _invalid("table capacity must be an integer between 1 and 100")
        normalized_capacities[table_id] = cap

    return {
        "effective_from": effective_from_val,
        "slot_minutes": slot_minutes,
        "reservation_duration_minutes": duration,
        "cancellation_cutoff_minutes": cutoff,
        "opening_hours": normalized_hours,
        "capacities": normalized_capacities,
    }


def _restaurant_table(state: ServiceState, restaurant_id: str, table_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    restaurant = state.restaurants.get(restaurant_id)
    if restaurant is None:
        raise _not_found()
    table = next((candidate for candidate in restaurant["tables"] if candidate["id"] == table_id), None)
    if table is None:
        raise _not_found()
    return restaurant, table


def _opening_for(restaurant: dict[str, Any], local_date: date) -> dict[str, str] | None:
    day = WEEKDAYS[local_date.weekday()]
    return next((entry for entry in restaurant["opening_hours"] if entry["weekday"] == day), None)


def _closing_instant(local_date: date, closing: str, timezone_name: str) -> datetime:
    # Opening-hour boundaries are configured as wall-clock times. ZoneInfo's fold=0
    # interpretation maps a nonexistent boundary to the transition's post-gap instant.
    naive = datetime.combine(local_date, time.fromisoformat(closing))
    return naive.replace(tzinfo=ZoneInfo(timezone_name), fold=0).astimezone(UTC)


def _resolve_booking_time(
    restaurant: dict[str, Any],
    local_value: Any,
    *,
    policy: dict[str, Any] | None = None,
) -> tuple[datetime, str]:
    naive = _parse_local(local_value)
    local_string = naive.strftime("%Y-%m-%dT%H:%M")
    try:
        start = resolve_local(local_string, restaurant["timezone"])
    except DomainError as exc:
        raise _error(422, "invalid_local_time", exc.message) from exc
    active_policy = policy or get_effective_policy(restaurant, naive.date())
    opening = _opening_for(active_policy, naive.date())
    if opening is None:
        raise _error(422, "outside_opening_hours", "restaurant is closed")
    opens = time.fromisoformat(opening["opens"])
    closes = time.fromisoformat(opening["closes"])
    if not (opens <= naive.time() < closes):
        raise _error(422, "outside_opening_hours", "time is outside opening hours")
    opens_minutes = opens.hour * 60 + opens.minute
    start_minutes = naive.hour * 60 + naive.minute
    if (start_minutes - opens_minutes) % active_policy["slot_minutes"] != 0:
        raise _error(422, "not_on_slot_grid", "time is not on the slot grid")
    close_instant = _closing_instant(naive.date(), opening["closes"], restaurant["timezone"])
    available_seconds = (close_instant - _instant(start)).total_seconds()
    if active_policy["reservation_duration_minutes"] * 60 > available_seconds:
        raise _error(422, "outside_opening_hours", "reservation ends after closing")
    return start, local_string


def _record_end(record: dict[str, Any]) -> datetime:
    return _aware(record["ends_at"])


def _normalize_table_selection(restaurant: dict[str, Any], values: dict[str, Any]) -> list[str]:
    if "table_id" in values and "table_ids" in values:
        raise _error(422, "validation_failed", "cannot provide both table_id and table_ids")
    if "table_id" in values:
        tid = _required_id(values, "table_id")
        if not any(t["id"] == tid for t in restaurant["tables"]):
            raise _not_found()
        return [tid]
    if "table_ids" in values:
        tids = values["table_ids"]
        if not isinstance(tids, list) or not tids:
            raise _error(422, "validation_failed", "table_ids must be a non-empty array")
        for tid in tids:
            if not isinstance(tid, str) or not (1 <= len(tid) <= 64):
                raise _error(422, "validation_failed", "each table_id must be 1 to 64 characters")
        if len(tids) != len(set(tids)):
            raise _error(422, "validation_failed", "duplicate table ID in table_ids")
        for tid in tids:
            if not any(t["id"] == tid for t in restaurant["tables"]):
                raise _not_found()
        if len(tids) > 2:
            raise _error(422, "combination_not_allowed", "combinations are pairs only")
        if len(tids) == 2:
            pair_set = set(tids)
            allowed = [set(p) for p in restaurant.get("combinable", [])]
            if pair_set not in allowed:
                raise _error(422, "combination_not_allowed", "table combination not allowed")
        return list(tids)
    raise _error(422, "validation_failed", "table_id or table_ids is required")


def _table_selection_capacity(restaurant: dict[str, Any], policy: dict[str, Any], table_ids: list[str]) -> int:
    table_cap_map = {t["id"]: t["capacity"] for t in restaurant["tables"]}
    caps = policy.get("capacities", {})
    return sum(caps.get(tid, table_cap_map.get(tid, 0)) for tid in table_ids)


def _has_conflict(
    state: ServiceState,
    restaurant_id: str,
    table_or_tables: str | list[str],
    start: datetime,
    end: datetime,
    *,
    ignore_references: set[str] | None = None,
) -> bool:
    target_tables = set([table_or_tables] if isinstance(table_or_tables, str) else table_or_tables)
    ignored = ignore_references or set()
    restaurant = state.restaurants.get(restaurant_id)
    if restaurant is not None:
        for cl in restaurant.get("closures", []):
            if cl["table_id"] in target_tables:
                c_start = _aware(cl["from"])
                c_end = _aware(cl["to"])
                if _overlap(start, end, c_start, c_end):
                    return True
    for reference, existing in state.reservations.items():
        if reference in ignored or existing.get("status") != "confirmed":
            continue
        if existing["restaurant_id"] != restaurant_id:
            continue
        existing_tables = set(existing.get("table_ids") or ([existing["table_id"]] if "table_id" in existing else []))
        if not (target_tables & existing_tables):
            continue
        if _overlap(start, end, _aware(existing["starts_at"]), _record_end(existing)):
            return True
    return False


def _serialize_reservation(record: dict[str, Any]) -> dict[str, Any]:
    fields = [
        "reservation_id", "reference", "restaurant_id", "table_id", "table_ids",
        "party_size", "status", "starts_at_local", "starts_at", "ends_at",
        "created_at", "revision", "accepted_terms"
    ]
    res = {}
    for k in fields:
        if k in record:
            res[k] = copy.deepcopy(record[k])
    if "table_ids" not in res and "table_id" in res:
        res["table_ids"] = [res["table_id"]]
    if "table_ids" in res:
        if len(res["table_ids"]) == 1:
            res["table_id"] = res["table_ids"][0]
        else:
            res.pop("table_id", None)
    return res


def _new_reservation(
    state: ServiceState,
    user_id: str,
    values: dict[str, Any],
    *,
    reservation_id: str | None = None,
    reference: str | None = None,
    created_at: str | None = None,
    ignore_references: set[str] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    restaurant_id = _required_id(values, "restaurant_id")
    restaurant = state.restaurants.get(restaurant_id)
    if restaurant is None:
        raise _not_found()
    table_ids = _normalize_table_selection(restaurant, values)
    party_size = _party_size(values)
    if "starts_at_local" not in values:
        raise _invalid("starts_at_local is required")
    naive = _parse_local(values["starts_at_local"])
    effective_policy = policy or get_effective_policy(restaurant, naive.date())
    capacity = _table_selection_capacity(restaurant, effective_policy, table_ids)
    if party_size > capacity:
        raise _error(422, "party_exceeds_capacity", "party size exceeds table capacity")
    start, local_string = _resolve_booking_time(restaurant, values.get("starts_at_local"), policy=effective_policy)
    end = _instant(start) + timedelta(minutes=effective_policy["reservation_duration_minutes"])
    end_local = end.astimezone(ZoneInfo(restaurant["timezone"]))
    if _has_conflict(
        state,
        restaurant_id,
        table_ids,
        start,
        end,
        ignore_references=ignore_references,
    ):
        raise _error(409, "table_unavailable", "table is unavailable")
    if reference is None:
        while True:
            candidate = "".join(secrets.choice(REFERENCE_ALPHABET) for _ in range(8))
            if candidate not in state.reservations:
                reference = candidate
                break
    assert reference is not None
    now_ts = created_at or rfc3339(datetime.now(UTC))
    terms = extract_accepted_terms(effective_policy)
    changes = []
    if len(table_ids) > 1:
        changes.append({"field": "table_ids", "from": None, "to": list(table_ids)})
    else:
        changes.append({"field": "table_id", "from": None, "to": table_ids[0]})
    changes.append({"field": "starts_at_local", "from": None, "to": local_string})
    changes.append({"field": "party_size", "from": None, "to": party_size})

    history_entry = {
        "seq": 1,
        "at": now_ts,
        "event": "created",
        "revision": 1,
        "accepted_terms": copy.deepcopy(terms),
        "changes": changes,
    }
    record = {
        "reservation_id": reservation_id or uuid.uuid4().hex,
        "reference": reference,
        "user_id": user_id,
        "restaurant_id": restaurant_id,
        "table_ids": list(table_ids),
        "party_size": party_size,
        "status": "confirmed",
        "starts_at_local": local_string,
        "starts_at": rfc3339(start),
        "ends_at": rfc3339(end_local),
        "created_at": now_ts,
        "revision": 1,
        "accepted_terms": terms,
        "history": [history_entry],
    }
    if len(table_ids) == 1:
        record["table_id"] = table_ids[0]
    return record


def _compute_replan(
    restaurant: dict[str, Any],
    closure_table_id: str,
    from_dt: datetime,
    to_dt: datetime,
    from_str: str,
    to_str: str,
    state: ServiceState,
) -> dict[str, Any]:
    restaurant_id = restaurant["id"]
    tables = restaurant["tables"]
    combinable = restaurant.get("combinable", [])

    singles = [[t["id"]] for t in tables]
    pairs = [list(p) for p in combinable]
    all_options = singles + pairs

    if len(tables) > 6 or len(pairs) > 4:
        raise DomainError(422, "planning_limit", "planning limit exceeded")

    considered: list[dict[str, Any]] = []
    for r in state.reservations.values():
        if r.get("restaurant_id") == restaurant_id and r.get("status") == "confirmed":
            b_start = _aware(r["starts_at"])
            b_end = _record_end(r)
            if _overlap(b_start, b_end, from_dt, to_dt):
                considered.append(r)

    if len(considered) > 6:
        raise DomainError(422, "planning_limit", "planning limit exceeded")

    considered.sort(key=lambda b: b["reference"])
    K = len(considered)
    plan_id = "plan_" + secrets.token_hex(16)

    if K == 0:
        return {
            "plan_id": plan_id,
            "restaurant_id": restaurant_id,
            "restaurant_revision": restaurant.get("revision", 0),
            "closure": {
                "table_id": closure_table_id,
                "from": from_str,
                "to": to_str,
            },
            "assignments": [],
            "moved_count": 0,
            "unused_seats": 0,
            "applied": False,
        }

    considered_refs = {b["reference"] for b in considered}
    fixed: list[dict[str, Any]] = [
        r for r in state.reservations.values()
        if r.get("restaurant_id") == restaurant_id and r.get("status") == "confirmed" and r["reference"] not in considered_refs
    ]
    applied_closures = restaurant.get("closures", [])
    table_cap_map = {t["id"]: t["capacity"] for t in tables}

    eligible_per_booking: list[list[tuple[int, list[str], bool, int]]] = []
    for b in considered:
        b_start = _aware(b["starts_at"])
        b_end = _record_end(b)
        b_party = b["party_size"]
        curr_tables = set(b.get("table_ids") or ([b["table_id"]] if "table_id" in b else []))
        terms = b.get("accepted_terms", {})
        term_caps = terms.get("capacities", {})

        booking_opts = []
        for opt_idx, opt in enumerate(all_options):
            cap = sum(term_caps.get(tid, table_cap_map.get(tid, 0)) for tid in opt)
            if cap < b_party:
                continue

            if closure_table_id in opt and _overlap(b_start, b_end, from_dt, to_dt):
                continue

            conflict_applied = False
            for cl in applied_closures:
                if cl["table_id"] in opt:
                    cl_start = _aware(cl["from"])
                    cl_end = _aware(cl["to"])
                    if _overlap(b_start, b_end, cl_start, cl_end):
                        conflict_applied = True
                        break
            if conflict_applied:
                continue

            conflict_fixed = False
            opt_set = set(opt)
            for f in fixed:
                f_tables = set(f.get("table_ids") or ([f["table_id"]] if "table_id" in f else []))
                if (opt_set & f_tables) and _overlap(b_start, b_end, _aware(f["starts_at"]), _record_end(f)):
                    conflict_fixed = True
                    break
            if conflict_fixed:
                continue

            changed = (set(opt) != curr_tables)
            unused = cap - b_party
            booking_opts.append((opt_idx, opt, changed, unused))

        if not booking_opts:
            raise DomainError(409, "no_feasible_plan", "no feasible plan")
        eligible_per_booking.append(booking_opts)

    best_cost: tuple[int, int, tuple[int, ...]] | None = None
    best_assignment: list[tuple[int, list[str], bool]] | None = None

    current_assignment: list[tuple[int, list[str], bool] | None] = [None] * K
    current_tables_assigned: list[set[str] | None] = [None] * K

    def backtrack(idx: int, cur_moved: int, cur_unused: int, cur_ranks: list[int]):
        nonlocal best_cost, best_assignment
        if idx == K:
            cost = (cur_moved, cur_unused, tuple(cur_ranks))
            if best_cost is None or cost < best_cost:
                best_cost = cost
                best_assignment = list(current_assignment)  # type: ignore
            return

        b = considered[idx]
        b_start = _aware(b["starts_at"])
        b_end = _record_end(b)

        for opt_idx, opt, changed, unused in eligible_per_booking[idx]:
            opt_set = set(opt)
            conflict = False
            for prev_idx in range(idx):
                if opt_set & current_tables_assigned[prev_idx]:  # type: ignore
                    prev_b = considered[prev_idx]
                    if _overlap(b_start, b_end, _aware(prev_b["starts_at"]), _record_end(prev_b)):
                        conflict = True
                        break
            if conflict:
                continue

            new_moved = cur_moved + (1 if changed else 0)
            new_unused = cur_unused + unused
            new_ranks = cur_ranks + [opt_idx]

            if best_cost is not None:
                if new_moved > best_cost[0]:
                    continue
                if new_moved == best_cost[0] and new_unused > best_cost[1]:
                    continue
                if (
                    new_moved == best_cost[0]
                    and new_unused == best_cost[1]
                    and tuple(new_ranks) > best_cost[2][: len(new_ranks)]
                ):
                    continue

            current_assignment[idx] = (opt_idx, opt, changed)
            current_tables_assigned[idx] = opt_set
            backtrack(idx + 1, new_moved, new_unused, new_ranks)
            current_tables_assigned[idx] = None
            current_assignment[idx] = None

    backtrack(0, 0, 0, [])

    if best_assignment is None:
        raise DomainError(409, "no_feasible_plan", "no feasible plan")

    assignments = []
    for idx, b in enumerate(considered):
        opt_idx, opt, changed = best_assignment[idx]
        assignments.append({
            "reference": b["reference"],
            "table_ids": list(opt),
            "changed": bool(changed),
        })

    return {
        "plan_id": plan_id,
        "restaurant_id": restaurant_id,
        "restaurant_revision": restaurant.get("revision", 0),
        "closure": {
            "table_id": closure_table_id,
            "from": from_str,
            "to": to_str,
        },
        "assignments": assignments,
        "moved_count": best_cost[0],
        "unused_seats": best_cost[1],
        "applied": False,
    }


def _validate_idempotency_key(headers: dict[str, str]) -> str:
    key = headers.get("idempotency-key", "")
    if not key:
        raise _error(400, "missing_idempotency_key", "Idempotency-Key is required")
    if not 1 <= len(key) <= 255:
        raise _invalid("Idempotency-Key must contain 1 to 255 characters")
    return key


def _bearer(headers: dict[str, str]) -> str:
    authorization = headers.get("authorization", "")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
        raise _error(401, "unauthenticated", "valid bearer token required")
    return parts[1]


def _query_one(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name)
    if not values or values[0] == "":
        raise _invalid(f"{name} is required")
    return values[0]


def _default_seed_state() -> ServiceState:
    weekdays = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    default_hours = [{"weekday": d, "opens": "08:00", "closes": "23:30"} for d in weekdays]

    def make_tables(count: int) -> list[dict[str, Any]]:
        tables = []
        capacities = [2, 2, 4, 4, 6, 8]
        for i in range(1, count + 1):
            cap = capacities[(i - 1) % len(capacities)]
            tables.append({"id": f"t_{i}", "label": str(i), "capacity": cap})
        return tables

    venues = [
        # MUMBAI (India)
        {"id": "r_mumbai_royal", "name": "The Royal Pavilion & Palace", "city": "Mumbai", "timezone": "Asia/Kolkata", "category": "Indian Royal Fine Dining", "theme": "mumbai_royal", "bg_image": "/assets/mumbai.jpg"},
        {"id": "r_mumbai_bastian", "name": "Bastian Rooftop & Grill", "city": "Mumbai", "timezone": "Asia/Kolkata", "category": "Rooftop Seafood & Bar", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1517248135467-4c7edcad34c4?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_mumbai_trident", "name": "Trident Bay Lounge", "city": "Mumbai", "timezone": "Asia/Kolkata", "category": "Luxury Bay Pub & Lounge", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1578474846511-04ba529f0b88?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_mumbai_canteen", "name": "The Bombay Canteen Bar", "city": "Mumbai", "timezone": "Asia/Kolkata", "category": "Modern Indian Pub", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1585937421612-70a008356fbe?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_mumbai_zuma", "name": "Masala Library Gastronomy", "city": "Mumbai", "timezone": "Asia/Kolkata", "category": "Molecular Indian Dining", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1565557623262-b51c2513a641?auto=format&fit=crop&w=800&q=80"},

        # PARIS (France)
        {"id": "r_lumiere", "name": "Lumière Gastronomy", "city": "Paris", "timezone": "Europe/Paris", "category": "Modern French Fine Dining", "theme": "parisian_gold", "bg_image": "/assets/lumiere.jpg"},
        {"id": "r_maison", "name": "Maison Rouge Bistro", "city": "Paris", "timezone": "Europe/Paris", "category": "Classic French Bistro", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1550966871-3ed3cdb5ed0c?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_paris_jules", "name": "Le Jules Verne Eiffel", "city": "Paris", "timezone": "Europe/Paris", "category": "Eiffel Tower Fine Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1502602898657-3e91760cbb34?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_paris_meurice", "name": "Le Meurice Alain Ducasse", "city": "Paris", "timezone": "Europe/Paris", "category": "Palace Hotel Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1544025162-d76694265947?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_paris_laperouse", "name": "Lapérouse Historic Lounge", "city": "Paris", "timezone": "Europe/Paris", "category": "Historic Lounge Bar", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1514933651103-005eec06c04b?auto=format&fit=crop&w=800&q=80"},

        # TOKYO (Japan)
        {"id": "r_omakase", "name": "Ginza Omakase Counter", "city": "Tokyo", "timezone": "Asia/Tokyo", "category": "Japanese Omakase", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1579871494447-9811cf80d66c?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_tokyo_roppongi", "name": "Roppongi Sky Lounge", "city": "Tokyo", "timezone": "Asia/Tokyo", "category": "Cocktail Lounge & Pub", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1503899036084-c55cdd92da26?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_tokyo_sukiyabashi", "name": "Sukiyabashi Sushi Bar", "city": "Tokyo", "timezone": "Asia/Tokyo", "category": "Traditional Sushi Counter", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1611143669185-af224c5e3252?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_tokyo_narisawa", "name": "Narisawa Innovative Grill", "city": "Tokyo", "timezone": "Asia/Tokyo", "category": "Avant-Garde Dining", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1555396273-367ea4eb4db5?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_tokyo_parkhyatt", "name": "New York Grill Tokyo", "city": "Tokyo", "timezone": "Asia/Tokyo", "category": "Skyline Steakhouse & Bar", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1540555700478-4be289fbecef?auto=format&fit=crop&w=800&q=80"},

        # LONDON (UK)
        {"id": "r_velvet", "name": "Velvet & Oak Gastropub", "city": "London", "timezone": "Europe/London", "category": "British Gastropub & Grill", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1572116469696-31de0f17cc34?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_london_wolseley", "name": "The Wolseley Piccadilly", "city": "London", "timezone": "Europe/London", "category": "Grand European Cafe", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1559339352-11d035aa65de?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_london_mayfair", "name": "Mayfair Prime Steakhouse", "city": "London", "timezone": "Europe/London", "category": "Mayfair Steak & Wine", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1550547660-d9450f859349?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_london_sketch", "name": "Sketch Gallery Lounge", "city": "London", "timezone": "Europe/London", "category": "Artisan Cocktail Lounge", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1566073771259-6a8506099945?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_london_ritz", "name": "The Ritz Restaurant", "city": "London", "timezone": "Europe/London", "category": "British Palace Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1578683010236-d716f9a3f461?auto=format&fit=crop&w=800&q=80"},

        # NEW YORK (USA)
        {"id": "r_nocturne", "name": "Nocturne Sky Lounge", "city": "New York", "timezone": "America/New_York", "category": "Manhattan Rooftop Lounge", "theme": "rooftop_sky", "bg_image": "/assets/rooftop.jpg"},
        {"id": "r_ny_manhatta", "name": "Manhatta High-Rise Grill", "city": "New York", "timezone": "America/New_York", "category": "Downtown Panoramic Grill", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1533105079780-92b9be482077?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_ny_balthazar", "name": "Balthazar SoHo Bistro", "city": "New York", "timezone": "America/New_York", "category": "SoHo French Bistro", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1414235077428-338989a2e8c0?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_ny_eleven", "name": "Eleven Madison Fine Dining", "city": "New York", "timezone": "America/New_York", "category": "3-Star Fine Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1552566626-52f8b828add9?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_ny_bernardin", "name": "Le Bernardin Seafood", "city": "New York", "timezone": "America/New_York", "category": "Luxury Seafood Dining", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1534422298391-e4f8c172dddb?auto=format&fit=crop&w=800&q=80"},

        # DUBAI (UAE)
        {"id": "r_dubai_atmosphere", "name": "At.mosphere Burj Khalifa", "city": "Dubai", "timezone": "Asia/Dubai", "category": "Burj Skyline Lounge", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1512453979798-5ea266f8880c?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_dubai_zuma", "name": "Zuma Dubai Lounge", "city": "Dubai", "timezone": "Asia/Dubai", "category": "Contemporary Asian Pub", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1541544741938-0af808871cc0?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_dubai_ossiano", "name": "Ossiano Underwater Dining", "city": "Dubai", "timezone": "Asia/Dubai", "category": "Underwater Fine Dining", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1544551763-46a013bb70d5?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_dubai_tresind", "name": "Trèsind Studio Gastronomy", "city": "Dubai", "timezone": "Asia/Dubai", "category": "Modern Indian Gastronomy", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1589301760014-d929f3979dbc?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_dubai_nusr", "name": "Nusr-Et Steakhouse Dubai", "city": "Dubai", "timezone": "Asia/Dubai", "category": "Luxury Steakhouse Pub", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1558030006-450675393462?auto=format&fit=crop&w=800&q=80"},

        # ROME (Italy)
        {"id": "r_toscana", "name": "Villa Toscana Cellar", "city": "Rome", "timezone": "Europe/Rome", "category": "Tuscan Trattoria & Wine", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1537047902294-62a40c20a6ae?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_rome_pergola", "name": "La Pergola Rome", "city": "Rome", "timezone": "Europe/Rome", "category": "Panoromic Fine Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1528605248644-14dd04022da1?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_rome_aroma", "name": "Aroma Rooftop Colosseum", "city": "Rome", "timezone": "Europe/Rome", "category": "Colosseum View Lounge", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1552832230-c0197dd311b5?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_rome_imago", "name": "Imàgo Rooftop Bar", "city": "Rome", "timezone": "Europe/Rome", "category": "Hassler Rooftop Bar", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1519671482749-fd09be7ccebf?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_rome_roscioli", "name": "Salumeria Roscioli", "city": "Rome", "timezone": "Europe/Rome", "category": "Historic Italian Bistro", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1481931098730-318b6f776db0?auto=format&fit=crop&w=800&q=80"},

        # SINGAPORE (Singapore)
        {"id": "r_opium", "name": "Opium Night Lounge", "city": "Singapore", "timezone": "Asia/Singapore", "category": "Asian Fusion Lounge", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1470337458703-46ad1756a187?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_sg_mbs", "name": "Marina Bay Sands Grill", "city": "Singapore", "timezone": "Asia/Singapore", "category": "Rooftop SkyPark Bar", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1525625293386-3f8f99389edd?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_sg_odette", "name": "Odette Fine Dining", "city": "Singapore", "timezone": "Asia/Singapore", "category": "Modern French Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1560624052-449f5ddf0c31?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_sg_jumbo", "name": "Jumbo Seafood Bay", "city": "Singapore", "timezone": "Asia/Singapore", "category": "Coastal Seafood & Pub", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1563245372-f21724e3856d?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_sg_atlas", "name": "Atlas Bar & Lounge", "city": "Singapore", "timezone": "Asia/Singapore", "category": "Art Deco Gin Lounge", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1517457373958-b7bdd4587205?auto=format&fit=crop&w=800&q=80"},

        # LOS ANGELES (USA)
        {"id": "r_celestial", "name": "Celestial Rooftop & Hotel", "city": "Los Angeles", "timezone": "America/Los_Angeles", "category": "Rooftop Hotel & Bar", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1507676184212-d03ab07a01bf?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_la_spago", "name": "Spago Beverly Hills", "city": "Los Angeles", "timezone": "America/Los_Angeles", "category": "Beverly Hills Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1466978913421-dad2ebd01d17?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_la_nobu", "name": "Nobu Malibu Beach", "city": "Los Angeles", "timezone": "America/Los_Angeles", "category": "Coastal Japanese Lounge", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1559329007-40df8a9345d8?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_la_republicue", "name": "République Brasserie", "city": "Los Angeles", "timezone": "America/Los_Angeles", "category": "French Brasserie Pub", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1543007630-9710e4a00a20?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_la_providence", "name": "Providence Seafood", "city": "Los Angeles", "timezone": "America/Los_Angeles", "category": "Michelin Seafood", "theme": "tokyo_slate", "bg_image": "https://images.unsplash.com/photo-1510812431401-41d2bd2722f3?auto=format&fit=crop&w=800&q=80"},

        # BERLIN (Germany)
        {"id": "r_anker", "name": "Zum Anker Fine Dining", "city": "Berlin", "timezone": "Europe/Berlin", "category": "German Fine Dining", "theme": "dark_velvet", "bg_image": "/assets/anker.jpg"},
        {"id": "r_berlin_borchardt", "name": "Borchardt Gastronomy", "city": "Berlin", "timezone": "Europe/Berlin", "category": "Classic Berlin Bistro", "theme": "dark_velvet", "bg_image": "https://images.unsplash.com/photo-1484659619207-9165d119dafe?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_berlin_grill", "name": "Grill Royal Spree", "city": "Berlin", "timezone": "Europe/Berlin", "category": "Waterfront Steakhouse", "theme": "rooftop_sky", "bg_image": "https://images.unsplash.com/photo-1549488344-1f9b8d2bd1f3?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_berlin_timraue", "name": "Restaurant Tim Raue", "city": "Berlin", "timezone": "Europe/Berlin", "category": "Asian Inspired Dining", "theme": "mumbai_royal", "bg_image": "https://images.unsplash.com/photo-1569058242253-92a9c755a0ec?auto=format&fit=crop&w=800&q=80"},
        {"id": "r_berlin_facil", "name": "FACIL Garden Restaurant", "city": "Berlin", "timezone": "Europe/Berlin", "category": "Glasshouse Fine Dining", "theme": "parisian_gold", "bg_image": "https://images.unsplash.com/photo-1498654896293-37aacf113fd9?auto=format&fit=crop&w=800&q=80"},
    ]

    restaurants_dict = {}
    for v in venues:
        restaurants_dict[v["id"]] = {
            "id": v["id"],
            "name": v["name"],
            "city": v["city"],
            "timezone": v["timezone"],
            "category": v["category"],
            "theme": v["theme"],
            "bg_image": v["bg_image"],
            "slot_minutes": 30,
            "reservation_duration_minutes": 90,
            "cancellation_cutoff_minutes": 0,
            "opening_hours": default_hours,
            "tables": make_tables(6),
            "manager_user_ids": ["u_ada"],
            "combinable": [],
            "closures": [],
            "revision": 0,
            "policies": [],
        }

    user_guest_id = "u_guest"
    user_ada_id = "u_ada"
    user_bob_id = "u_bob"

    users_dict = {
        user_guest_id: {
            "id": user_guest_id,
            "email": "guest@example.com",
            "password_hash": hash_password("correct horse"),
            "display_name": "Guest User",
        },
        user_ada_id: {
            "id": user_ada_id,
            "email": "ada@example.com",
            "password_hash": hash_password("correct horse"),
            "display_name": "Ada",
        },
        user_bob_id: {
            "id": user_bob_id,
            "email": "bob@example.com",
            "password_hash": hash_password("correct horse"),
            "display_name": "Bob",
        },
    }

    tokens_dict = {
        "guest-token-123456": user_guest_id,
        "token-ada-123456": user_ada_id,
        "token-bob-123456": user_bob_id,
    }

    return ServiceState(
        users=users_dict,
        tokens=tokens_dict,
        restaurants=restaurants_dict,
        reservations={},
        receipts={},
    )


class TablekeeperService:
    """Implements the public Stage 1 contract over a single transactional state."""

    def __init__(self, store: StateStore | None = None) -> None:
        self.store = store if store is not None else StateStore(initial=_default_seed_state())

    async def handle(self, method: str, target: str, headers: dict[str, str], body: Any = None) -> ApiResponse:
        try:
            return await self._dispatch(method.upper(), target, {k.lower(): v for k, v in headers.items()}, _json_shape(body))
        except DomainError as error:
            return _make_error_response(error)
        except RecursionError:
            return _make_error_response(_error(400, "malformed_request", "request body is too deeply nested"))
        except OverflowError:
            return _make_error_response(_invalid("value is outside the supported range"))

    async def _dispatch(
        self, method: str, target: str, headers: dict[str, str], body: Any
    ) -> ApiResponse:
        parsed = urlsplit(target)
        raw_path = parsed.path or "/"
        path = raw_path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if method == "GET" and path == "/health":
            return ApiResponse(200, {"status": "ok"})

        if method == "POST" and path == "/_test/reset":
            fixture = _require_object(body)
            candidate = await asyncio.to_thread(_fixture_state, fixture)
            await self.store.replace(candidate)
            return ApiResponse(204)

        if method == "GET" and path == "/_test/export":
            return ApiResponse(200, await self.store.export())

        if method == "POST" and path == "/_test/import":
            envelope = _require_object(body)
            candidate = self._validated_import_state(envelope)
            await self.store.replace(candidate)
            return ApiResponse(204)

        if method == "GET" and path in ("/", "/index.html"):
            accept = headers.get("accept", "")
            if "text/html" in accept or "application/json" not in accept:
                web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
                index_path = os.path.join(web_dir, "index.html")
                if os.path.isfile(index_path):
                    with open(index_path, "rb") as f:
                        return ApiResponse(200, f.read(), content_type="text/html; charset=utf-8")
            return ApiResponse(200, {"service": "Tablekeeper", "stage": 3, "health": "/health"})

        if method == "GET" and (path.startswith(("/static/", "/assets/")) or path.endswith((".css", ".js", ".jpg", ".jpeg", ".png", ".webp", ".svg", ".woff2", ".ico"))):
            rel_path = path.lstrip("/")
            if rel_path.startswith("static/"):
                rel_path = rel_path[len("static/"):]
            web_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web")
            file_path = os.path.abspath(os.path.join(web_dir, rel_path))
            if file_path.startswith(web_dir) and os.path.isfile(file_path):
                content_type = self._guess_content_type(file_path)
                with open(file_path, "rb") as f:
                    return ApiResponse(200, f.read(), content_type=content_type)

        if method == "POST" and path in ("/auth/signup", "/auth/login"):
            payload = _require_object(body)
            if path.endswith("signup"):
                return await self._signup(payload)
            return await self._login(payload)

        if method == "GET" and path == "/restaurants":
            state = await self.store.snapshot()
            return ApiResponse(
                200,
                {
                    "restaurants": [
                        {key: restaurant[key] for key in ("id", "name", "timezone")}
                        for restaurant in state.restaurants.values()
                    ]
                },
            )

        policy_match = re.fullmatch(r"/restaurants/([^/]+)/policies", path)
        if policy_match:
            restaurant_id = unquote(policy_match.group(1))
            if not restaurant_id or len(restaurant_id) > 64:
                raise _invalid("restaurant id must contain 1 to 64 characters")
            if method == "GET":
                return await self._get_policies(restaurant_id)
            if method == "POST":
                payload = _require_object(body)
                user_id = await self._authenticated_user(headers)
                key = _validate_idempotency_key(headers)
                return await self._publish_policy(restaurant_id, user_id, payload, key, path)
            raise _not_found()

        replans_apply_match = re.fullmatch(r"/restaurants/([^/]+)/replans/([^/]+)/apply", path)
        if replans_apply_match:
            restaurant_id = unquote(replans_apply_match.group(1))
            plan_id = unquote(replans_apply_match.group(2))
            if not restaurant_id or len(restaurant_id) > 64:
                raise _invalid("restaurant id must contain 1 to 64 characters")
            if method == "POST":
                payload = _require_object(body)
                user_id = await self._authenticated_user(headers)
                key = _validate_idempotency_key(headers)
                return await self._apply_replan(restaurant_id, plan_id, user_id, payload, key, path)
            raise _not_found()

        replans_match = re.fullmatch(r"/restaurants/([^/]+)/replans", path)
        if replans_match:
            restaurant_id = unquote(replans_match.group(1))
            if not restaurant_id or len(restaurant_id) > 64:
                raise _invalid("restaurant id must contain 1 to 64 characters")
            if method == "POST":
                payload = _require_object(body)
                user_id = await self._authenticated_user(headers)
                key = _validate_idempotency_key(headers)
                return await self._create_replan(restaurant_id, user_id, payload, key, path)
            raise _not_found()

        restaurant_match = re.fullmatch(r"/restaurants/([^/]+)", path)
        if restaurant_match:
            restaurant_id = unquote(restaurant_match.group(1))
            if not restaurant_id or len(restaurant_id) > 64:
                raise _invalid("restaurant id must contain 1 to 64 characters")
            if method == "GET":
                state = await self.store.snapshot()
                restaurant = state.restaurants.get(restaurant_id)
                if restaurant is None:
                    raise _not_found()
                result = copy.deepcopy(restaurant)
                result.pop("policies", None)
                return ApiResponse(200, result)
            raise _not_found()

        if method == "GET" and path == "/availability":
            return await self._availability(query)

        if method == "POST" and path == "/reservations":
            payload = _require_object(body)
            user_id = await self._authenticated_user(headers)
            key = _validate_idempotency_key(headers)
            return await self._create_reservation(user_id, payload, key)

        if method == "POST" and path == "/reservation-moves":
            payload = _require_object(body)
            user_id = await self._authenticated_user(headers)
            key = _validate_idempotency_key(headers)
            return await self._move_reservations(user_id, payload, key)

        if method == "POST" and path == "/series":
            payload = _require_object(body)
            user_id = await self._authenticated_user(headers)
            key = _validate_idempotency_key(headers)
            return await self._create_series(user_id, payload, key)

        series_amend_match = re.fullmatch(r"/series/([^/]+)/amend", path)
        if series_amend_match:
            series_id = unquote(series_amend_match.group(1))
            if not series_id or len(series_id) > 64:
                raise _invalid("series id must contain 1 to 64 characters")
            if method == "POST":
                payload = _require_object(body)
                user_id = await self._authenticated_user(headers)
                key = _validate_idempotency_key(headers)
                return await self._amend_series(series_id, user_id, payload, key, path)
            raise _not_found()

        series_match = re.fullmatch(r"/series/([^/]+)", path)
        if series_match:
            series_id = unquote(series_match.group(1))
            if method == "GET":
                return await self._get_series(series_id, headers)
            raise _not_found()

        if method == "GET" and path == "/reservations":
            user_id = await self._authenticated_user(headers)
            state = await self.store.snapshot()
            rows = [
                _serialize_reservation(r)
                for r in state.reservations.values()
                if r["user_id"] == user_id
            ]
            rows.sort(key=lambda r: _instant(_aware(r["starts_at"])), reverse=True)
            return ApiResponse(200, {"reservations": rows})

        match = re.fullmatch(r"/reservations/([^/]+)(/cancel|/decision|/history)?", path)
        if match:
            reference = unquote(match.group(1))
            subpath = match.group(2)
            if subpath == "/decision":
                if method == "GET":
                    return await self._reservation_decision(reference, headers)
                raise _not_found()
            if subpath == "/history":
                if method == "GET":
                    return await self._reservation_history(reference, headers)
                raise _not_found()
            if subpath == "/cancel":
                if method == "POST":
                    user_id = await self._authenticated_user(headers)
                    return await self._cancel_reservation(reference, user_id)
                raise _not_found()
            if subpath is None:
                user_id = await self._authenticated_user(headers)
                if method == "GET":
                    state = await self.store.snapshot()
                    record = state.reservations.get(reference)
                    if record is None or record["user_id"] != user_id:
                        raise _not_found()
                    return ApiResponse(200, _serialize_reservation(record))
                if method == "PATCH":
                    payload = _require_object(body)
                    return await self._patch_reservation(reference, user_id, payload)
                raise _not_found()

        raise _not_found()

    def _guess_content_type(self, path: str) -> str:
        if path.endswith(".html"):
            return "text/html; charset=utf-8"
        if path.endswith(".css"):
            return "text/css; charset=utf-8"
        if path.endswith(".js"):
            return "application/javascript; charset=utf-8"
        if path.endswith((".jpg", ".jpeg")):
            return "image/jpeg"
        if path.endswith(".png"):
            return "image/png"
        if path.endswith(".webp"):
            return "image/webp"
        if path.endswith(".svg"):
            return "image/svg+xml"
        if path.endswith(".woff2"):
            return "font/woff2"
        return "application/octet-stream"

    async def _authenticated_user(self, headers: dict[str, str]) -> str:
        token = _bearer(headers)
        state = await self.store.snapshot()
        user_id = state.tokens.get(token)
        if user_id is None or user_id not in state.users:
            raise _error(401, "unauthenticated", "unknown bearer token")
        return user_id

    async def _optional_authenticated_user(self, headers: dict[str, str]) -> str | None:
        authorization = headers.get("authorization", "")
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            return None
        token = parts[1]
        state = await self.store.snapshot()
        user_id = state.tokens.get(token)
        if user_id is None or user_id not in state.users:
            return None
        return user_id

    def _validated_import_state(self, envelope: dict[str, Any]) -> ServiceState:
        if set(envelope) != {"track", "format_version", "state"}:
            raise _invalid("invalid export envelope")
        if envelope["track"] != "tablekeeper" or envelope["format_version"] != 1:
            raise _invalid("unsupported export envelope")
        try:
            candidate = ServiceState.from_dict(envelope["state"])

            seen_email_addresses: set[str] = set()
            for user_id, user in candidate.users.items():
                if not isinstance(user_id, str) or not 1 <= len(user_id) <= 64 or not isinstance(user, dict):
                    raise _invalid("invalid user state")
                if set(user) != {"id", "email", "password_hash", "display_name"}:
                    raise _invalid("invalid user state")
                if (
                    user["id"] != user_id
                    or not isinstance(user["email"], str)
                    or not isinstance(user["password_hash"], str)
                    or not isinstance(user["display_name"], str)
                ):
                    raise _invalid("invalid user state")
                email_key = user["email"].casefold()
                if email_key in seen_email_addresses:
                    raise _invalid("duplicate email in user state")
                seen_email_addresses.add(email_key)
                if not is_valid_password_hash(user["password_hash"]):
                    raise _invalid("invalid password hash in state")

            if any(
                not isinstance(token, str) or not token or not isinstance(user_id, str) or user_id not in candidate.users
                for token, user_id in candidate.tokens.items()
            ):
                raise _invalid("invalid token state")

            # Ensure manager_user_ids, combinable, closures, revision, and policies are normalized on imported restaurants
            for rid, rest in candidate.restaurants.items():
                if not isinstance(rest, dict):
                    raise _invalid("invalid restaurant state")
                if "manager_user_ids" not in rest:
                    rest["manager_user_ids"] = []
                if "policies" not in rest:
                    rest["policies"] = []
                if "combinable" not in rest:
                    rest["combinable"] = []
                if "closures" not in rest:
                    rest["closures"] = []
                if "revision" not in rest:
                    rest["revision"] = 0
                for m in rest["manager_user_ids"]:
                    if m not in candidate.users:
                        raise _invalid("manager user does not exist in state")

            # Reuse the reset-fixture validator for restaurant base configuration, without
            # rehashing accounts or mutating the imported snapshot.
            base_restaurants = [
                {k: v for k, v in r.items() if k not in ("policies", "closures", "revision")}
                for r in candidate.restaurants.values()
            ]
            normalized_restaurants = _fixture_state(
                {"users": [], "restaurants": base_restaurants}
            ).restaurants
            for rid, rest in candidate.restaurants.items():
                norm = normalized_restaurants.get(rid)
                if norm is None:
                    raise _invalid("invalid restaurant state")
                base = {k: v for k, v in rest.items() if k not in ("policies", "closures", "revision")}
                norm_base = {k: v for k, v in norm.items() if k not in ("policies", "closures", "revision")}
                if base != norm_base:
                    raise _invalid("invalid restaurant state")
                policies = rest.get("policies", [])
                if not isinstance(policies, list):
                    raise _invalid("invalid restaurant policies state")
                for expected_ver, p in enumerate(policies, start=1):
                    if not isinstance(p, dict) or p.get("policy_version") != expected_ver:
                        raise _invalid("invalid policy version in restaurant state")
                    validated_p = _validate_policy_payload(norm, p)
                    for k, v in validated_p.items():
                        if p.get(k) != v:
                            raise _invalid("invalid policy field in restaurant state")

            base_reservation_fields = {
                "reservation_id",
                "reference",
                "user_id",
                "restaurant_id",
                "party_size",
                "status",
                "starts_at_local",
                "starts_at",
                "ends_at",
                "created_at",
            }
            allowed_reservation_fields = base_reservation_fields | {
                "table_id",
                "table_ids",
                "revision",
                "accepted_terms",
                "history",
                "series_id",
                "series_index",
                "is_exception",
            }
            seen_reservation_ids: set[str] = set()
            for reference, record in candidate.reservations.items():
                if not isinstance(reference, str) or not REFERENCE_RE.fullmatch(reference) or not isinstance(record, dict):
                    raise _invalid("invalid reservation state")
                has_tbl = ("table_id" in record) or ("table_ids" in record)
                if not has_tbl or not (base_reservation_fields.issubset(set(record)) and set(record).issubset(allowed_reservation_fields)) or record["reference"] != reference:
                    raise _invalid("invalid reservation state")
                if (
                    not isinstance(record["reservation_id"], str)
                    or not 1 <= len(record["reservation_id"]) <= 64
                    or record["user_id"] not in candidate.users
                    or record["restaurant_id"] not in candidate.restaurants
                    or record["status"] not in ("confirmed", "cancelled")
                ):
                    raise _invalid("invalid reservation state")
                if record["reservation_id"] in seen_reservation_ids:
                    raise _invalid("duplicate reservation id in state")
                seen_reservation_ids.add(record["reservation_id"])
                _aware(record["starts_at"])
                _aware(record["ends_at"])
                _aware(record["created_at"])

                if "table_ids" not in record and "table_id" in record:
                    record["table_ids"] = [record["table_id"]]
                if "table_ids" in record:
                    if len(record["table_ids"]) == 1:
                        record["table_id"] = record["table_ids"][0]
                    else:
                        record.pop("table_id", None)

                restaurant = candidate.restaurants[record["restaurant_id"]]
                if "revision" not in record:
                    record["revision"] = 1
                if "accepted_terms" not in record:
                    record["accepted_terms"] = extract_accepted_terms(get_policy_0(restaurant))
                if "history" not in record:
                    terms = record["accepted_terms"]
                    t_ids = record.get("table_ids") or [record["table_id"]]
                    change_field = "table_ids" if len(t_ids) > 1 else "table_id"
                    change_val = list(t_ids) if len(t_ids) > 1 else t_ids[0]
                    hist = [
                        {
                            "seq": 1,
                            "at": record["created_at"],
                            "event": "created",
                            "revision": 1,
                            "accepted_terms": copy.deepcopy(terms),
                            "changes": [
                                {"field": change_field, "from": None, "to": change_val},
                                {"field": "starts_at_local", "from": None, "to": record["starts_at_local"]},
                                {"field": "party_size", "from": None, "to": record["party_size"]},
                            ],
                        }
                    ]
                    if record["status"] == "cancelled":
                        record["revision"] = 2
                        hist.append({
                            "seq": 2,
                            "at": record["created_at"],
                            "event": "cancelled",
                            "revision": 2,
                            "accepted_terms": copy.deepcopy(terms),
                            "changes": [],
                        })
                    record["history"] = hist

                naive = _parse_local(record["starts_at_local"])
                pol = get_effective_policy(restaurant, naive.date())
                exp_start, _ = _resolve_booking_time(restaurant, record["starts_at_local"], policy=pol)
                exp_end = _instant(exp_start) + timedelta(minutes=pol["reservation_duration_minutes"])
                exp_end_local = exp_end.astimezone(ZoneInfo(restaurant["timezone"]))
                if (
                    record["starts_at"] != rfc3339(exp_start)
                    or record["ends_at"] != rfc3339(exp_end_local)
                ):
                    raise _invalid("reservation timestamps do not match its booking")

            confirmed = [
                record
                for record in candidate.reservations.values()
                if record["status"] == "confirmed"
            ]
            for index, first in enumerate(confirmed):
                first_tables = set(first.get("table_ids") or [first["table_id"]])
                for second in confirmed[index + 1 :]:
                    second_tables = set(second.get("table_ids") or [second["table_id"]])
                    if (
                        first["restaurant_id"] == second["restaurant_id"]
                        and (first_tables & second_tables)
                        and _overlap(
                            _aware(first["starts_at"]),
                            _record_end(first),
                            _aware(second["starts_at"]),
                            _record_end(second),
                        )
                    ):
                        raise _invalid("overlapping confirmed reservations in state")

            for series_id, s in candidate.series.items():
                if not isinstance(series_id, str) or not isinstance(s, dict):
                    raise _invalid("invalid series state")
                if s.get("series_id") != series_id:
                    raise _invalid("invalid series id in state")
                if s.get("user_id") not in candidate.users:
                    raise _invalid("series user does not exist in state")
                if s.get("restaurant_id") not in candidate.restaurants:
                    raise _invalid("series restaurant does not exist in state")
                if isinstance(s.get("revision"), bool) or not isinstance(s.get("revision"), int) or s["revision"] < 1:
                    raise _invalid("invalid series revision")
                if isinstance(s.get("interval_weeks"), bool) or not isinstance(s.get("interval_weeks"), int) or not (1 <= s["interval_weeks"] <= 4):
                    raise _invalid("invalid series interval_weeks")
                if not isinstance(s.get("occurrences"), list):
                    raise _invalid("invalid series occurrences")
                for occ in s["occurrences"]:
                    if not isinstance(occ, dict) or "index" not in occ or "reference" not in occ:
                        raise _invalid("invalid occurrence in series")
                    if occ["reference"] not in candidate.reservations:
                        raise _invalid("occurrence reservation reference not found")

            for receipt in candidate.receipts.values():
                valid_path = (
                    receipt.path in ("/reservations", "/reservation-moves", "/series")
                    or bool(re.fullmatch(r"/restaurants/[^/]+/policies", receipt.path))
                    or bool(re.fullmatch(r"/restaurants/[^/]+/replans", receipt.path))
                    or bool(re.fullmatch(r"/restaurants/[^/]+/replans/[^/]+/apply", receipt.path))
                    or bool(re.fullmatch(r"/series/[^/]+/amend", receipt.path))
                )
                if (
                    receipt.user_id not in candidate.users
                    or not 1 <= len(receipt.key) <= 255
                    or receipt.method != "POST"
                    or not valid_path
                    or receipt.status != 201
                ):
                    raise _invalid("invalid idempotency receipt")
                body = json.loads(receipt.request_json)
                if not isinstance(body, dict) or canonical_json(body) != receipt.request_json:
                    raise _invalid("invalid idempotency request body")
        except DomainError as exc:
            if exc.status == 422 and exc.code == "validation_failed":
                raise
            raise _invalid("invalid imported state") from exc
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise _invalid("invalid imported state") from exc
        return candidate

    async def _get_policies(self, restaurant_id: str) -> ApiResponse:
        state = await self.store.snapshot()
        restaurant = state.restaurants.get(restaurant_id)
        if restaurant is None:
            raise _not_found()
        return ApiResponse(200, {"policies": copy.deepcopy(restaurant.get("policies", []))})

    async def _publish_policy(
        self,
        restaurant_id: str,
        user_id: str,
        payload: dict[str, Any],
        key: str,
        path: str,
    ) -> ApiResponse:
        state = await self.store.snapshot()
        restaurant = state.restaurants.get(restaurant_id)
        if restaurant is None:
            raise _not_found()
        if user_id not in restaurant.get("manager_user_ids", []):
            raise DomainError(403, "forbidden", "forbidden")

        validated = _validate_policy_payload(restaurant, payload)

        def mutation(current: ServiceState) -> tuple[int, dict[str, Any]]:
            cur_rest = current.restaurants.get(restaurant_id)
            if cur_rest is None:
                raise _not_found()
            if user_id not in cur_rest.get("manager_user_ids", []):
                raise DomainError(403, "forbidden", "forbidden")

            policies = cur_rest.setdefault("policies", [])
            version = len(policies) + 1
            record = {"policy_version": version, **validated}
            policies.append(copy.deepcopy(record))
            cur_rest["revision"] = cur_rest.get("revision", 0) + 1
            return 201, record

        status, response_body, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path=path,
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response_body)

    async def _create_replan(
        self,
        restaurant_id: str,
        user_id: str,
        payload: dict[str, Any],
        key: str,
        path: str,
    ) -> ApiResponse:
        state = await self.store.snapshot()
        restaurant = state.restaurants.get(restaurant_id)
        if restaurant is None:
            raise _not_found()
        if user_id not in restaurant.get("manager_user_ids", []):
            raise DomainError(403, "forbidden", "forbidden")

        closure_table_id = payload.get("table_id")
        from_raw = payload.get("from")
        to_raw = payload.get("to")
        if not isinstance(closure_table_id, str) or not isinstance(from_raw, str) or not isinstance(to_raw, str):
            raise _invalid("table_id, from, and to are required")

        if not any(t["id"] == closure_table_id for t in restaurant["tables"]):
            raise _not_found()

        try:
            from_dt = datetime.fromisoformat(from_raw)
            to_dt = datetime.fromisoformat(to_raw)
        except Exception as exc:
            raise _invalid("from and to must be valid ISO timestamps") from exc

        if from_dt.tzinfo is None or to_dt.tzinfo is None:
            raise _invalid("from and to must have explicit timezone offsets")
        if from_dt >= to_dt:
            raise _invalid("from must be earlier than to")

        async def mutation(current: ServiceState) -> tuple[int, dict[str, Any]]:
            cur_rest = current.restaurants.get(restaurant_id)
            if cur_rest is None:
                raise _not_found()
            if user_id not in cur_rest.get("manager_user_ids", []):
                raise DomainError(403, "forbidden", "forbidden")

            plan = _compute_replan(cur_rest, closure_table_id, from_dt, to_dt, from_raw, to_raw, current)
            current.plans[plan["plan_id"]] = plan

            preview_resp = {
                "plan_id": plan["plan_id"],
                "restaurant_revision": cur_rest.get("revision", 0),
                "closure": copy.deepcopy(plan["closure"]),
                "assignments": copy.deepcopy(plan["assignments"]),
                "moved_count": plan["moved_count"],
                "unused_seats": plan["unused_seats"],
            }
            return 201, preview_resp

        status, response_body, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path=path,
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response_body)

    async def _apply_replan(
        self,
        restaurant_id: str,
        plan_id: str,
        user_id: str,
        payload: dict[str, Any],
        key: str,
        path: str,
    ) -> ApiResponse:
        async def mutation(current: ServiceState) -> tuple[int, dict[str, Any]]:
            cur_rest = current.restaurants.get(restaurant_id)
            if cur_rest is None:
                raise _not_found()
            if user_id not in cur_rest.get("manager_user_ids", []):
                raise DomainError(403, "forbidden", "forbidden")

            plan = current.plans.get(plan_id)
            if plan is None or plan.get("restaurant_id") != restaurant_id:
                raise _not_found()

            if cur_rest.get("revision", 0) != plan["restaurant_revision"]:
                raise DomainError(409, "stale_plan", "intervening restaurant revision")

            if plan.get("applied") is True:
                raise DomainError(409, "plan_already_applied", "plan already applied")

            cur_rest.setdefault("closures", []).append(copy.deepcopy(plan["closure"]))
            affected_series_ids: set[str] = set()
            now_ts = rfc3339(datetime.now(UTC))

            for assignment in plan["assignments"]:
                ref = assignment["reference"]
                rec = current.reservations[ref]
                new_tables = list(assignment["table_ids"])
                if assignment["changed"]:
                    old_tables = rec.get("table_ids") or ([rec["table_id"]] if "table_id" in rec else [])
                    rec["table_ids"] = list(new_tables)
                    if len(new_tables) == 1:
                        rec["table_id"] = new_tables[0]
                    else:
                        rec.pop("table_id", None)
                    rec["revision"] = rec.get("revision", 1) + 1

                    hist = rec.setdefault("history", [])
                    hist.append({
                        "seq": len(hist) + 1,
                        "at": now_ts,
                        "event": "reassigned",
                        "revision": rec["revision"],
                        "plan_id": plan_id,
                        "accepted_terms": copy.deepcopy(rec.get("accepted_terms", {})),
                        "changes": [{"field": "table_ids", "from": old_tables, "to": list(new_tables)}],
                    })
                    if rec.get("series_id"):
                        affected_series_ids.add(rec["series_id"])

            for sid in affected_series_ids:
                if sid in current.series:
                    current.series[sid]["revision"] = current.series[sid].get("revision", 1) + 1

            cur_rest["revision"] = cur_rest.get("revision", 0) + 1
            plan["applied"] = True

            reservations_out = [
                _serialize_reservation(current.reservations[item["reference"]])
                for item in plan["assignments"]
            ]

            response_body = {
                "plan_id": plan_id,
                "restaurant_revision": cur_rest["revision"],
                "reservations": reservations_out,
            }
            return 201, response_body

        status, response_body, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path=path,
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response_body)

    async def _signup(self, payload: dict[str, Any]) -> ApiResponse:
        email = _required_string(payload, "email")
        password = _required_string(payload, "password")
        display_name = _required_string(payload, "display_name")
        if not EMAIL_RE.fullmatch(email):
            raise _invalid("email must be of the form local@domain")
        if len(password) < 8:
            raise _invalid("password must be at least 8 characters")
        token = issue_token()
        password_hash = await asyncio.to_thread(hash_password, password)

        def mutation(state: ServiceState) -> dict[str, Any]:
            email_key = email.casefold()
            if any(user["email"].casefold() == email_key for user in state.users.values()):
                raise _error(409, "email_taken", "email is already registered")
            user_id = "u_" + uuid.uuid4().hex
            state.users[user_id] = {
                "id": user_id,
                "email": email,
                "password_hash": password_hash,
                "display_name": display_name,
            }
            state.tokens[token] = user_id
            return {"user_id": user_id, "display_name": display_name, "token": token}

        response = await self.store.transaction(mutation)
        return ApiResponse(201, response)

    async def _login(self, payload: dict[str, Any]) -> ApiResponse:
        email = _required_string(payload, "email")
        password = _required_string(payload, "password")
        state = await self.store.snapshot()
        user = next((candidate for candidate in state.users.values() if candidate["email"].casefold() == email.casefold()), None)
        if user is None or not await asyncio.to_thread(verify_password, password, user["password_hash"]):
            raise _error(401, "unauthenticated", "email or password is incorrect")
        token = issue_token()
        user_id = user["id"]

        def mutation(candidate: ServiceState) -> None:
            current = candidate.users.get(user_id)
            if current is None or current["password_hash"] != user["password_hash"]:
                raise _error(401, "unauthenticated", "email or password is incorrect")
            candidate.tokens[token] = user_id

        await self.store.transaction(mutation)
        return ApiResponse(200, {"user_id": user_id, "display_name": user["display_name"], "token": token})

    async def _availability(self, query: dict[str, list[str]]) -> ApiResponse:
        restaurant_id = _query_one(query, "restaurant_id")
        if len(restaurant_id) > 64:
            raise _invalid("restaurant_id must be at most 64 characters")
        date_value = _query_one(query, "date")
        party_text = _query_one(query, "party_size")
        if not DECIMAL_RE.fullmatch(party_text):
            raise _invalid("party_size must be plain decimal digits")
        party_size_digits = party_text.lstrip("0") or "0"
        if party_size_digits == "0":
            raise _invalid("party_size must be a positive integer")

        def party_size_fits(cap_val: int) -> bool:
            cap_str = str(cap_val)
            if len(party_size_digits) > len(cap_str):
                return False
            if len(party_size_digits) == len(cap_str) and party_size_digits > cap_str:
                return False
            return True

        local_date = _strict_date(date_value)
        explain_values = query.get("explain")
        explain_mode = False
        if explain_values is not None:
            if len(explain_values) != 1 or explain_values[0] != "true":
                raise _invalid("explain parameter must be 'true'")
            explain_mode = True

        state = await self.store.snapshot()
        restaurant = state.restaurants.get(restaurant_id)
        if restaurant is None:
            raise _not_found()
        policy = get_effective_policy(restaurant, local_date)
        opening = _opening_for(policy, local_date)
        slots = []
        if opening is not None:
            opens = time.fromisoformat(opening["opens"])
            closes = time.fromisoformat(opening["closes"])
            open_minutes = opens.hour * 60 + opens.minute
            close_minutes = closes.hour * 60 + closes.minute
            close_instant = _closing_instant(local_date, opening["closes"], restaurant["timezone"])
            minute = open_minutes
            while minute < close_minutes:
                naive = datetime.combine(local_date, time(minute // 60, minute % 60))
                local_value = naive.strftime("%Y-%m-%dT%H:%M")
                try:
                    start = resolve_local(local_value, restaurant["timezone"])
                except DomainError:
                    minute += policy["slot_minutes"]
                    continue
                start_instant = _instant(start)
                duration_seconds = policy["reservation_duration_minutes"] * 60
                if duration_seconds <= (close_instant - start_instant).total_seconds():
                    end = start_instant + timedelta(minutes=policy["reservation_duration_minutes"])
                    available = []
                    available_options = []
                    explain_entries = []
                    table_cap_map = {t["id"]: t["capacity"] for t in restaurant["tables"]}
                    for table in restaurant["tables"]:
                        tid = table["id"]
                        t_cap = policy["capacities"].get(tid, table["capacity"])
                        holds_cap = party_size_fits(t_cap)
                        holds_no_overlap = not _has_conflict(
                            state,
                            restaurant_id,
                            tid,
                            start,
                            end,
                        )
                        is_avail = holds_cap and holds_no_overlap
                        if is_avail:
                            available.append(tid)
                            available_options.append({"table_ids": [tid], "capacity": t_cap})
                        if explain_mode:
                            explain_entries.append({
                                "table_id": tid,
                                "policy_version": policy["policy_version"],
                                "available": is_avail,
                                "rules": [
                                    {"rule": "capacity", "holds": holds_cap},
                                    {"rule": "no_overlap", "holds": holds_no_overlap},
                                ],
                            })
                    for pair in restaurant.get("combinable", []):
                        p1, p2 = pair[0], pair[1]
                        cap1 = policy["capacities"].get(p1, table_cap_map.get(p1, 0))
                        cap2 = policy["capacities"].get(p2, table_cap_map.get(p2, 0))
                        pair_cap = cap1 + cap2
                        if party_size_fits(pair_cap):
                            if not _has_conflict(state, restaurant_id, list(pair), start, end):
                                available_options.append({"table_ids": list(pair), "capacity": pair_cap})
                    slot_data = {
                        "starts_at_local": local_value,
                        "starts_at": rfc3339(start),
                        "available_table_ids": available,
                        "available_options": available_options,
                    }
                    if explain_mode:
                        slot_data["explain"] = explain_entries
                    slots.append(slot_data)
                minute += policy["slot_minutes"]
        return ApiResponse(
            200,
            {
                "restaurant_id": restaurant_id,
                "date": local_date.isoformat(),
                "timezone": restaurant["timezone"],
                "slots": slots,
            },
        )

    async def _create_reservation(self, user_id: str, payload: dict[str, Any], key: str) -> ApiResponse:
        async def mutation(state: ServiceState) -> tuple[int, dict[str, Any]]:
            record = _new_reservation(state, user_id, payload)
            state.reservations[record["reference"]] = record
            restaurant_id = record["restaurant_id"]
            if restaurant_id in state.restaurants:
                state.restaurants[restaurant_id]["revision"] = state.restaurants[restaurant_id].get("revision", 0) + 1
            return 201, _serialize_reservation(record)

        status, response, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path="/reservations",
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response)

    def _owned_reservation(self, state: ServiceState, reference: str, user_id: str) -> dict[str, Any]:
        record = state.reservations.get(reference)
        if record is None or record["user_id"] != user_id:
            raise _not_found()
        return record

    def _check_cutoff(self, state: ServiceState, record: dict[str, Any]) -> None:
        starts_at = _instant(_aware(record["starts_at"]))
        now = datetime.now(UTC)
        if starts_at <= now:
            raise _error(409, "cutoff_passed", "cancellation cutoff has passed")
        cutoff_minutes = record.get("accepted_terms", {}).get("cancellation_cutoff_minutes")
        if cutoff_minutes is None:
            restaurant = state.restaurants.get(record["restaurant_id"])
            cutoff_minutes = restaurant["cancellation_cutoff_minutes"] if restaurant else 0
        if (starts_at - now).total_seconds() <= cutoff_minutes * 60:
            raise _error(409, "cutoff_passed", "cancellation cutoff has passed")

    async def _cancel_reservation(self, reference: str, user_id: str) -> ApiResponse:
        def mutation(state: ServiceState) -> dict[str, Any]:
            record = self._owned_reservation(state, reference, user_id)
            if record["status"] == "cancelled":
                return _serialize_reservation(record)
            self._check_cutoff(state, record)
            record["status"] = "cancelled"
            record["revision"] = record.get("revision", 1) + 1
            now_ts = rfc3339(datetime.now(UTC))
            history = record.setdefault("history", [])
            history.append({
                "seq": len(history) + 1,
                "at": now_ts,
                "event": "cancelled",
                "revision": record["revision"],
                "accepted_terms": copy.deepcopy(record.get("accepted_terms", {})),
                "changes": [],
            })
            if record.get("series_id"):
                sid = record["series_id"]
                if sid in state.series:
                    state.series[sid]["revision"] = state.series[sid].get("revision", 1) + 1
            rest_id = record["restaurant_id"]
            if rest_id in state.restaurants:
                state.restaurants[rest_id]["revision"] = state.restaurants[rest_id].get("revision", 0) + 1
            return _serialize_reservation(record)

        result = await self.store.transaction(mutation)
        return ApiResponse(200, result)

    def _amended_record(
        self,
        state: ServiceState,
        record: dict[str, Any],
        changes: dict[str, Any],
        *,
        ignore_references: set[str] | None = None,
        check_occupancy: bool = True,
    ) -> dict[str, Any]:
        restaurant_id = record["restaurant_id"]
        restaurant = state.restaurants.get(restaurant_id)
        if restaurant is None:
            raise _not_found()

        current_table_ids = record.get("table_ids") or ([record["table_id"]] if "table_id" in record else [])

        if "table_id" in changes and "table_ids" in changes:
            raise _error(422, "validation_failed", "cannot provide both table_id and table_ids")

        if "table_id" in changes or "table_ids" in changes:
            proposed_table_ids = _normalize_table_selection(restaurant, changes)
        else:
            proposed_table_ids = list(current_table_ids)

        proposed_starts = changes.get("starts_at_local", record["starts_at_local"])
        proposed_party = _party_size(changes) if "party_size" in changes else record["party_size"]

        naive = _parse_local(proposed_starts)
        policy = get_effective_policy(restaurant, naive.date())
        capacity = _table_selection_capacity(restaurant, policy, proposed_table_ids)
        if proposed_party > capacity:
            raise _error(422, "party_exceeds_capacity", "party size exceeds table capacity")

        start, local_string = _resolve_booking_time(restaurant, proposed_starts, policy=policy)
        end = _instant(start) + timedelta(minutes=policy["reservation_duration_minutes"])
        end_local = end.astimezone(ZoneInfo(restaurant["timezone"]))

        if check_occupancy and _has_conflict(
            state,
            restaurant_id,
            proposed_table_ids,
            start,
            end,
            ignore_references=ignore_references,
        ):
            raise _error(409, "table_unavailable", "table is unavailable")

        changes_list = []
        if proposed_table_ids != current_table_ids:
            if len(current_table_ids) > 1 or len(proposed_table_ids) > 1:
                changes_list.append({"field": "table_ids", "from": current_table_ids, "to": proposed_table_ids})
            else:
                changes_list.append({"field": "table_id", "from": current_table_ids[0], "to": proposed_table_ids[0]})
        if local_string != record["starts_at_local"]:
            changes_list.append({"field": "starts_at_local", "from": record["starts_at_local"], "to": local_string})
        if proposed_party != record["party_size"]:
            changes_list.append({"field": "party_size", "from": record["party_size"], "to": proposed_party})

        new_terms = extract_accepted_terms(policy)
        new_rev = record.get("revision", 1) + 1
        now_ts = rfc3339(datetime.now(UTC))

        updated = copy.deepcopy(record)
        updated.update(
            {
                "table_ids": list(proposed_table_ids),
                "party_size": proposed_party,
                "starts_at_local": local_string,
                "starts_at": rfc3339(start),
                "ends_at": rfc3339(end_local),
                "accepted_terms": new_terms,
                "revision": new_rev,
            }
        )
        if len(proposed_table_ids) == 1:
            updated["table_id"] = proposed_table_ids[0]
        else:
            updated.pop("table_id", None)

        history = updated.setdefault("history", [])
        history.append({
            "seq": len(history) + 1,
            "at": now_ts,
            "event": "changed",
            "revision": new_rev,
            "accepted_terms": copy.deepcopy(new_terms),
            "changes": changes_list,
        })
        return updated

    async def _patch_reservation(
        self, reference: str, user_id: str, payload: dict[str, Any]
    ) -> ApiResponse:
        def mutation(state: ServiceState) -> dict[str, Any]:
            current = self._owned_reservation(state, reference, user_id)
            if current["status"] == "cancelled":
                raise _error(409, "reservation_cancelled", "reservation is cancelled")

            if "expected_revision" in payload:
                exp_rev = payload["expected_revision"]
                if isinstance(exp_rev, bool) or not isinstance(exp_rev, int) or exp_rev <= 0:
                    raise _invalid("expected_revision must be a positive integer")
                if exp_rev != current.get("revision", 1):
                    raise _error(409, "stale_revision", "revision does not match expected_revision")

            self._check_cutoff(state, current)

            current_table_ids = current.get("table_ids") or ([current["table_id"]] if "table_id" in current else [])
            if "table_id" in payload and "table_ids" in payload:
                raise _error(422, "validation_failed", "cannot provide both table_id and table_ids")
            if "table_id" in payload or "table_ids" in payload:
                restaurant = state.restaurants.get(current["restaurant_id"])
                if restaurant is None:
                    raise _not_found()
                proposed_table_ids = _normalize_table_selection(restaurant, payload)
            else:
                proposed_table_ids = list(current_table_ids)

            proposed_starts = payload.get("starts_at_local", current["starts_at_local"])
            proposed_party = payload.get("party_size", current["party_size"])

            if "party_size" in payload:
                _party_size(payload)
            if "starts_at_local" in payload:
                _parse_local(payload["starts_at_local"])

            if (
                proposed_table_ids == current_table_ids
                and proposed_starts == current["starts_at_local"]
                and proposed_party == current["party_size"]
            ):
                return _serialize_reservation(current)

            updated = self._amended_record(state, current, payload, ignore_references={reference})
            if updated.get("series_id"):
                sid = updated["series_id"]
                if sid in state.series:
                    state.series[sid]["revision"] = state.series[sid].get("revision", 1) + 1
                    for occ in state.series[sid].get("occurrences", []):
                        if occ["reference"] == reference:
                            occ["exception"] = True
                    updated["is_exception"] = True

            rest_id = current["restaurant_id"]
            if rest_id in state.restaurants:
                state.restaurants[rest_id]["revision"] = state.restaurants[rest_id].get("revision", 0) + 1

            state.reservations[reference] = updated
            return _serialize_reservation(updated)

        return ApiResponse(200, await self.store.transaction(mutation))

    async def _move_reservations(
        self, user_id: str, payload: dict[str, Any], key: str
    ) -> ApiResponse:
        async def mutation(state: ServiceState) -> tuple[int, dict[str, Any]]:
            moves = payload.get("moves")
            if not isinstance(moves, list) or not 1 <= len(moves) <= 8:
                raise _invalid("moves must contain 1 to 8 items")
            seen: set[str] = set()
            references: list[str] = []
            for item in moves:
                if not isinstance(item, dict):
                    raise _invalid("each move must be an object")
                reference = item.get("reference")
                if not isinstance(reference, str) or not reference:
                    raise _invalid("each move requires a reference")
                if reference in seen:
                    raise _invalid("move references must be distinct")
                seen.add(reference)
                references.append(reference)

            originals: list[dict[str, Any]] = []
            restaurant_ids: set[str] = set()
            for reference in references:
                current = self._owned_reservation(state, reference, user_id)
                originals.append(current)
                restaurant_ids.add(current["restaurant_id"])
            if len(restaurant_ids) > 1:
                raise _invalid("all moved reservations must belong to the same restaurant")

            updated_records: list[dict[str, Any]] = []
            changed_flags: list[bool] = []
            for item, current in zip(moves, originals):
                if current["status"] == "cancelled":
                    raise _error(409, "reservation_cancelled", "reservation is cancelled")

                if "expected_revision" in item:
                    exp_rev = item["expected_revision"]
                    if isinstance(exp_rev, bool) or not isinstance(exp_rev, int) or exp_rev <= 0:
                        raise _invalid("expected_revision must be a positive integer")
                    if exp_rev != current.get("revision", 1):
                        raise _error(409, "stale_revision", "revision does not match expected_revision")

                self._check_cutoff(state, current)

                current_table_ids = current.get("table_ids") or ([current["table_id"]] if "table_id" in current else [])
                if "table_id" in item and "table_ids" in item:
                    raise _error(422, "validation_failed", "cannot provide both table_id and table_ids")
                if "table_id" in item or "table_ids" in item:
                    rest = state.restaurants.get(current["restaurant_id"])
                    if rest is None:
                        raise _not_found()
                    proposed_table_ids = _normalize_table_selection(rest, item)
                else:
                    proposed_table_ids = list(current_table_ids)

                proposed_starts = item.get("starts_at_local", current["starts_at_local"])
                proposed_party = item.get("party_size", current["party_size"])

                if "party_size" in item:
                    _party_size(item)
                if "starts_at_local" in item:
                    _parse_local(item["starts_at_local"])

                if (
                    proposed_table_ids == current_table_ids
                    and proposed_starts == current["starts_at_local"]
                    and proposed_party == current["party_size"]
                ):
                    updated_records.append(copy.deepcopy(current))
                    changed_flags.append(False)
                else:
                    changes = {name: item[name] for name in ("table_id", "table_ids", "starts_at_local", "party_size") if name in item}
                    updated = self._amended_record(
                        state,
                        current,
                        changes,
                        ignore_references=seen,
                        check_occupancy=False,
                    )
                    updated_records.append(updated)
                    changed_flags.append(True)

            for updated in updated_records:
                if updated.get("status") != "confirmed":
                    continue
                start = _aware(updated["starts_at"])
                end = _record_end(updated)
                u_tables = updated.get("table_ids") or [updated["table_id"]]
                if _has_conflict(
                    state,
                    updated["restaurant_id"],
                    u_tables,
                    start,
                    end,
                    ignore_references=seen,
                ):
                    raise _error(409, "table_unavailable", "table is unavailable")
            for index, first in enumerate(updated_records):
                if first.get("status") != "confirmed":
                    continue
                first_tables = set(first.get("table_ids") or [first["table_id"]])
                for second in updated_records[index + 1 :]:
                    if second.get("status") != "confirmed":
                        continue
                    second_tables = set(second.get("table_ids") or [second["table_id"]])
                    if (
                        first["restaurant_id"] == second["restaurant_id"]
                        and (first_tables & second_tables)
                        and _overlap(
                            _aware(first["starts_at"]),
                            _record_end(first),
                            _aware(second["starts_at"]),
                            _record_end(second),
                        )
                    ):
                        raise _error(409, "table_unavailable", "table is unavailable")

            restaurant = state.restaurants[list(restaurant_ids)[0]]
            any_changed = any(changed_flags)
            if any_changed:
                restaurant["revision"] = restaurant.get("revision", 0) + 1
                affected_series_ids: set[str] = set()
                for is_changed, updated in zip(changed_flags, updated_records):
                    if is_changed and updated.get("series_id"):
                        sid = updated["series_id"]
                        affected_series_ids.add(sid)
                        updated["is_exception"] = True
                        if sid in state.series:
                            for occ in state.series[sid].get("occurrences", []):
                                if occ["reference"] == updated["reference"]:
                                    occ["exception"] = True
                for sid in affected_series_ids:
                    if sid in state.series:
                        state.series[sid]["revision"] = state.series[sid].get("revision", 1) + 1

            for updated in updated_records:
                state.reservations[updated["reference"]] = updated

            return 201, {
                "reservations": [
                    _serialize_reservation(record)
                    for record in updated_records
                ]
            }

        status, response, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path="/reservation-moves",
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response)

    async def _reservation_decision(self, reference: str, headers: dict[str, str]) -> ApiResponse:
        user_id = await self._optional_authenticated_user(headers)
        state = await self.store.snapshot()
        record = state.reservations.get(reference)
        if record is None or user_id is None or record.get("user_id") != user_id:
            raise _not_found()
        return ApiResponse(
            200,
            {
                "reference": record["reference"],
                "revision": record.get("revision", 1),
                "accepted_terms": copy.deepcopy(record.get("accepted_terms", {})),
            },
        )

    async def _reservation_history(self, reference: str, headers: dict[str, str]) -> ApiResponse:
        user_id = await self._optional_authenticated_user(headers)
        state = await self.store.snapshot()
        record = state.reservations.get(reference)
        if record is None or user_id is None or record.get("user_id") != user_id:
            raise _not_found()
        return ApiResponse(
            200,
            {
                "reference": record["reference"],
                "entries": copy.deepcopy(record.get("history", [])),
            },
        )

    async def _create_series(
        self, user_id: str, payload: dict[str, Any], key: str
    ) -> ApiResponse:
        if not isinstance(payload, dict):
            raise _invalid("request body must be an object")
        anchor_ref = payload.get("anchor_reference")
        if not isinstance(anchor_ref, str) or not anchor_ref:
            raise _invalid("anchor_reference is required")
        count = payload.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or not (2 <= count <= 12):
            raise _invalid("count must be an integer between 2 and 12")
        interval_weeks = payload.get("interval_weeks")
        if isinstance(interval_weeks, bool) or not isinstance(interval_weeks, int) or not (1 <= interval_weeks <= 4):
            raise _invalid("interval_weeks must be an integer between 1 and 4")

        async def mutation(state: ServiceState) -> tuple[int, dict[str, Any]]:
            anchor = state.reservations.get(anchor_ref)
            if anchor is None or anchor.get("user_id") != user_id:
                raise _not_found()
            if anchor.get("status") == "cancelled":
                raise _error(409, "reservation_cancelled", "anchor reservation is cancelled")
            if anchor.get("series_id"):
                raise _error(409, "already_in_series", "anchor reservation is already in a series")
            self._check_cutoff(state, anchor)

            restaurant = state.restaurants.get(anchor["restaurant_id"])
            if restaurant is None:
                raise _not_found()
            anchor_table_ids = anchor.get("table_ids") or [anchor["table_id"]]

            anchor_naive = _parse_local(anchor["starts_at_local"])
            anchor_date = anchor_naive.date()
            anchor_time_str = anchor_naive.strftime("%H:%M")
            now_ts = rfc3339(datetime.now(UTC))

            new_records: list[dict[str, Any]] = []
            for i in range(1, count):
                occ_date = anchor_date + timedelta(days=i * interval_weeks * 7)
                occ_local_str = f"{occ_date.isoformat()}T{anchor_time_str}"
                occ_policy = get_effective_policy(restaurant, occ_date)

                occ_cap = _table_selection_capacity(restaurant, occ_policy, anchor_table_ids)
                if anchor["party_size"] > occ_cap:
                    raise _error(422, "party_exceeds_capacity", "party size exceeds table capacity")

                start, local_string = _resolve_booking_time(restaurant, occ_local_str, policy=occ_policy)
                end = _instant(start) + timedelta(minutes=occ_policy["reservation_duration_minutes"])
                end_local = end.astimezone(ZoneInfo(restaurant["timezone"]))

                if _has_conflict(state, anchor["restaurant_id"], anchor_table_ids, start, end):
                    raise _error(409, "table_unavailable", "table is unavailable")
                for prev in new_records:
                    prev_tables = prev.get("table_ids") or [prev["table_id"]]
                    if (set(anchor_table_ids) & set(prev_tables)) and _overlap(start, end, _aware(prev["starts_at"]), _record_end(prev)):
                        raise _error(409, "table_unavailable", "table is unavailable")

                while True:
                    candidate_ref = "".join(secrets.choice(REFERENCE_ALPHABET) for _ in range(8))
                    if candidate_ref not in state.reservations and not any(r["reference"] == candidate_ref for r in new_records):
                        break

                terms = extract_accepted_terms(occ_policy)
                changes = []
                if len(anchor_table_ids) > 1:
                    changes.append({"field": "table_ids", "from": None, "to": list(anchor_table_ids)})
                else:
                    changes.append({"field": "table_id", "from": None, "to": anchor_table_ids[0]})
                changes.append({"field": "starts_at_local", "from": None, "to": local_string})
                changes.append({"field": "party_size", "from": None, "to": anchor["party_size"]})

                history_entry = {
                    "seq": 1,
                    "at": now_ts,
                    "event": "created",
                    "revision": 1,
                    "accepted_terms": copy.deepcopy(terms),
                    "changes": changes,
                }
                rec = {
                    "reservation_id": uuid.uuid4().hex,
                    "reference": candidate_ref,
                    "user_id": user_id,
                    "restaurant_id": anchor["restaurant_id"],
                    "table_ids": list(anchor_table_ids),
                    "party_size": anchor["party_size"],
                    "status": "confirmed",
                    "starts_at_local": local_string,
                    "starts_at": rfc3339(start),
                    "ends_at": rfc3339(end_local),
                    "created_at": now_ts,
                    "revision": 1,
                    "accepted_terms": terms,
                    "history": [history_entry],
                    "series_index": i,
                    "is_exception": False,
                }
                if len(anchor_table_ids) == 1:
                    rec["table_id"] = anchor_table_ids[0]
                new_records.append(rec)

            series_id = "s_" + uuid.uuid4().hex
            anchor["series_id"] = series_id
            anchor["series_index"] = 0
            anchor["is_exception"] = False

            occurrences_meta = [{"index": 0, "reference": anchor["reference"], "exception": False}]
            for rec in new_records:
                rec["series_id"] = series_id
                state.reservations[rec["reference"]] = rec
                occurrences_meta.append({"index": rec["series_index"], "reference": rec["reference"], "exception": False})

            series_record = {
                "series_id": series_id,
                "user_id": user_id,
                "restaurant_id": anchor["restaurant_id"],
                "revision": 1,
                "interval_weeks": interval_weeks,
                "count": count,
                "anchor_reference": anchor["reference"],
                "occurrences": occurrences_meta,
            }
            state.series[series_id] = series_record

            restaurant["revision"] = restaurant.get("revision", 0) + 1

            response_occurrences = [
                {
                    "index": 0,
                    "reference": anchor["reference"],
                    "exception": False,
                    "reservation": _serialize_reservation(anchor),
                }
            ]
            for rec in new_records:
                response_occurrences.append({
                    "index": rec["series_index"],
                    "reference": rec["reference"],
                    "exception": False,
                    "reservation": _serialize_reservation(rec),
                })

            return 201, {
                "series_id": series_id,
                "revision": 1,
                "interval_weeks": interval_weeks,
                "occurrences": response_occurrences,
            }

        status, response, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path="/series",
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response)

    async def _get_series(self, series_id: str, headers: dict[str, str]) -> ApiResponse:
        user_id = await self._optional_authenticated_user(headers)
        state = await self.store.snapshot()
        series = state.series.get(series_id)
        if series is None or user_id is None or series.get("user_id") != user_id:
            raise _not_found()
        occurrences = []
        for occ in series.get("occurrences", []):
            ref = occ["reference"]
            rec = state.reservations.get(ref)
            if rec is not None:
                occurrences.append({
                    "index": occ["index"],
                    "reference": ref,
                    "exception": occ.get("exception", False),
                    "reservation": _serialize_reservation(rec),
                })
        return ApiResponse(
            200,
            {
                "series_id": series["series_id"],
                "revision": series["revision"],
                "interval_weeks": series["interval_weeks"],
                "occurrences": occurrences,
            },
        )

    async def _amend_series(
        self,
        series_id: str,
        user_id: str,
        payload: dict[str, Any],
        key: str,
        path: str,
    ) -> ApiResponse:
        async def mutation(current: ServiceState) -> tuple[int, dict[str, Any]]:
            series = current.series.get(series_id)
            if series is None or series.get("user_id") != user_id:
                raise _not_found()

            if "expected_revision" not in payload or "from_index" not in payload or "local_time" not in payload:
                raise _invalid("expected_revision, from_index, and local_time are required")

            exp_rev = payload["expected_revision"]
            if isinstance(exp_rev, bool) or not isinstance(exp_rev, int) or exp_rev <= 0:
                raise _invalid("expected_revision must be a positive integer")

            from_idx = payload["from_index"]
            if isinstance(from_idx, bool) or not isinstance(from_idx, int) or not (0 <= from_idx < series.get("count", 0)):
                raise _invalid("from_index must be an integer in 0..count-1")

            local_time = payload["local_time"]
            if not isinstance(local_time, str) or not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", local_time):
                raise _invalid("local_time must be HH:MM in 00:00..23:59")

            if exp_rev != series.get("revision", 1):
                raise DomainError(409, "stale_revision", "mismatched series revision")

            restaurant = current.restaurants.get(series["restaurant_id"])
            if restaurant is None:
                raise _not_found()

            eligible_occurrences = []
            for occ in series.get("occurrences", []):
                if occ["index"] < from_idx:
                    continue
                if occ.get("exception", False):
                    continue
                ref = occ["reference"]
                rec = current.reservations.get(ref)
                if rec is None or rec.get("status") == "cancelled":
                    continue
                eligible_occurrences.append((occ, rec))

            changes_to_apply = []
            for occ, rec in eligible_occurrences:
                curr_starts_at_local = rec["starts_at_local"]
                date_part = _parse_local(curr_starts_at_local).date()
                proposed_local = f"{date_part.isoformat()}T{local_time}"

                if proposed_local == curr_starts_at_local:
                    continue

                self._check_cutoff(current, rec)
                pol = get_effective_policy(restaurant, date_part)
                start_instant, resolved_local = _resolve_booking_time(restaurant, proposed_local, policy=pol)
                duration = timedelta(minutes=pol["reservation_duration_minutes"])
                end_instant = start_instant + duration
                end_local = end_instant.astimezone(ZoneInfo(restaurant["timezone"]))

                rec_table_ids = rec.get("table_ids") or [rec["table_id"]]
                cap = _table_selection_capacity(restaurant, pol, rec_table_ids)
                if rec["party_size"] > cap:
                    raise _error(422, "party_exceeds_capacity", "party size exceeds table capacity")

                changes_to_apply.append({
                    "occ": occ,
                    "rec": rec,
                    "policy": pol,
                    "start_instant": start_instant,
                    "end_instant": end_instant,
                    "resolved_local": resolved_local,
                    "end_local": end_local,
                })

            if changes_to_apply:
                changed_refs = {item["rec"]["reference"] for item in changes_to_apply}
                for item in changes_to_apply:
                    rec_tables = item["rec"].get("table_ids") or [item["rec"]["table_id"]]
                    if _has_conflict(
                        current,
                        restaurant["id"],
                        rec_tables,
                        item["start_instant"],
                        item["end_instant"],
                        ignore_references=changed_refs,
                    ):
                        raise _error(409, "table_unavailable", "table is unavailable")

                for i, first in enumerate(changes_to_apply):
                    first_tables = set(first["rec"].get("table_ids") or [first["rec"]["table_id"]])
                    for second in changes_to_apply[i + 1 :]:
                        second_tables = set(second["rec"].get("table_ids") or [second["rec"]["table_id"]])
                        if (first_tables & second_tables) and _overlap(
                            first["start_instant"], first["end_instant"],
                            second["start_instant"], second["end_instant"]
                        ):
                            raise _error(409, "table_unavailable", "table is unavailable")

            now_ts = rfc3339(datetime.now(UTC))
            for item in changes_to_apply:
                rec = item["rec"]
                old_starts = rec["starts_at_local"]
                rec["starts_at_local"] = item["resolved_local"]
                rec["starts_at"] = rfc3339(item["start_instant"])
                rec["ends_at"] = rfc3339(item["end_local"])
                new_terms = extract_accepted_terms(item["policy"])
                rec["accepted_terms"] = new_terms
                rec["revision"] = rec.get("revision", 1) + 1

                hist = rec.setdefault("history", [])
                hist.append({
                    "seq": len(hist) + 1,
                    "at": now_ts,
                    "event": "changed",
                    "revision": rec["revision"],
                    "accepted_terms": copy.deepcopy(new_terms),
                    "changes": [{"field": "starts_at_local", "from": old_starts, "to": item["resolved_local"]}],
                })

            if changes_to_apply:
                series["revision"] = series.get("revision", 1) + 1
                restaurant["revision"] = restaurant.get("revision", 0) + 1

            occurrences_out = []
            for occ in series.get("occurrences", []):
                ref = occ["reference"]
                r = current.reservations.get(ref)
                if r is not None:
                    occurrences_out.append({
                        "index": occ["index"],
                        "reference": ref,
                        "exception": occ.get("exception", False),
                        "reservation": _serialize_reservation(r),
                    })

            resp_body = {
                "series_id": series["series_id"],
                "revision": series["revision"],
                "interval_weeks": series["interval_weeks"],
                "occurrences": occurrences_out,
            }
            return 201, resp_body

        status, response_body, _ = await self.store.idempotent_write(
            user_id=user_id,
            method="POST",
            path=path,
            key=key,
            request_body=payload,
            mutation=mutation,
        )
        return ApiResponse(status, response_body)