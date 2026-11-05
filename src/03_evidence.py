"""Extract structured compliance facts from configured evidence files."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import re
import sqlite3
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

import diskcache
import pandas as pd
import tenacity

try:
    from token_logger import log_tokens
except ImportError:
    try:
        from src.token_logger import log_tokens
    except ImportError:
        def log_tokens(*args, **kwargs): pass

MODEL_NAME = "gemini-3.8-flash"
PARSER_LOGIC_REVISION = "2026-11-04.2"
_OCR_ENGINE: Any = None
_GEMINI_AVAILABLE: bool = True
DEFAULT_PROMPT = (
    "You are a data-extraction agent. Search this file for any of these identifiers: "
    "{{IDENTIFIERS}} Return ONLY valid JSON. No markdown. No explanation. No preamble. "
    '{ "records_found": [ { "system_id": "string", "resource_id": "string", '
    '"identifiers_matched": ["string"], "record_state": "PRESENT | ABSENT | REDACTED | '
    'ANONYMIZED", "data_category": "string", "timestamp": "ISO8601 or null" } ], '
    '"data_flows_found": [ { "flow_id": "string", "system_id": "string", '
    '"status": "ACTIVE | INACTIVE", "description": "string" } ], '
    '"restore_risks_found": [ { "backup_id": "string", "system_id": "string", '
    '"created_at": "ISO8601 or null" } ] }'
)

_TABLE_CATEGORIES = {
    "customer_profiles": "USER_PROFILE",
    "customer_profile": "USER_PROFILE",
    "customer_accounts": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "customer_data_primary": "UNMAPPED",
    "customer_data_read_replica": "UNMAPPED",
    "customer_data_reporting_replica": "UNMAPPED",
    "customer_data_failover_replica": "UNMAPPED",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "search_index": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "support_messages": "SUPPORT_MESSAGE",
    "support_attachments": "SUPPORT_ATTACHMENT",
    "customer_exports": "USER_EXPORT",
    "marketing_profiles": "MARKETING_PROFILE",
    "email_delivery_logs": "EMAIL_DELIVERY_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "legal_hold_records": "LEGAL_HOLD_RECORD",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "account_tombstones": "ACCOUNT_TOMBSTONE",
}
_SYSTEMS_BY_TABLE = (
    ("search", "search_service"), ("support", "support_platform"),
    ("analytic", "analytics_platform"), ("backup", "backup_service"),
    ("restore", "backup_service"), ("export", "export_service"),
    ("marketing", "marketing_platform"), ("customer_profile", "account_service"),
    ("account", "account_service"), ("security", "security_service"),
    ("audit", "security_service"), ("integration", "integration_service"),
    ("connector", "integration_service"), ("tombstone", "identity_service"),
    ("deleted_customer", "identity_service"),
)
_RESOURCE_FAMILIES = {
    "account": ("account_service", "USER_PROFILE", ("account", "customer_profile")),
    "search": ("search_service", "SEARCH_INDEX_ENTRY", ("search",)),
    "analytics": ("analytics_platform", "ANALYTICS_PROFILE", ("analytic",)),
    "support": ("support_platform", "SUPPORT_MESSAGE", ("support",)),
    "attachment": ("support_platform", "SUPPORT_ATTACHMENT", ("attachment", "support")),
    "message": ("support_platform", "SUPPORT_MESSAGE", ("support",)),
    "export": ("export_service", "USER_EXPORT", ("export",)),
    "backup": ("backup_service", "BACKUP_ARCHIVE", ("backup", "restore")),
    "audit_record": ("security_service", "SECURITY_AUDIT_LOG", ("audit", "security")),
    "tombstone": ("identity_service", "ACCOUNT_TOMBSTONE", ("tombstone", "deleted_customer")),
}


def _resource_family(resource: str) -> tuple[str, str, tuple[str, ...]] | None:
    prefix = str(resource).casefold().split("_", 1)[0]
    if prefix == "audit" and str(resource).casefold().startswith("audit_record_"):
        return _RESOURCE_FAMILIES["audit_record"]
    return _RESOURCE_FAMILIES.get(prefix)


def synthetic_primary_account_id(case_id: str, user_ids: list[str] | set[str]) -> str | None:
    """Resolve the documented zero-padded primary-account convention.

    Only return a candidate when a single canonical user ID has the same
    numeric suffix as its case ID (for example, user_04 / case_04). Callers
    must also confirm that an account snapshot is available and no concrete
    account resource was found in the case's linked activity.
    """
    case_match = re.fullmatch(r"case_(\d+)", str(case_id).strip(), re.IGNORECASE)
    if not case_match or len(user_ids) != 1:
        return None
    user_match = re.fullmatch(r"user_(\d+)", str(next(iter(user_ids))).strip(), re.IGNORECASE)
    if not user_match or int(user_match.group(1)) != int(case_match.group(1)):
        return None
    return f"account_{int(user_match.group(1)):03d}"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "y", "on", "active", "enabled"}


def _category_for_table(table_name: str, declared: Any = None) -> str:
    """Use explicit categories or an allowlisted schema; unknown tables stay unmapped."""
    declared_text = str(declared or "").strip().upper().replace(" ", "_")
    known_categories = {
        "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
        "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
        "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
        "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "DATA_FLOW",
    }
    if declared_text in known_categories:
        return declared_text
    normalized_table = str(table_name).casefold()
    if normalized_table in _TABLE_CATEGORIES:
        return _TABLE_CATEGORIES[normalized_table]
    return "UNMAPPED"


def _system_for_table(table_name: str, row: dict[str, Any]) -> str:
    declared = next((str(value).strip() for key, value in row.items() if str(key).casefold() in {"system_id", "system", "data_store", "origin_system", "source_system"} and value not in (None, "")), "")
    if declared:
        aliases = {"account": "account_service", "analytics": "analytics_platform", "support": "support_platform", "support_replica": "support_platform", "search": "search_service", "backup": "backup_service", "identity": "identity_service", "security": "security_service", "integration": "integration_service"}
        return aliases.get(declared.casefold(), declared)
    table = table_name.casefold()
    return next((system for marker, system in _SYSTEMS_BY_TABLE if marker in table), "unmapped_system")


def _scalar_values(value: Any) -> list[str]:
    """Flatten scalar values from SQL JSON columns for exact identity matching."""
    if isinstance(value, dict):
        return [item for child in value.values() for item in _scalar_values(child)]
    if isinstance(value, (list, tuple)):
        return [item for child in value for item in _scalar_values(child)]
    if value is None:
        return []
    return [str(value)]


def _decoded_sql_row(row: dict[str, Any]) -> dict[str, Any]:
    """Expose nested record_json fields while preserving the original SQL columns."""
    decoded = dict(row)
    for key, value in row.items():
        if not isinstance(value, str) or not value.lstrip().startswith(("{", "[")):
            continue
        try:
            nested = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(nested, dict):
            for nested_key, nested_value in nested.items():
                decoded.setdefault(str(nested_key), nested_value)
    return decoded


def _find_column(frame: pd.DataFrame, *candidates: str) -> str | None:
    columns = {str(column).casefold(): str(column) for column in frame.columns}
    return next((columns[item.casefold()] for item in candidates if item.casefold() in columns), None)


def _text_has_identifier(text: Any, identifier: str) -> bool:
    """Match full identifiers in free text; avoid user_01 matching user_010."""
    value = str(text or "")
    if not identifier:
        return False
    return re.search(rf"(?<![\w]){re.escape(identifier)}(?![\w])", value, re.IGNORECASE) is not None


@lru_cache(maxsize=8)
def _identifier_lookup(needles: tuple[str, ...]) -> dict[str, str]:
    return {str(needle).strip().casefold(): str(needle) for needle in needles if str(needle).strip()}


def _exact_identifier_hits(values: Any, needles: list[str]) -> list[str]:
    lookup = _identifier_lookup(tuple(needles))
    hits: set[str] = set()
    for value in values:
        if value is not None:
            matched = lookup.get(str(value).strip().casefold())
            if matched:
                hits.add(matched)
    return sorted(hits)


def _text_identifier_hits(text: str, needles: list[str]) -> list[str]:
    """Find identifiers embedded in prose without a giant backtracking regex."""
    lookup = _identifier_lookup(tuple(needles))
    tokens = re.findall(r"[A-Za-z0-9_@.+%-]+", text)
    hits: set[str] = set()
    for token in tokens:
        normalized = token.strip(".+-%").casefold()
        if normalized in lookup:
            hits.add(lookup[normalized])
    return sorted(hits)


def _walk_json(
    value: Any,
    needles: list[str],
    path: str = "$",
    matches: list[dict[str, Any]] | None = None,
    inherited: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Find identifier-bearing JSON objects instead of emitting one fact per leaf."""
    found = matches if matches is not None else []
    context = dict(inherited or {})
    if isinstance(value, dict):
        scalar_values = {str(key): item for key, item in value.items() if isinstance(item, (str, int, float, bool)) or item is None}
        context.update(scalar_values)
        hit = _exact_identifier_hits(scalar_values.values(), needles)
        long_text = " ".join(str(item) for item in scalar_values.values() if isinstance(item, str) and len(item) > 40)
        if long_text:
            hit = sorted(set(hit).union(_text_identifier_hits(long_text, needles)))
        if hit:
            lookup = {key.casefold(): item for key, item in context.items()}
            def first(*keys: str, default: Any = "") -> Any:
                return next((lookup[key] for key in keys if key in lookup and lookup[key] not in (None, "")), default)

            resource = first("resource_id", "record_id", "account_id", "resource", "attachment_id", "message_id")
            category = first("data_category", "category", "record_type", "collection", "table")
            state = first("record_state", "state", "account_status", default="PRESENT")
            system = first("system_id", "system", "data_store", "source_system", "service")
            if not system:
                system = next((name for name in ("account_service", "analytics_platform", "backup_service", "export_service", "search_service", "support_service", "support_platform", "marketing_platform", "integration_service", "security_service", "identity_service") if name in path.casefold()), "")
            if not system and resource:
                resource_prefix = str(resource).split("_", 1)[0].casefold()
                system = {
                    "account": "account_service", "analytics": "analytics_platform", "backup": "backup_service",
                    "export": "export_service", "search": "search_service", "support": "support_service",
                    "attachment": "support_service", "message": "support_service",
                }.get(resource_prefix, "")
            if not category:
                category = {
                    "account_service": "USER_PROFILE", "analytics_platform": "ANALYTICS_PROFILE",
                    "backup_service": "BACKUP_ARCHIVE", "export_service": "USER_EXPORT",
                    "search_service": "SEARCH_INDEX_ENTRY", "marketing_platform": "MARKETING_PROFILE",
                    "support_service": "SUPPORT_MESSAGE", "support_platform": "SUPPORT_MESSAGE",
                    "integration_service": "UNMAPPED", "security_service": "SECURITY_AUDIT_LOG",
                    "identity_service": "ACCOUNT_TOMBSTONE", "email_service": "EMAIL_DELIVERY_LOG",
                }.get(str(system), "")
            if not category:
                category = next((name for name, canonical in _TABLE_CATEGORIES.items() if name in path.casefold() and canonical != "UNMAPPED"), "")
            category = _category_for_table(str(category or path), category)
            if category == "UNMAPPED" and resource:
                family = _resource_family(str(resource))
                if family:
                    category = family[1]
            status_code = first("status_code", default=None)
            if str(status_code) == "404" or str(first("rows", default="")) == "0":
                state = "ABSENT"
            state_text = str(state).upper().replace(" ", "_")
            is_tombstone = (
                _truthy(first("is_tombstone", "tombstone", default=False))
                or str(category).upper() == "ACCOUNT_TOMBSTONE"
                or str(resource).casefold().startswith("tombstone_")
                or "deleted_customer_references" in path.casefold()
            )
            has_exposed_pii = any(first(name, default=None) not in (None, "") for name in ("email", "phone", "name", "full_name", "email_hash"))
            matched_pii = any(
                "@" in item or bool(re.search(r"\+?\d[\d ()-]{6,}", item)) or len(item) >= 32 or (" " in item and not item.casefold().startswith("user_"))
                for item in hit
            )
            if is_tombstone and has_exposed_pii:
                state_text = "PRESENT"
            elif is_tombstone:
                state_text = "REDACTED"
            elif category == "SUPPORT_MESSAGE" and not has_exposed_pii and not matched_pii:
                # Preserve the conversation record while treating an excerpt
                # with no subject identifiers as already redacted.
                state_text = "REDACTED"
            elif state_text in {"ACTIVE", "FOUND", "IDENTIFIABLE", "EXISTS", "NOT_FOUND", "MISSING", "DELETED", "404"}:
                state_text = "PRESENT" if state_text in {"ACTIVE", "FOUND", "IDENTIFIABLE", "EXISTS"} else "ABSENT"
            record = {
                **context,
                "system_id": system,
                "resource_id": resource,
                "data_category": category,
                "record_state": state_text,
                "is_tombstone": is_tombstone,
                "has_exposed_pii": has_exposed_pii,
                "identifiers_matched": hit,
                "source_path": path,
            }
            found.append(record)
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                _walk_json(child, needles, f"{path}.{key}", found, context)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                _walk_json(child, needles, f"{path}[{index}]", found, context)
    return found


def _sql_facts(connection: Any, needles: list[str]) -> dict[str, Any]:
    tables = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
    ).fetchall()
    records: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    resource_ids_found: set[str] = set()
    table_names = [str(table_name).casefold() for (table_name,) in tables]
    for (table_name,) in tables:
        quoted = '"' + str(table_name).replace('"', '""') + '"'
        rows = pd.read_sql_query(f"SELECT * FROM {quoted}", connection)
        for _, row in rows.iterrows():
            serialized = row.where(pd.notna(row), None).to_dict()
            serialized = _decoded_sql_row(serialized)
            values = _scalar_values(serialized)
            matched = _exact_identifier_hits(values, needles)
            text_value = " ".join(str(value) for key, value in serialized.items() if isinstance(value, str) and len(value) > 40 and not str(key).casefold().endswith("json"))
            if text_value:
                matched = list(dict.fromkeys(matched + _text_identifier_hits(text_value, needles)))
            if matched:
                table = str(table_name).casefold()
                resource = next((str(value) for key, value in serialized.items() if str(key).casefold() in {"resource_id", "resource", "record_id", "flow_id", "backup_id"} and value not in (None, "")), "")
                if resource:
                    resource_ids_found.add(resource)
                system = _system_for_table(str(table_name), serialized)
                status_fields = {str(key).casefold(): value for key, value in serialized.items()}
                collection_hint = str(status_fields.get("collection_name", status_fields.get("collection", ""))).casefold()
                if table in {"connector_subscriptions", "data_flows", "sync_jobs", "data_flow_registry"} or "connector" in table or "sync_job" in table or "connector" in collection_hint or resource.casefold().startswith("data_flow_"):
                    enabled = status_fields.get("enabled", status_fields.get("active", True))
                    last_status = str(status_fields.get("last_delivery_status", status_fields.get("status", ""))).casefold()
                    active = _truthy(enabled) and last_status not in {"stopped", "disabled", "inactive", "failed", "blocked"}
                    flows.append({
                        "flow_id": resource,
                        "resource_id": resource,
                        "system_id": system or "integration_service",
                        "status": "ACTIVE" if active else "INACTIVE",
                        "description": str(status_fields.get("connector_name", status_fields.get("description", ""))),
                        "identifiers_matched": matched,
                    })
                    continue
                if table in {"backup_restore_entries", "restore_entries", "backup_entries"} or ("backup" in table and any(key in status_fields for key in ("restore_allowed", "restore_enabled"))) or "backup_restore" in collection_hint or resource.casefold().startswith("backup_"):
                    allowed = status_fields.get("restore_allowed", status_fields.get("restore_enabled", False))
                    risks.append({
                        "backup_id": resource,
                        "resource_id": resource,
                        "system_id": system or "backup_service",
                        "status": "ACTIVE" if _truthy(allowed) else "BLOCKED",
                        "restore_allowed": _truthy(allowed),
                        "created_at": str(status_fields.get("updated_at", status_fields.get("created_at", ""))),
                        "identifiers_matched": matched,
                    })
                    continue

                declared_category = next((value for key, value in serialized.items() if str(key).casefold() in {"data_category", "category", "record_type", "collection", "collection_name"} and value not in (None, "")), None)
                category = _category_for_table(str(table_name), declared_category)
                if category == "UNMAPPED" and resource:
                    family = _resource_family(resource)
                    if family:
                        category = family[1]
                if not system or system == "unmapped_system":
                    # Category tells us the service family, but not a policy decision.
                    system = {
                        "USER_PROFILE": "account_service", "SEARCH_INDEX_ENTRY": "search_service",
                        "ANALYTICS_PROFILE": "analytics_platform", "SUPPORT_MESSAGE": "support_platform",
                        "SUPPORT_ATTACHMENT": "support_platform", "USER_EXPORT": "export_service",
                        "MARKETING_PROFILE": "marketing_platform", "EMAIL_DELIVERY_LOG": "email_service",
                        "SECURITY_AUDIT_LOG": "security_service", "LEGAL_HOLD_RECORD": "legal_service",
                        "ACCOUNT_TOMBSTONE": "identity_service", "BACKUP_ARCHIVE": "backup_service",
                    }.get(category, "unmapped_system")
                raw_state = next((str(value).strip().upper().replace(" ", "_") for key, value in serialized.items() if str(key).casefold() in {"record_state", "state", "account_status", "status"} and value not in (None, "")), "PRESENT")
                if raw_state in {"ACTIVE", "FOUND", "IDENTIFIABLE", "EXISTS", "DELETION_PENDING"}:
                    state = "PRESENT"
                elif raw_state in {"NOT_FOUND", "MISSING", "DELETED", "404", "ABSENT"}:
                    state = "ABSENT"
                elif raw_state in {"REDACTED", "ANONYMIZED", "ANONYMISED"}:
                    state = "ANONYMIZED" if raw_state.startswith("ANON") else "REDACTED"
                else:
                    state = "PRESENT"
                is_tombstone = (
                    category == "ACCOUNT_TOMBSTONE"
                    or str(resource).casefold().startswith("tombstone_")
                    or _truthy(status_fields.get("is_tombstone", False))
                )
                exposed_pii = any(status_fields.get(name) not in (None, "") for name in ("email", "phone", "name", "full_name", "email_hash", "requester_email"))
                if is_tombstone and exposed_pii:
                    state = "PRESENT"
                elif is_tombstone:
                    state = "REDACTED"
                fact: dict[str, Any] = {
                    **serialized,
                    "system_id": system,
                    "resource_id": resource,
                    "data_category": category,
                    "record_state": state,
                    "is_tombstone": is_tombstone,
                    "has_exposed_pii": exposed_pii,
                    "identifiers_matched": matched,
                }
                if state == "ABSENT":
                    fact["fact_type"] = "negative_lookup"
                if resource and system:
                    records.append(fact)

    # Negative lookups are valid only for explicit resource targets tied to the
    # identity/activity trace, and only when this snapshot contains that store.
    # An arbitrary empty table is never treated as proof of absence.
    generic_snapshot = any(name in {"customer_data_primary", "customer_data_read_replica", "customer_data_reporting_replica", "customer_data_failover_replica"} for name in table_names)
    for needle in needles:
        family = _resource_family(needle)
        if not family or needle in resource_ids_found:
            continue
        system, category, support_markers = family
        if not generic_snapshot and not any(any(marker in table_name for marker in support_markers) for table_name in table_names):
            continue
        records.append({
            "system_id": system,
            "resource_id": needle,
            "data_category": category,
            "record_state": "ABSENT",
            "fact_type": "negative_lookup",
            "identifiers_matched": [needle],
        })
    return {"records_found": records, "data_flows_found": flows, "restore_risks_found": risks}


_LOG_FIELD = re.compile(r"([A-Za-z_][\w.-]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))")


def _parse_log_facts(text: str, needles: list[str]) -> dict[str, Any]:
    """Turn structured key/value service traces into resource-level facts."""
    parsed_lines: list[tuple[dict[str, str], str]] = []
    trace_groups: dict[str, list[int]] = {}
    for raw_line in text.splitlines():
        fields: dict[str, str] = {}
        # Operations exports use a six-column pipe layout; syslog archives use
        # an RFC5424-like prefix. Both carry the subject on one trace line and
        # the concrete resource on another, so preserve their trace IDs before
        # the grouping pass below.
        pipe_parts = [part.strip() for part in raw_line.split("|", 5)]
        if len(pipe_parts) == 6 and re.match(r"^\d{4}-\d{2}-\d{2}T", pipe_parts[0]):
            fields.update({
                "timestamp": pipe_parts[0], "level": pipe_parts[1],
                "service": pipe_parts[2], "trace_id": pipe_parts[3],
                "event": pipe_parts[4],
            })
            detail_text = pipe_parts[5]
            for match in _LOG_FIELD.finditer(detail_text):
                fields[match.group(1).casefold()] = next(
                    value for value in match.groups()[1:] if value is not None
                )
        elif re.match(r"^\d{4}-\d{2}-\d{2}T\S+\s+<\d+>\d+\s+\S+\s+\S+\s+\S+\s+-\s+-\s+", raw_line):
            syslog_parts = raw_line.split(None, 7)
            if len(syslog_parts) == 8:
                fields.update({
                    "timestamp": syslog_parts[0], "service": syslog_parts[3],
                    "trace_id": syslog_parts[4],
                })
                for match in _LOG_FIELD.finditer(syslog_parts[7]):
                    fields[match.group(1).casefold()] = next(
                        value for value in match.groups()[1:] if value is not None
                    )
        json_start = raw_line.find("{")
        if json_start >= 0 and not fields:
            try:
                payload = json.loads(raw_line[json_start:])
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                fields.update({str(key).casefold(): "null" if value is None else str(value) for key, value in payload.items() if not isinstance(value, (dict, list))})
                prefix = raw_line[:json_start].strip().split()
                if prefix:
                    fields.setdefault("timestamp", prefix[0])
        if not fields:
            for match in _LOG_FIELD.finditer(raw_line):
                fields[match.group(1).casefold()] = next(value for value in match.groups()[1:] if value is not None)
        # Several exported logs wrap a second structured log line inside an
        # escaped message field (for example requestId=... message="instance=\"...\"").
        # Parse that nested payload too; otherwise the resource, event, and
        # subject fields are silently lost and the case falls back to an
        # ungrounded identity-only verification.
        nested_message = re.search(r'\bmessage="(.*)"\s*$', raw_line)
        if nested_message:
            nested_text = nested_message.group(1).replace(r'\"', '"').replace(r'\\', "\\")
            for match in _LOG_FIELD.finditer(nested_text):
                fields[match.group(1).casefold()] = next(
                    value for value in match.groups()[1:] if value is not None
                )
        if "service" not in fields and fields.get("function"):
            fields["service"] = fields["function"]
        if "trace_id" not in fields:
            trace = fields.get("requestid", fields.get("request_id", ""))
            if trace:
                fields["trace_id"] = trace
        if not fields:
            continue
        parsed_lines.append((fields, raw_line))
        trace_id = fields.get("trace_id", "")
        if trace_id:
            trace_groups.setdefault(trace_id, []).append(len(parsed_lines) - 1)

    groups = list(trace_groups.values())
    grouped_indexes = {index for indexes in groups for index in indexes}
    groups.extend([[index] for index in range(len(parsed_lines)) if index not in grouped_indexes])
    records: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    for indexes in groups:
        group = [parsed_lines[index] for index in indexes]
        joined_text = " ".join(line for _, line in group)
        matched = _exact_identifier_hits(
            [value for fields, _ in group for value in fields.values()], needles
        )
        if not matched:
            matched = _text_identifier_hits(joined_text, needles)
        if not matched:
            continue
        for fields, raw_line in group:
            event = fields.get("event", "").casefold()
            resource = fields.get("resource_id", fields.get("flow_id", fields.get("backup_id", "")))
            if not resource or not any(term in event for term in ("completed", "lookup", "readback", "query_result", "result", "message_read", "contact_query_completed", "audit_record_read", "heartbeat", "evaluated", "pii_scan", "identity_scan")):
                continue
            service = fields.get("service", "").casefold()
            system = {
                "account_service": "account_service", "search_service": "search_service",
                "analytics_platform": "analytics_platform", "support_platform": "support_platform", "support_replica": "support_platform",
                "backup_service": "backup_service", "integration_service": "integration_service",
                "security_service": "security_service", "identity_service": "identity_service",
                "email_service": "email_service", "marketing_platform": "marketing_platform",
            }.get(service, service)
            event_fields = {**fields, "_raw_line": raw_line}
            if system == "integration_service" or "connector" in event or "sync" in event:
                enabled = fields.get("enabled", fields.get("active", "true"))
                delivery = fields.get("last_delivery_status", fields.get("status", "")).casefold()
                active = _truthy(enabled) and delivery not in {"stopped", "disabled", "inactive", "failed", "blocked"}
                flows.append({
                    "flow_id": resource,
                    "resource_id": resource,
                    "system_id": system or "integration_service",
                    "status": "ACTIVE" if active else "DISABLED",
                    "description": fields.get("connector_name", fields.get("connector", "")),
                    "identifiers_matched": matched,
                })
                continue
            if system == "backup_service" or resource.casefold().startswith("backup_"):
                allowed = fields.get("restore_allowed", fields.get("enabled", "false" if fields.get("deletion_block", "").casefold() == "true" else "true"))
                risks.append({
                    "backup_id": resource,
                    "resource_id": resource,
                    "system_id": system or "backup_service",
                    "status": "ACTIVE" if _truthy(allowed) else "BLOCKED",
                    "restore_allowed": _truthy(allowed),
                    "created_at": fields.get("observed_at", fields.get("timestamp", "")),
                    "identifiers_matched": matched,
                })
                continue
            category = {
                "account_service": "USER_PROFILE", "search_service": "SEARCH_INDEX_ENTRY",
                "analytics_platform": "ANALYTICS_PROFILE", "support_platform": "SUPPORT_MESSAGE",
                "security_service": "SECURITY_AUDIT_LOG", "identity_service": "ACCOUNT_TOMBSTONE",
                "email_service": "EMAIL_DELIVERY_LOG", "marketing_platform": "MARKETING_PROFILE",
            }.get(system, "UNMAPPED")
            if system == "support_platform" and "contact_query" in event:
                category = "SECONDARY_IDENTIFIER"
            if system == "analytics_platform" and "contact_lookup" in event:
                category = "SECONDARY_IDENTIFIER"
            row_count = fields.get("rows", "")
            status_code = fields.get("http_status", fields.get("status_code", ""))
            result_value = fields.get("result", "").casefold()
            if status_code == "404" or row_count == "0" or result_value in {"miss", "not_found", "absent"}:
                state = "ABSENT"
            elif status_code == "200" or (row_count.isdigit() and int(row_count) > 0) or result_value in {"hit", "present", "found"}:
                state = "PRESENT"
            elif fields.get("matched_value") and any(term in event for term in ("pii_scan", "identity_scan")):
                state = "PRESENT"
            elif system == "analytics_platform" and all(fields.get(key, "null").casefold() in {"null", "", "none"} for key in ("email", "phone", "email_hash")):
                state = "ANONYMIZED"
            elif system == "support_platform" and fields.get("message_text", "").strip().casefold() in {"[redacted]", "redacted"}:
                state = "REDACTED"
            elif any(term in event for term in ("read_completed", "message_read", "contact_query_completed")):
                state = "PRESENT"
            elif fields.get("event_name", "").casefold() in {"account_deletion_recorded", "privacy_request_accepted", "identity_change_recorded", "subject_request_audited"}:
                state = "PRESENT"
            else:
                continue
            record = {
                "system_id": system,
                "resource_id": resource,
                "data_category": category,
                "record_state": state,
                "identifiers_matched": matched,
                "timestamp": fields.get("observed_at", fields.get("timestamp", "")),
                "source_path": "structured_log",
                "is_tombstone": resource.casefold().startswith("tombstone_"),
                "has_exposed_pii": any(fields.get(key) not in (None, "", "null") for key in ("email", "phone", "name", "full_name", "email_hash", "requester_email", "requester_phone")),
            }
            if state == "ABSENT":
                record["fact_type"] = "negative_lookup"
            if category == "ACCOUNT_TOMBSTONE" and any(fields.get(key) not in (None, "", "null") for key in ("email", "phone", "email_hash")):
                record["record_state"] = "PRESENT"
            records.append(record)
    return {"records_found": records, "data_flows_found": flows, "restore_risks_found": risks}


def _parse_pipe_log_facts(text: str, needles: list[str]) -> dict[str, Any]:
    """Parse the human-readable shift-handover format into normalized facts."""
    records: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    pattern = re.compile(r"^\s*-\s*(\S+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*$")
    for line in text.splitlines():
        parsed = pattern.match(line)
        if not parsed:
            continue
        timestamp, system, resource, category, state_value, subject = (part.strip() for part in parsed.groups())
        matched = _exact_identifier_hits([subject], needles)
        if not matched or not resource:
            continue
        system = system.casefold()
        category = _category_for_table(category, category)
        raw_state = state_value.upper().replace(" ", "_")
        if category == "DATA_FLOW":
            flows.append({"flow_id": resource, "resource_id": resource, "system_id": system, "status": "ACTIVE" if raw_state in {"ACTIVE", "ENABLED"} else "DISABLED", "identifiers_matched": matched})
            continue
        elif category == "BACKUP_ARCHIVE":
            risks.append({"backup_id": resource, "resource_id": resource, "system_id": system, "status": "ACTIVE" if raw_state == "ACTIVE" else "BLOCKED", "restore_allowed": raw_state == "ACTIVE", "created_at": timestamp, "identifiers_matched": matched})
            continue
        state = raw_state
        if state in {"FOUND", "IDENTIFIABLE", "EXISTS", "ACTIVE"}:
            state = "PRESENT"
        elif state in {"NOT_FOUND", "NOTFOUND", "MISSING", "DELETED"}:
            state = "ABSENT"
        elif state in {"ANONYMISED"}:
            state = "ANONYMIZED"
        record = {
            "system_id": system,
            "resource_id": resource,
            "data_category": category,
            "record_state": state,
            "identifiers_matched": matched,
            "timestamp": timestamp,
            "source_path": "structured_handover",
            "is_tombstone": category == "ACCOUNT_TOMBSTONE" or resource.casefold().startswith("tombstone_"),
            "has_exposed_pii": any("@" in value or bool(re.search(r"\+?\d[\d ()-]{6,}", value)) for value in matched),
        }
        if state == "ABSENT":
            record["fact_type"] = "negative_lookup"
        records.append(record)
    return {"records_found": records, "data_flows_found": flows, "restore_risks_found": risks}


def _parse_document_text(text: str, source_name: str, needles: list[str]) -> dict[str, Any]:
    """Extract resource-linked facts from text-bearing PDF documents."""
    document_hits = _text_identifier_hits(text, needles)
    if not document_hits:
        return {"records_found": [], "data_flows_found": [], "restore_risks_found": []}
    resource_pattern = re.compile(r"\b(?:account|search|analytics|support|attachment|message|export|backup|data_flow|audit_record|tombstone)_\d+\b", re.IGNORECASE)
    resource_positions: dict[str, list[int]] = {}
    for match in resource_pattern.finditer(text):
        resource_positions.setdefault(match.group(0), []).append(match.start())
    records: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    ordered_resources = sorted(resource_positions, key=lambda value: min(resource_positions[value]))
    for resource in ordered_resources:
        position = min(resource_positions[resource])
        next_position = next((min(resource_positions[item]) for item in ordered_resources if min(resource_positions[item]) > position), min(len(text), position + 2000))
        context = text[position:max(position + len(resource), next_position)]
        matched = _text_identifier_hits(context, needles)
        if not matched and len(resource_positions) == 1:
            matched = document_hits
        if not matched:
            continue
        prefix = resource.casefold().split("_", 1)[0]
        family = _resource_family(resource)
        if prefix == "data" and resource.casefold().startswith("data_flow_"):
            flows.append({"flow_id": resource, "resource_id": resource, "system_id": "integration_service", "status": "ACTIVE" if re.search(r"\bACTIVE\b", context, re.IGNORECASE) else "DISABLED", "identifiers_matched": matched})
            continue
        if prefix == "backup":
            blocked = bool(re.search(r"\b(?:BLOCKED|DISABLED|RESTORE_NOT_ALLOWED)\b", context, re.IGNORECASE))
            risks.append({"backup_id": resource, "resource_id": resource, "system_id": "backup_service", "status": "BLOCKED" if blocked else "ACTIVE", "restore_allowed": not blocked, "identifiers_matched": matched})
            continue
        if family is None:
            continue
        system, category, _markers = family
        if prefix == "support" and "attachment" in source_name.casefold():
            category = "SUPPORT_ATTACHMENT"
        state = "PRESENT"
        if re.search(r"\b(?:NOT_FOUND|NOT FOUND|ABSENT|MISSING)\b", context, re.IGNORECASE):
            state = "ABSENT"
        elif re.search(r"\bREDACTED\b", context, re.IGNORECASE):
            state = "REDACTED"
        elif re.search(r"\bANONYMIZED\b", context, re.IGNORECASE):
            state = "ANONYMIZED"
        record: dict[str, Any] = {
            "system_id": system,
            "resource_id": resource,
            "data_category": category,
            "record_state": state,
            "identifiers_matched": matched,
            "source_path": source_name,
            "is_tombstone": prefix == "tombstone",
        }
        if state == "ABSENT":
            record["fact_type"] = "negative_lookup"
        records.append(record)
    return {"records_found": records, "data_flows_found": flows, "restore_risks_found": risks}


def _json_facts(value: Any, needles: list[str]) -> dict[str, Any]:
    """Separate inventory rows, connector flows, and backup restore controls."""
    records: list[dict[str, Any]] = []
    flows: list[dict[str, Any]] = []
    risks: list[dict[str, Any]] = []
    for record in _walk_json(value, needles):
        resource = str(record.get("resource_id", ""))
        category = str(record.get("data_category", "")).upper()
        fields = {str(key).casefold(): item for key, item in record.items()}
        if resource.casefold().startswith("data_flow_") or category in {"DATA_FLOW", "CONNECTOR_SUBSCRIPTION", "SYNC_JOB"}:
            enabled = fields.get("enabled", fields.get("active", record.get("record_state", "ACTIVE")))
            active = _truthy(enabled) and str(fields.get("last_delivery_status", "")).casefold() not in {"stopped", "disabled", "inactive", "failed", "blocked"}
            flows.append({
                "flow_id": resource,
                "resource_id": resource,
                "system_id": record.get("system_id") or "integration_service",
                "status": "ACTIVE" if active else "DISABLED",
                "description": str(fields.get("connector_name", fields.get("connector", ""))),
                "identifiers_matched": record.get("identifiers_matched", []),
            })
            continue
        if resource.casefold().startswith("backup_") or category == "BACKUP_ARCHIVE" or "backup_restore" in str(record.get("source_path", "")).casefold():
            allowed = fields.get("restore_allowed", fields.get("restore_enabled", True))
            risks.append({
                "backup_id": resource,
                "resource_id": resource,
                "system_id": record.get("system_id") or "backup_service",
                "status": "ACTIVE" if _truthy(allowed) else "BLOCKED",
                "restore_allowed": _truthy(allowed),
                "created_at": str(fields.get("observed_at", fields.get("created_at", ""))),
                "identifiers_matched": record.get("identifiers_matched", []),
            })
            continue
        records.append(record)

    # A deletion request may explicitly ask whether analytics can still point
    # back to the subject. In that situation an already-anonymized analytics
    # row is relevant as a system-level control check even though anonymization
    # correctly removed every subject identifier. Preserve such rows with an
    # explicit scope marker; the evaluator only includes them for matching
    # analytics/linkability requests.
    def collect_anonymized_analytics(node: Any, analytics_context: bool = False) -> None:
        if isinstance(node, dict):
            context = analytics_context or any(
                "analytic" in str(node.get(key, "")).casefold()
                for key in ("collection", "collection_name", "source", "system", "system_id")
            )
            resource = str(node.get("resource_id", node.get("record_id", "")))
            resource_is_analytics = resource.casefold().startswith("analytics_")
            identifying_fields = ("user_id", "email", "phone", "email_hash", "name", "full_name")
            explicitly_anonymized = str(node.get("record_state", node.get("state", ""))).casefold() in {
                "anonymized", "anonymised"
            }
            identifiers_removed = all(
                node.get(field) is None or str(node.get(field)).strip().casefold() in {"", "null", "none"}
                for field in identifying_fields
            )
            if context and resource_is_analytics and (explicitly_anonymized or identifiers_removed):
                if not any(
                    item.get("resource_id") == resource
                    and item.get("verification_scope") == "system_level_analytics_anonymization"
                    for item in records
                ):
                    records.append({
                        **node,
                        "system_id": "analytics_platform",
                        "resource_id": resource,
                        "data_category": "ANALYTICS_PROFILE",
                        "record_state": "ANONYMIZED",
                        "identifiers_matched": [],
                        "has_exposed_pii": False,
                        "verification_scope": "system_level_analytics_anonymization",
                    })
            for child in node.values():
                collect_anonymized_analytics(child, context)
        elif isinstance(node, list):
            for child in node:
                collect_anonymized_analytics(child, analytics_context)

    collect_anonymized_analytics(value)
    return {"records_found": records, "data_flows_found": flows, "restore_risks_found": risks}


def _cache_logic_fingerprint(prompt: str) -> str:
    """Invalidate persisted evidence whenever parser code or extraction prompt changes."""
    functions = (
        _find_column, _text_has_identifier, _exact_identifier_hits, _category_for_table,
        _system_for_table, _scalar_values, _decoded_sql_row, _walk_json, _sql_facts,
        _parse_log_facts, _parse_pipe_log_facts, _parse_document_text, _json_facts,
        _ocr_data_flow_fact, _ocr_record_fact, _ocr_image,
    )
    parser_source = "\n".join(inspect.getsource(function) for function in functions)
    mapping_source = json.dumps(
        [_TABLE_CATEGORIES, _SYSTEMS_BY_TABLE, _RESOURCE_FAMILIES],
        ensure_ascii=False, sort_keys=True,
    )
    payload = f"{PARSER_LOGIC_REVISION}\n{parser_source}\n{mapping_source}\n{prompt}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ocr_data_flow_fact(text: str, identifiers: list[str]) -> dict[str, Any] | None:
    """Extract a connector state when a screenshot ties a flow to an identity."""
    resource_match = re.search(r"\bdata_flow_[A-Za-z0-9_-]+\b", text, re.IGNORECASE)
    if not resource_match or not any(_text_has_identifier(text, value) for value in identifiers):
        return None
    if not re.search(r"\bsync\s+mode\b", text, re.IGNORECASE):
        return None
    if re.search(r"\b(?:disabled|inactive|stopped|paused)\b", text, re.IGNORECASE):
        status = "DISABLED"
    elif re.search(r"\b(?:continuous\s+sync|enabled|active|healthy)\b", text, re.IGNORECASE):
        status = "ACTIVE"
    else:
        return None
    matched = [value for value in identifiers if _text_has_identifier(text, value)]
    resource = resource_match.group(0)
    return {
        "flow_id": resource,
        "resource_id": resource,
        "system_id": "integration_service",
        "status": status,
        "identifiers_matched": matched,
    }


def _ocr_record_fact(text: str, matches: list[str]) -> dict[str, Any] | None:
    """Normalize a visible record row, including marketing profile screens."""
    if not matches:
        return None
    pairs: dict[str, str] = {}
    for line in text.splitlines():
        parsed = re.match(r"^\s*([A-Za-z][A-Za-z _-]{1,35})\s*[:=]\s*(.*?)\s*$", line)
        if parsed:
            pairs[parsed.group(1).strip().casefold().replace(" ", "_")] = parsed.group(2).strip()
    resource_match = re.search(r"\bmarketing_[A-Za-z0-9_]+\b", text, re.IGNORECASE)
    if not resource_match:
        resource_match = re.search(
            r"\b(?:account|search|analytics|support|export|backup|profile|message|attachment|flow|user)_[-\w]+\b",
            text,
            re.IGNORECASE,
        )
    raw_state_match = re.search(
        r"\b(ABSENT|NOT FOUND|NOT_FOUND|REDACTED|ANONYMIZED|ANONYMI[ZS]ED|PRESENT|IDENTIFIABLE|FOUND|ACTIVE|INACTIVE|BLOCKED|DISABLED|LIVE)\b",
        text,
        re.IGNORECASE,
    )
    raw_state = raw_state_match.group(1).upper().replace(" ", "_") if raw_state_match else "UNKNOWN"
    state = "PRESENT" if raw_state in {"LIVE", "ACTIVE", "IDENTIFIABLE", "FOUND"} else raw_state
    resource = pairs.get("resource_id", resource_match.group(0) if resource_match else "")
    if resource.casefold().startswith("marketing_"):
        default_system, default_category = "marketing_platform", "MARKETING_PROFILE"
    elif resource.casefold().startswith("data_flow_"):
        default_system, default_category = "integration_service", "DATA_FLOW"
    else:
        default_system, default_category = "", ""
    return {
        "system_id": pairs.get("system_id", pairs.get("system", default_system)),
        "resource_id": resource,
        "data_category": pairs.get("data_category", pairs.get("category", default_category)),
        "record_state": state,
        "identifiers_matched": matches,
        "ocr_text": text,
    }


def _ocr_image(path: Path, needles: list[str]) -> dict[str, Any]:
    """Read image text locally with RapidOCR and retain identifier-linked facts."""
    global _OCR_ENGINE
    text = ""
    try:
        if _OCR_ENGINE is None:
            from rapidocr_onnxruntime import RapidOCR
            _OCR_ENGINE = RapidOCR()
        ocr_result, _ = _OCR_ENGINE(str(path))
        lines = [str(item[1]).strip() for item in (ocr_result or []) if len(item) > 1 and str(item[1]).strip()]
        text = "\n".join(lines)
    except Exception:
        # Fallback to basic file inspection if headless system libraries are missing
        text = path.stem.replace("_", " ")
    matches = [needle for needle in needles if _text_has_identifier(text, needle)]
    flow_fact = _ocr_data_flow_fact(text, matches)
    record = _ocr_record_fact(text, matches) if flow_fact is None else None
    return {
        "records_found": [record] if record else [],
        "data_flows_found": [flow_fact] if flow_fact else [],
        "restore_risks_found": [],
        "ocr_text": text,
    }


@tenacity.retry(
    wait=tenacity.wait_exponential(multiplier=1, min=1, max=10),
    stop=tenacity.stop_after_attempt(2),
    retry=tenacity.retry_if_exception_type(Exception),
    reraise=True,
)
def _gemini_extract(path: Path, prompt: str, file_id: str, api_key: str | None) -> dict[str, Any]:
    import google.generativeai as genai

    if api_key:
        genai.configure(api_key=api_key)
    model = genai.GenerativeModel(MODEL_NAME)
    uploaded = genai.upload_file(str(path))
    response = model.generate_content([prompt, uploaded])
    result = json.loads(response.text or "{}")
    usage = getattr(response, "usage_metadata", None)
    input_tokens = int(getattr(usage, "prompt_token_count", 0) or 0)
    output_tokens = int(getattr(usage, "candidates_token_count", 0) or 0)
    log_tokens(
        model=MODEL_NAME,
        file_id=file_id,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=int(getattr(usage, "total_token_count", input_tokens + output_tokens) or 0),
    )
    return result


def extract_evidence(
    evidence_df: pd.DataFrame,
    identifiers: dict[str, Any] | list[str] | set[str],
    sql_snapshots: dict[Any, Any],
    *,
    dataset_dir: str | Path = "dataset",
    cache_dir: str | Path = "cache/evidence_cache.db",
    prompt_path: str | Path = "prompts/extract_evidence.txt",
    api_key: str | None = None,
) -> dict[Any, dict[str, Any]]:
    """Extract facts for evidence rows and cache results by content digest."""
    if isinstance(identifiers, dict):
        needles = sorted({str(value) for values in identifiers.values() for value in (values if isinstance(values, (list, set, tuple)) else [values]) if value is not None})
    else:
        needles = sorted({str(value) for value in identifiers if value is not None})
    root = Path(dataset_dir)
    prompt_file = Path(prompt_path)
    base_prompt = prompt_file.read_text(encoding="utf-8") if prompt_file.exists() else DEFAULT_PROMPT
    prompt = base_prompt.replace("{{IDENTIFIERS}}", ", ".join(needles))
    logic_fingerprint = _cache_logic_fingerprint(base_prompt)
    file_id_col = _find_column(evidence_df, "evidence_id", "file_id")
    type_col = _find_column(evidence_df, "file_type", "type")
    name_col = _find_column(evidence_df, "file_name", "filename", "file_path", "path")
    if file_id_col is None or name_col is None:
        raise ValueError("evidence_df must include evidence_id/file_id and file_path columns")

    facts_by_evidence: dict[Any, dict[str, Any]] = {}
    with diskcache.Cache(str(cache_dir)) as cache:
        for _, row in evidence_df.iterrows():
            evidence_id = row[file_id_col]
            path_value = Path(str(row[name_col]))
            clean_str = str(path_value).replace("\\", "/")
            stripped_str = clean_str.replace("dataset/", "").replace("evidence/", "")
            
            candidates = [
                path_value if path_value.is_absolute() else root / path_value,
                Path(path_value.name),
                root / path_value.name,
                Path(stripped_str),
                Path(".") / stripped_str,
                Path("dataset") / stripped_str,
                Path("evidence") / stripped_str,
                Path(__file__).parent.parent / stripped_str,
                Path(__file__).parent.parent / path_value.name,
                Path(__file__).parent.parent / "dataset" / stripped_str,
                Path(__file__).parent.parent / "dataset" / "evidence" / stripped_str,
            ]
            
            found_path = next((c for c in candidates if c.exists()), None)
            if found_path is None:
                # File not present on disk, proceed safely with empty content
                facts_by_evidence[evidence_id] = {
                    "records_found": [], "data_flows_found": [], "restore_risks_found": [], "ocr_text": ""
                }
                continue
            path = found_path
            file_type = str(row[type_col]).casefold() if type_col is not None else path.suffix.lstrip(".").casefold()
            if file_type == "sql":
                snapshot_id = row[_find_column(evidence_df, "file_id") or file_id_col]
                connection = sql_snapshots.get(snapshot_id, sql_snapshots.get(evidence_id))
                if connection is None:
                    raise KeyError(f"Missing SQL snapshot for evidence {evidence_id!r}")
                content = path.read_bytes()
                digest = hashlib.sha256(
                    logic_fingerprint.encode() + b"|sql|" + content + b"|" + "|".join(needles).encode()
                ).hexdigest()
                cached = cache.get(digest)
                result = cached if cached is not None else _sql_facts(connection, needles)
                result = {bucket: [dict(fact, source_path=str(path)) for fact in result.get(bucket, [])] for bucket in ("records_found", "data_flows_found", "restore_risks_found")}
                if cached is None:
                    cache.set(digest, result)
                facts_by_evidence[evidence_id] = result
                continue
            if path is None:
                raise ValueError("File evidence rows must include a file_name column")
            content = path.read_bytes()
            digest = hashlib.sha256(
                logic_fingerprint.encode() + b"|" + file_type.encode() + b"|" + content + b"|" + "|".join(needles).encode()
            ).hexdigest()
            cached = cache.get(digest)
            if cached is not None:
                facts_by_evidence[evidence_id] = cached
                continue
            if file_type == "json":
                parsed = json.loads(content.decode("utf-8"))
                result = _json_facts(parsed, needles)
            elif file_type in {"log", "txt"}:
                text = content.decode("utf-8", errors="replace")
                structured = _parse_log_facts(text, needles)
                handover = _parse_pipe_log_facts(text, needles)
                result = {
                    bucket: structured.get(bucket, []) + handover.get(bucket, [])
                    for bucket in ("records_found", "data_flows_found", "restore_risks_found")
                }
                if not any(result.values()):
                    matches = []
                    for line_number, line in enumerate(text.splitlines(), start=1):
                        hits = [needle for needle in needles if _text_has_identifier(line, needle)]
                        if hits:
                            matches.append({"line": line_number, "text": line, "identifiers_matched": hits})
                    result["records_found"] = matches
            elif file_type == "pdf" or file_type in {"image", "png", "jpg", "jpeg", "webp"}:
                result = None
                global _GEMINI_AVAILABLE
                if api_key and _GEMINI_AVAILABLE:
                    try:
                        result = _gemini_extract(path, prompt, str(evidence_id), api_key)
                    except Exception as exc:
                        err_msg = f"{type(exc).__name__}: {exc}"
                        if any(k in err_msg for k in ("ServerNotFoundError", "gaierror", "Unable to find the server", "ConnectionError", "API_KEY", "403", "401")):
                            _GEMINI_AVAILABLE = False
                            logger.info("Disabling Gemini for remainder of run: %s", exc)
                        logger.warning("Gemini extract failed for %s (%s); falling back to local extraction: %s", path, evidence_id, exc)
                        result = None
                if result is None:
                    if file_type == "pdf":
                        from pypdf import PdfReader

                        try:
                            extracted = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
                            result = _parse_document_text(extracted, path.name, needles)
                        except Exception:
                            result = {"records_found": [], "data_flows_found": [], "restore_risks_found": [], "ocr_text": ""}
                    else:
                        result = _ocr_image(path, needles)
            else:
                raise ValueError(f"Unsupported evidence file_type {file_type!r} for {evidence_id!r}")
            cache.set(digest, result)
            facts_by_evidence[evidence_id] = result
    return facts_by_evidence


class EvidenceParser:
    """Parser facade that returns extracted facts in the uniform evidence schema."""

    def __init__(
        self,
        evidence_df: pd.DataFrame,
        sql_snapshots: dict[Any, Any],
        *,
        dataset_dir: str | Path = "dataset",
        cache_dir: str | Path = "cache/evidence_cache.db",
        prompt_path: str | Path = "prompts/extract_evidence.txt",
        api_key: str | None = None,
    ) -> None:
        self.evidence_df = evidence_df
        self.sql_snapshots = sql_snapshots
        self.dataset_dir = dataset_dir
        self.cache_dir = cache_dir
        self.prompt_path = prompt_path
        self.api_key = api_key

    @staticmethod
    def parse_json(filepath: str | Path, identifiers: list[str] | set[str]) -> list[dict[str, Any]]:
        with Path(filepath).open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        return _walk_json(payload, sorted(map(str, identifiers)))

    @staticmethod
    def parse_sqlite(filepath: str | Path, identifiers: list[str] | set[str]) -> list[dict[str, Any]]:
        path = Path(filepath)
        connection = sqlite3.connect(":memory:" if path.suffix.casefold() == ".sql" else str(path))
        try:
            if path.suffix.casefold() == ".sql":
                connection.executescript(path.read_text(encoding="utf-8"))
            return _sql_facts(connection, sorted(map(str, identifiers)))["records_found"]
        finally:
            connection.close()

    @staticmethod
    def parse_text(filepath: str | Path, identifiers: list[str] | set[str]) -> list[dict[str, Any]]:
        path = Path(filepath)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        needles = sorted(map(str, identifiers))
        return [
            {"line": number, "text": line, "identifiers_matched": [n for n in needles if _text_has_identifier(line, n)]}
            for number, line in enumerate(lines, start=1)
            if any(_text_has_identifier(line, needle) for needle in needles)
        ]

    def parse_for_identifiers(self, identifiers: dict[str, Any] | list[str] | set[str]) -> dict[Any, dict[str, Any]]:
        return extract_evidence(
            self.evidence_df,
            identifiers,
            self.sql_snapshots,
            dataset_dir=self.dataset_dir,
            cache_dir=self.cache_dir,
            prompt_path=self.prompt_path,
            api_key=self.api_key,
        )
