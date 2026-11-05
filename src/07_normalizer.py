"""Normalize heterogeneous evidence parser results to a stable JSON contract."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)

    evidence_id: str
    system_id: str = ""
    resource_id: str = ""
    data_category: str = "UNKNOWN"
    state: Literal[
        "PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "INACTIVE",
        "BLOCKED", "DISABLED", "UNKNOWN",
    ] = "UNKNOWN"
    identifiers_matched: list[str] = Field(default_factory=list)
    source_path: str = ""
    is_tombstone: bool = False
    has_exposed_pii: bool = False
    fact_type: Literal["record", "negative_lookup"] = "record"
    verification_scope: str = ""
    timestamp: str = ""

    @field_validator("is_tombstone", mode="before")
    @classmethod
    def parse_tombstone_flag(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        return str(value).strip().casefold() in {"1", "true", "yes", "y", "on"}


_STATE_MAP = {
    "FOUND": "PRESENT", "EXISTS": "PRESENT", "IDENTIFIABLE": "PRESENT", "ACTIVE": "ACTIVE",
    "NOT_FOUND": "ABSENT", "NOT FOUND": "ABSENT", "MISSING": "ABSENT", "DELETED": "ABSENT", "LOOKUP_MISS": "ABSENT",
    "INACTIVE": "INACTIVE", "DISABLED": "DISABLED", "BLOCKED": "BLOCKED",
    "REDACTED": "REDACTED", "ANONYMIZED": "ANONYMIZED", "ANONYMISED": "ANONYMIZED",
    "PRESENT": "PRESENT", "ABSENT": "ABSENT", "DELETED": "ABSENT",
}
_KNOWN_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
    "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
    "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "UNMAPPED", "UNKNOWN",
}
_CATEGORY_MARKERS = (
    ("tombstone", "ACCOUNT_TOMBSTONE"), ("backup", "BACKUP_ARCHIVE"),
    ("restore", "BACKUP_ARCHIVE"), ("attachment", "SUPPORT_ATTACHMENT"),
    ("search", "SEARCH_INDEX_ENTRY"), ("analytics", "ANALYTICS_PROFILE"),
    ("telemetry", "PRODUCT_TELEMETRY"), ("support", "SUPPORT_MESSAGE"),
    ("export", "USER_EXPORT"), ("marketing", "MARKETING_PROFILE"),
    ("email_delivery", "EMAIL_DELIVERY_LOG"), ("audit", "SECURITY_AUDIT_LOG"),
    ("legal_hold", "LEGAL_HOLD_RECORD"), ("profile", "USER_PROFILE"),
)
_SYSTEM_PREFIXES = {
    "account": "account_service", "profile": "account_service", "search": "search_service",
    "support": "support_platform", "attachment": "support_platform", "analytics": "analytics_platform",
    "backup": "backup_service", "export": "export_service", "marketing": "marketing_platform",
    "flow": "integration_service", "data_flow": "integration_service", "audit": "security_service",
    "tombstone": "identity_service", "email": "email_service",
}


def _get(source: dict[str, Any], *names: str, default: Any = "") -> Any:
    fields = {str(key).casefold(): value for key, value in source.items()}
    for name in names:
        value = fields.get(name.casefold())
        if value is not None and str(value).strip():
            return value
    return default


def _system_id(source: dict[str, Any], resource_id: str) -> str:
    explicit = str(_get(source, "system_id", "system", "data_store", "source_system")).strip()
    if explicit:
        aliases = {"account": "account_service", "search": "search_service", "backup": "backup_service", "export": "export_service", "analytics": "analytics_platform", "support": "support_platform", "identity": "identity_service", "security": "security_service"}
        return aliases.get(explicit.casefold(), explicit)
    prefix = resource_id.split("_", 1)[0].casefold()
    return _SYSTEM_PREFIXES.get(prefix, "")


def _data_category(source: dict[str, Any], resource: str) -> str:
    value = str(_get(source, "data_category", "category", "record_type", "collection", "collection_name", default="")).strip().upper().replace(" ", "_")
    if value in _KNOWN_CATEGORIES:
        return value
    combined = " ".join((value, resource)).casefold()
    return next((category for marker, category in _CATEGORY_MARKERS if marker in combined), "UNMAPPED")


def _bool_value(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "y", "on", "enabled", "active"}


def normalize_evidence(facts_by_id: dict[Any, dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Return evaluator-compatible facts with canonical names and state values."""
    normalized: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for evidence_id_value, facts in facts_by_id.items():
        evidence_id = str(evidence_id_value)
        buckets: dict[str, list[dict[str, Any]]] = {
            "records_found": [], "data_flows_found": [], "restore_risks_found": []
        }
        for raw in facts.get("records_found", []) or []:
            source = dict(raw)
            resource = str(_get(source, "resource_id", "record_id", "account_id", "resource", "backup_id", "flow_id"))
            raw_state = str(_get(source, "record_state", "state", "status", default="UNKNOWN")).strip().upper().replace(" ", "_")
            state = _STATE_MAP.get(raw_state, "UNKNOWN")
            category = _data_category(source, resource)
            is_tombstone = _bool_value(_get(source, "is_tombstone", default=False)) or category == "ACCOUNT_TOMBSTONE" or resource.casefold().startswith("tombstone_")
            has_pii = _bool_value(_get(source, "has_exposed_pii", default=False)) or any(
                _get(source, key, default=None) not in (None, "", "null")
                for key in ("email", "phone", "name", "full_name", "email_hash", "requester_email", "requester_phone")
            )
            if is_tombstone and has_pii:
                state = "PRESENT"
            elif is_tombstone and state in {"ABSENT", "UNKNOWN"}:
                state = "REDACTED"
            matched_value = _get(source, "identifiers_matched", default=[])
            if isinstance(matched_value, str):
                matched = [matched_value]
            elif isinstance(matched_value, (list, tuple, set)):
                matched = sorted({str(value) for value in matched_value if str(value).strip()})
            else:
                matched = []
            row = NormalizedRecord(
                evidence_id=evidence_id,
                system_id=_system_id(source, resource),
                resource_id=resource,
                data_category=category,
                state=state,
                identifiers_matched=matched,
                source_path=str(_get(source, "source_path", "file_path")),
                is_tombstone=is_tombstone,
                has_exposed_pii=has_pii,
                fact_type="negative_lookup" if str(_get(source, "fact_type", default="")).casefold() == "negative_lookup" or state == "ABSENT" else "record",
                verification_scope=str(_get(source, "verification_scope", default="")),
                timestamp=str(_get(source, "timestamp", "observed_at", "updated_at", "created_at")),
            ).model_dump()
            # Preserve the legacy evaluator's record_state alias.
            row["record_state"] = row.pop("state")
            buckets["records_found"].append(row)
        for raw in facts.get("data_flows_found", []) or []:
            source = dict(raw)
            flow_id = str(_get(source, "flow_id", "resource_id", "id"))
            state = str(_get(source, "status", "state", default="UNKNOWN")).upper()
            buckets["data_flows_found"].append({
                "evidence_id": evidence_id,
                "flow_id": flow_id,
                "system_id": _system_id(source, flow_id),
                "status": _STATE_MAP.get(state, "UNKNOWN"),
                "description": str(_get(source, "description", "details")),
                "identifiers_matched": sorted({str(value) for value in (_get(source, "identifiers_matched", default=[]) if not isinstance(_get(source, "identifiers_matched", default=[]), str) else [_get(source, "identifiers_matched")]) if str(value).strip()}),
            })
        for raw in facts.get("restore_risks_found", []) or []:
            source = dict(raw)
            backup = str(_get(source, "backup_id", "resource_id", "id"))
            buckets["restore_risks_found"].append({
                "evidence_id": evidence_id,
                "backup_id": backup,
                "system_id": _system_id(source, backup),
                "created_at": str(_get(source, "created_at", "timestamp")),
                "status": str(_get(source, "status", "state", default="ACTIVE")).upper(),
                "restore_allowed": _bool_value(_get(source, "restore_allowed", default=True)),
                "identifiers_matched": sorted({str(value) for value in (_get(source, "identifiers_matched", default=[]) if not isinstance(_get(source, "identifiers_matched", default=[]), str) else [_get(source, "identifiers_matched")]) if str(value).strip()}),
            })
        # Retain OCR text for conflict review when a catalog links a resource
        # to one identity but a contemporaneous screenshot shows another.
        if facts.get("ocr_text"):
            buckets["ocr_text"] = str(facts["ocr_text"])
        normalized[evidence_id] = buckets
    return normalized
