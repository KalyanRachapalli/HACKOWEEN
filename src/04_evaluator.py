"""Evaluate a deletion request against activity and extracted evidence."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
import re
import unicodedata
from typing import Any

import pandas as pd

DELETION_KEYWORDS = (
    "delete", "deletion", "erase", "erasure", "remove", "removal", "forget", "gdpr",
    "right to erasure", "opt out", "unsubscribe", "close my account", "close the account", "close account",
)

# Explicit, deterministic deletion intent phrases in languages present in the
# challenge data. These are intentionally narrow: export/access/correction and
# marketing opt-out alone do not authorize account deletion.
LOCALIZED_DELETION_PHRASES = (
    "eliminar mi cuenta", "eliminar mis datos", "borrar mi cuenta", "borrar mis datos",
    "suprimir mis datos", "derecho de supresión", "eliminar la cuenta", "borrar la cuenta",
    "supprimer mon compte", "supprimer mes données", "suppression définitive du compte", "effacer mon compte", "effacer mes données",
    "mein konto löschen", "meine daten löschen", "löschen sie mein konto", "löschen sie meine daten",
    "eliminare il mio account", "cancellare i miei dati", "cancellare il mio account",
    "eliminar a minha conta", "apagar os meus dados", "apagar minha conta",
    "удалить мой аккаунт", "удалите мои данные", "удалить мои данные",
    "私のアカウントを削除", "私のデータを削除", "アカウントを削除",
    "删除我的账户", "删除我的帐户", "删除我的个人数据",
)

NON_DELETION_PHRASES = (
    "opt out", "unsubscribe", "do not sell", "stop marketing", "marketing emails",
    "marketing list", "promotional emails", "newsletter",
    "copy of my data", "access my data", "export my data", "correct my data",
    "update my address", "actualizar mis datos", "copia de mis datos", "exportar mis datos",
    "corregir mis datos", "désabonner", "copie de mes données", "corriger mes données",
    "abmelden", "kopie meiner daten", "meine daten korrigieren",
)


def _authorizes_deletion(text: str) -> bool:
    # Request prose is untrusted input. Strip instruction-like clauses before
    # intent detection; this project never executes request text as a prompt.
    neutralized = str(text)
    injection_patterns = (
        r"(?i)\bignore (?:all )?(?:previous|prior|above) instructions\b[^.!?]*[.!?]?",
        r"(?i)\b(?:reveal|print|show) (?:the )?(?:system|developer) prompt\b[^.!?]*[.!?]?",
        r"(?i)\b(?:you are now|act as|pretend to be)\b[^.!?]*[.!?]?",
        r"(?i)\b(?:bypass|override|disable) (?:the )?(?:security|safety|policy|rules)\b[^.!?]*[.!?]?",
    )
    for pattern in injection_patterns:
        neutralized = re.sub(pattern, " ", neutralized)
    normalized = " ".join(unicodedata.normalize("NFKC", neutralized).casefold().split())
    explicit_denial = (
        r"\bnot\s+(?:asking|requesting|seeking)\s+(?:for\s+)?(?:an?\s+)?(?:account\s+)?(?:deletion|erasure|to\s+(?:delete|erase|remove))\b",
        r"\bnot\s+(?:an?\s+)?request\s+to\s+(?:delete|erase|remove)\b",
        r"\b(?:not|never)\s+(?:an?\s+)?(?:account\s+)?(?:deletion|erasure)\s+request\b",
    )
    if any(re.search(pattern, normalized) for pattern in explicit_denial):
        return False
    if re.search(r"\b(?:do not|don't|dont|never|not)\s+(?:want\s+to\s+)?(?:delete|erase|remove|close)\b", normalized):
        return False
    # A subordinate "without removing ..." clause describes what the requester
    # wants preserved; it must not become a positive deletion signal.
    intent_text = re.sub(
        r"\bwithout\s+(?:deleting|erasing|removing)\b[^.!?]*(?:[.!?]|$)",
        " ",
        normalized,
    )
    action = r"(?:delet\w*|eras\w*|remov\w*|forget\w*|supprim\w*|suppression|elimin\w*|borr\w*|cancell\w*)"
    target = r"(?:account|profile|personal\s+(?:data|information)|(?:my|user|customer)\s+data|records?)"
    deletion_scope = bool(
        re.search(rf"\b{action}\b[^.!?;]{{0,80}}\b{target}\b", intent_text)
        or re.search(rf"\b{target}\b[^.!?;]{{0,80}}\b{action}\b", intent_text)
    )
    explicit_deletion = bool(re.search(rf"\b{action}\b", intent_text))
    account_closure = bool(re.search(r"\bclose\s+(?:(?:this|the|my)\s+)?account\b", intent_text))
    japanese_deletion = any(token in normalized for token in ("削除", "消去", "退会", "抹消")) and any(token in normalized for token in ("アカウント", "データ", "個人情報"))
    if any(phrase in normalized for phrase in NON_DELETION_PHRASES):
        # A clear account/data deletion still authorizes deletion when the same
        # message also asks to unsubscribe or access a copy of the data.
        return deletion_scope or account_closure or japanese_deletion or any(
            phrase in normalized for phrase in LOCALIZED_DELETION_PHRASES
        )
    prior_audit = bool(re.search(r"\b(?:verify|confirm|check|inspect|audit|tell me whether|investigate)\b.{0,140}\b(?:prior|previous|latest|actual|account|profile|deletion|deleted|gone|removed|request|state)\b", normalized)) and bool(re.search(r"\b(?:account|profile|deletion|deleted|data|request)\b", normalized))
    french_deletion = bool(re.search(r"\b(?:suppression|supprim\w*|effac\w*)\b.{0,80}\b(?:compte|donn\w*)\b", normalized))
    return explicit_deletion or account_closure or japanese_deletion or prior_audit or any(
        phrase in normalized for phrase in LOCALIZED_DELETION_PHRASES
    ) or french_deletion


def _value(row: Mapping[str, Any], *keys: str, default: Any = None) -> Any:
    lookup = {str(key).casefold(): value for key, value in row.items()}
    for key in keys:
        if key.casefold() in lookup:
            value = lookup[key.casefold()]
            if isinstance(value, (list, tuple, set, dict)):
                return value
            if pd.notna(value):
                return value
    return default


def _rows(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []
    if isinstance(data, pd.DataFrame):
        return data.to_dict(orient="records")
    if isinstance(data, Mapping):
        return [dict(data)]
    if isinstance(data, Iterable) and not isinstance(data, (str, bytes)):
        return [dict(row) for row in data]
    return []


def _step(phase: str, operation: str, system_id: Any = "", resource_id: Any = "", **extra: Any) -> dict[str, Any]:
    return {"phase": phase, "operation": operation, "system_id": "" if system_id is None else str(system_id), "resource_id": "" if resource_id is None else str(resource_id), **extra}


def _status_from_steps(case_id: str, steps: list[dict[str, Any]]) -> str:
    """Assign status from evidence facts, never from workflow-reported status."""
    findings = [step for step in steps if step.get("phase") == "FINDING"]
    verifications = [step for step in steps if step.get("phase") == "VERIFICATION"]
    if findings:
        if not verifications:
            raise ValueError(f"{case_id}: findings exist but no verification plan could be built")
        return "INCOMPLETE"
    if verifications:
        return "COMPLETE"
    raise ValueError(f"{case_id}: deletion request has no identity-linked evidence to evaluate")


def _matches_identifier(text: Any, identifier: str) -> bool:
    value = str(text or "")
    return bool(identifier) and re.search(rf"(?<![\w]){re.escape(identifier)}(?![\w])", value, re.IGNORECASE) is not None


def _conflicting_ocr_emails(ocr_text: str, identity_emails: set[str], resource_id: str) -> set[str]:
    """Find different emails in the OCR block belonging to this resource."""
    lines = ocr_text.splitlines()
    resource_pattern = re.compile(
        r"\b(?:data_flow|audit_record|customer_export|search|analytics|export|backup|marketing|"
        r"account|object|support|message|attachment|profile|tombstone|user|flow)_[-\w]+\b",
        re.IGNORECASE,
    )
    resource_lines = [
        (index, {value.casefold() for value in resource_pattern.findall(line)})
        for index, line in enumerate(lines)
    ]
    target = resource_id.strip().casefold()
    def same_resource(value: str) -> bool:
        return value == target or value.removeprefix("customer_") == target

    target_positions = [
        index for index, values in resource_lines
        if any(same_resource(value) for value in values)
        or _matches_identifier(lines[index], resource_id)
    ]
    if not target_positions:
        return set()

    email_lines = [
        (index, {
            value.casefold()
            for value in re.findall(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}", line)
        })
        for index, line in enumerate(lines)
    ]
    observed: set[str] = set()
    for position in target_positions:
        following = next(
            (index for index, values in resource_lines
             if index > position and any(not same_resource(value) for value in values)),
            len(lines),
        )
        start, stop = position, min(following, len(lines))
        nearby = [
            (index, addresses) for index, addresses in email_lines
            if start <= index < stop and addresses
        ]
        if nearby:
            nearest_distance = min(abs(index - position) for index, _ in nearby)
            if nearest_distance <= 12:
                observed.update(
                    address for index, addresses in nearby
                    if abs(index - position) == nearest_distance
                    for address in addresses
                )
    known = {value.strip().casefold() for value in identity_emails if value.strip()}
    return {
        address for address in observed
        if not any(address.endswith(email) for email in known)
    }


def _fact_matches_identity(fact: Mapping[str, Any], identifiers: set[str], resources: set[str]) -> bool:
    resource = str(_value(fact, "resource_id", "flow_id", "backup_id", default=""))
    matched_value = _value(fact, "identifiers_matched", default=[])
    values = matched_value if isinstance(matched_value, (list, tuple, set)) else [matched_value]
    matched = {str(value) for value in values if str(value).strip()}
    # Never let a parser result with no identity scope leak into every case.
    # Such facts are useful only when the case's activity trace independently
    # names the exact same concrete resource.
    return bool(identifiers.intersection(matched)) or bool(resource and resource in resources)


def _latest_facts(values: list[dict[str, Any]], resource_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Select one conservative, latest fact for each system/resource pair.

    A positive record in any evidence source wins over a negative lookup from a
    different source. This keeps a clean primary snapshot from hiding a copy
    that is still present in a replica or archive, while avoiding duplicate
    output steps for the same concrete resource.
    """
    selected: dict[tuple[str, str], tuple[int, int, pd.Timestamp, int, dict[str, Any]]] = {}
    for index, value in enumerate(values):
        resource = str(_value(value, *resource_fields, default=""))
        system = str(_value(value, "system_id", default=""))
        if not resource or not system:
            continue
        timestamp_value = value.get("timestamp") or value.get("created_at") or value.get("_captured_at") or ""
        timestamp = pd.to_datetime(timestamp_value, errors="coerce", utc=True)
        if pd.isna(timestamp):
            timestamp = pd.Timestamp.min.tz_localize("UTC")
        key = (system, resource)
        state = str(_value(value, "record_state", "state", "status", default="")).upper()
        positive = int(state in {"PRESENT", "ACTIVE", "ENABLED", "IDENTIFIABLE", "FOUND"})
        source_path = str(_value(value, "source_path", default="")).casefold()
        source_priority = 3 if "customer_accounts_" in source_path else 2 if "customer_data_inventory" in source_path else 1
        previous = selected.get(key)
        if previous is None or (positive, source_priority, timestamp, index) >= (previous[0], previous[1], previous[2], previous[3]):
            selected[key] = (positive, source_priority, timestamp, index, value)
    return [entry[4] for entry in selected.values()]


def evaluate_case(
    request: Mapping[str, Any],
    identity: Mapping[str, Any] | None,
    activity: Any,
    evidence_facts: Mapping[Any, Mapping[str, Any]],
    rules_dict: Mapping[str, str],
    audit_at: str | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Return the case status and ordered-independent finding/remediation steps."""
    request_text = str(_value(request, "request_text", "text", "description", default=""))
    if not _authorizes_deletion(request_text):
        return "NOT_APPLICABLE", []
    case_id = str(_value(request, "case_id", "request_id", "id", default="<unknown>"))
    if identity is None:
        raise ValueError(f"{case_id}: deletion request could not be resolved to a known identity")

    identifiers = {str(item) for values in identity.values() for item in (values if isinstance(values, (list, set, tuple)) else [values]) if item is not None}
    activity_rows = _rows(activity)
    if audit_at:
        time_candidates = ("timestamp", "event_at", "event_time", "activity_at", "created_at")
        time_col = next((
            key for key in time_candidates
            if any(
                key in row and pd.notna(pd.to_datetime(row.get(key), errors="coerce", utc=True))
                for row in activity_rows
            )
        ), None)
        if time_col:
            cutoff = pd.Timestamp(audit_at)
            activity_rows = [row for row in activity_rows if pd.notna(pd.to_datetime(row.get(time_col), errors="coerce", utc=True)) and pd.to_datetime(row.get(time_col), errors="coerce", utc=True) <= (cutoff.tz_localize("UTC") if cutoff.tzinfo is None else cutoff)]
    relevant_resources = {
        str(_value(row, "resource_id", "resource", default=""))
        for row in activity_rows
        if str(_value(row, "_case_linked", default="")).strip().casefold() in {"true", "1", "yes"}
        or any(_matches_identifier(value, identifier) for value in row.values() for identifier in identifiers if identifier)
    }
    relevant_activity = [row for row in activity_rows if str(_value(row, "resource_id", "resource", default="")) in relevant_resources]
    # If a trusted identity-link event and an in-scope screenshot mention the
    # same resource but the screenshot exposes a different email, do not choose
    # whichever source happens to sort last. Stop for explicit review.
    linked_resources = {
        str(_value(row, "resource_id", "resource", default="")).strip().casefold()
        for row in relevant_activity
        if str(_value(row, "action", "event_type", default="")).upper() == "LINK_RESOURCE_IDENTITY"
    }
    identity_emails = {
        str(value).strip().casefold()
        for value in (identity.get("emails", set()) if identity else set())
        if str(value).strip()
    }
    identity_link_times: dict[str, pd.Timestamp] = {}
    for row in relevant_activity:
        if str(_value(row, "action", "event_type", default="")).upper() != "LINK_RESOURCE_IDENTITY":
            continue
        resource = str(_value(row, "resource_id", "resource", default="")).strip().casefold()
        event_time = pd.to_datetime(
            _value(row, "timestamp", "event_time", "event_at", "created_at", default=""),
            errors="coerce",
            utc=True,
        )
        if resource and pd.notna(event_time) and (
            resource not in identity_link_times or event_time > identity_link_times[resource]
        ):
            identity_link_times[resource] = event_time
    for bundle in evidence_facts.values():
        ocr_text = str(bundle.get("ocr_text", "")).casefold()
        if not ocr_text:
            continue
        captured_at = pd.to_datetime(bundle.get("_ocr_captured_at", ""), errors="coerce", utc=True)
        for resource in linked_resources:
            if not resource or not _matches_identifier(ocr_text, resource):
                continue
            linked_at = identity_link_times.get(resource)
            # A later catalog link may legitimately reassign a resource after
            # an older screenshot was captured. Compare snapshots at a common
            # point in time before treating their owners as contradictory.
            if pd.notna(captured_at) and linked_at is not None and captured_at < linked_at:
                continue
            conflicting_emails = _conflicting_ocr_emails(ocr_text, identity_emails, resource)
            if conflicting_emails:
                raise ValueError(
                    f"{case_id}: NEEDS_REVIEW: identity-link evidence conflicts with OCR identity for resource {resource}"
                )
    all_records: list[dict[str, Any]] = []
    all_flows: list[dict[str, Any]] = []
    all_risks: list[dict[str, Any]] = []
    evidence_ids: dict[int, Any] = {}
    for evidence_id, facts in evidence_facts.items():
        records = facts.get("records_found", []) or []
        flows = facts.get("data_flows_found", []) or []
        risks = facts.get("restore_risks_found", []) or []
        for record in records:
            entry = dict(record)
            entry.setdefault("evidence_id", evidence_id)
            all_records.append(entry)
        all_flows.extend(dict(flow, evidence_id=flow.get("evidence_id", evidence_id)) for flow in flows)
        all_risks.extend(dict(risk, evidence_id=risk.get("evidence_id", evidence_id)) for risk in risks)

    # Cross-reference a catalog identity link with an in-scope object-storage
    # screenshot by filename. This recovers resource IDs that the UI omits from
    # the visible row while requiring both sources to agree on the filename and
    # numeric object suffix.
    for row in relevant_activity:
        if str(_value(row, "action", "event_type", default="")).upper() != "LINK_RESOURCE_IDENTITY":
            continue
        resource = str(_value(row, "resource_id", "resource", default="")).strip()
        system = str(_value(row, "system_id", "target_system", default="")).strip()
        details = str(_value(row, "details", "description", default=""))
        object_match = re.fullmatch(r"object_(\d+)", resource, re.IGNORECASE)
        filenames = {name.casefold() for name in re.findall(r"[\w.-]+\.pdf", details, re.IGNORECASE)}
        if not object_match or system.casefold() != "object_storage" or not filenames:
            continue
        suffix = object_match.group(1).lstrip("0") or "0"
        for evidence_id, bundle in evidence_facts.items():
            ocr_text = str(bundle.get("ocr_text", ""))
            if not ocr_text or not any(name in ocr_text.casefold() for name in filenames):
                continue
            if not re.search(rf"(?:delivery_confirmation|customer_export|invoice|return_label)_{re.escape(suffix)}\.pdf\b", ocr_text, re.IGNORECASE):
                continue
            all_records.append({
                "evidence_id": evidence_id,
                "system_id": "object_storage",
                "resource_id": resource,
                "data_category": "SUPPORT_ATTACHMENT",
                "record_state": "PRESENT",
                "identifiers_matched": sorted(identifiers),
                "source_path": "object_storage_catalog_and_screenshot",
            })
            break

    if audit_at:
        cutoff_timestamp = pd.to_datetime(audit_at, errors="coerce", utc=True)
        if pd.notna(cutoff_timestamp):
            def observed_by_cutoff(fact: Mapping[str, Any]) -> bool:
                observed = _value(fact, "timestamp", "observed_at", "created_at", "_captured_at", default="")
                if not str(observed).strip():
                    return True
                observed_at = pd.to_datetime(observed, errors="coerce", utc=True)
                return bool(pd.isna(observed_at) or observed_at <= cutoff_timestamp)

            all_records = [fact for fact in all_records if observed_by_cutoff(fact)]
            all_flows = [fact for fact in all_flows if observed_by_cutoff(fact)]
            all_risks = [fact for fact in all_risks if observed_by_cutoff(fact)]

    request_mentions_analytics_linkability = (
        "analytic" in request_text.casefold()
        and any(term in request_text.casefold() for term in ("anonymous", "anonymized", "anonymised", "point back", "link back", "identify me", "identify the user"))
    )
    scoped_analytics_records = [
        record for record in all_records
        if str(_value(record, "verification_scope", default="")) == "system_level_analytics_anonymization"
        and str(_value(record, "system_id", default="")) == "analytics_platform"
        and str(_value(record, "record_state", "state", default="")).upper() == "ANONYMIZED"
    ]
    # System-level checks use only the newest analytics identity snapshot
    # available at this request's audit cutoff, avoiding stale/duplicate rows
    # from historical report exports.
    latest_scope_capture = max(
        (pd.to_datetime(record.get("_captured_at"), errors="coerce", utc=True) for record in scoped_analytics_records),
        default=pd.NaT,
    )
    if pd.notna(latest_scope_capture):
        scoped_analytics_records = [
            record for record in scoped_analytics_records
            if pd.to_datetime(record.get("_captured_at"), errors="coerce", utc=True) == latest_scope_capture
        ]
    scoped_analytics_resources = {str(record.get("resource_id", "")) for record in scoped_analytics_records}
    all_records = [
        record for record in _latest_facts(all_records, ("resource_id",))
        if _fact_matches_identity(record, identifiers, relevant_resources)
        or (
            request_mentions_analytics_linkability
            and str(_value(record, "verification_scope", default="")) == "system_level_analytics_anonymization"
            and str(_value(record, "system_id", default="")) == "analytics_platform"
            and str(_value(record, "record_state", "state", default="")).upper() == "ANONYMIZED"
            and str(_value(record, "resource_id", default="")) in scoped_analytics_resources
        )
    ]
    all_flows = [flow for flow in _latest_facts(all_flows, ("flow_id", "resource_id")) if _fact_matches_identity(flow, identifiers, relevant_resources)]
    all_risks = [risk for risk in _latest_facts(all_risks, ("backup_id", "resource_id")) if _fact_matches_identity(risk, identifiers, relevant_resources)]

    # An absence observed in one snapshot cannot cancel a present copy in a
    # different evidence source. Keep the finding so a replica or archive can
    # never be hidden by a clean lookup from another store.
    present_resources = {
        (str(_value(record, "system_id", default="")), str(_value(record, "resource_id", default="")))
        for record in all_records
        if str(_value(record, "record_state", "state", default="")).upper() == "PRESENT"
    }
    all_records = [
        record for record in all_records
        if str(_value(record, "record_state", "state", default="")).upper() != "ABSENT"
        or (str(_value(record, "system_id", default="")), str(_value(record, "resource_id", default=""))) not in present_resources
    ]

    steps: list[dict[str, Any]] = []
    for record in all_records:
        resource = str(_value(record, "resource_id", default=""))
        category = str(_value(record, "data_category", default="UNMAPPED")).upper()
        treatment = str(rules_dict.get(category, "UNMAPPED")).upper()
        state = str(_value(record, "record_state", "state", default="PRESENT")).upper()
        system = _value(record, "system_id", default="")
        raw_tombstone = _value(record, "is_tombstone", default=False)
        is_tombstone = raw_tombstone if isinstance(raw_tombstone, bool) else str(raw_tombstone).strip().casefold() in {"1", "true", "yes", "y", "on"}
        matched_value = _value(record, "identifiers_matched", default=[])
        matched_identifiers = {str(value) for value in (matched_value if isinstance(matched_value, (list, tuple, set)) else [matched_value]) if str(value).strip()}
        direct_identifiers = {
            str(value)
            for field in ("emails", "phones", "email_hashes", "names")
            for value in (identity.get(field, set()) if isinstance(identity.get(field, set()), (list, tuple, set)) else [identity.get(field)])
            if value is not None and str(value).strip()
        }
        identifiable_sensitive_record = (
            state == "PRESENT"
            and category in {"ANALYTICS_PROFILE", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "PRODUCT_TELEMETRY"}
            and bool(_value(record, "has_exposed_pii", default=False))
        )
        evidence_id = record.get("evidence_id", "")
        if not str(system).strip() or not resource.strip():
            continue
        if state == "PRESENT" and (is_tombstone or identifiable_sensitive_record):
            finding_step = _step("FINDING", "REPORT_EXPOSED_PII", system, resource, evidence_id=evidence_id, state="PRESENT")
            # Tombstones with identifying values must be redacted. Other PII
            # findings still follow the category's supplied policy: for
            # example, analytics profiles are anonymized, while support text
            # is redacted and ordinary account records are deleted.
            pii_treatment = "REDACT" if is_tombstone else treatment
            if pii_treatment in {"DELETE", "REDACT", "ANONYMIZE"}:
                rem_operation = {"DELETE": "DELETE_RECORD", "REDACT": "REDACT_RECORD", "ANONYMIZE": "ANONYMIZE_RECORD"}[pii_treatment]
                rem_state = {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED"}[rem_operation]
                verify_operation = {"ABSENT": "VERIFY_RECORD_ABSENT", "REDACTED": "VERIFY_RECORD_REDACTED", "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED"}[rem_state]
                steps.extend([
                    finding_step,
                    _step("REMEDIATION", rem_operation, system, resource, state=rem_state),
                    _step("VERIFICATION", verify_operation, system, resource, state=rem_state),
                ])
            else:
                steps.extend([
                    finding_step,
                    _step("VERIFICATION", "VERIFY_RECORD_PRESENT", system, resource, evidence_id=evidence_id, state="PRESENT"),
                ])
        elif state == "PRESENT" and treatment in {"DELETE", "REDACT", "ANONYMIZE"}:
            finding_step = _step("FINDING", "REPORT_REMAINING_RECORD", system, resource, evidence_id=evidence_id, state=state)
            rem_operation = {"DELETE": "DELETE_RECORD", "REDACT": "REDACT_RECORD", "ANONYMIZE": "ANONYMIZE_RECORD"}[treatment]
            rem_state = {"DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED"}[rem_operation]
            verify_operation = {"ABSENT": "VERIFY_RECORD_ABSENT", "REDACTED": "VERIFY_RECORD_REDACTED", "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED"}[rem_state]
            steps.extend([
                finding_step,
                _step("REMEDIATION", rem_operation, system, resource, state=rem_state),
                _step("VERIFICATION", verify_operation, system, resource, state=rem_state),
            ])
        elif state == "PRESENT" and treatment == "RETAIN":
            steps.append(_step("VERIFICATION", "VERIFY_RECORD_PRESENT", system, resource, evidence_id=evidence_id, state="PRESENT"))
        elif state in {"ABSENT", "REDACTED", "ANONYMIZED"}:
            verify_op = {"ABSENT": "VERIFY_RECORD_ABSENT", "REDACTED": "VERIFY_RECORD_REDACTED", "ANONYMIZED": "VERIFY_RECORD_ANONYMIZED"}[state]
            steps.append(_step("VERIFICATION", verify_op, system, resource, evidence_id=evidence_id, state=state))
        elif state == "PRESENT":
            steps.extend([
                _step("FINDING", "REPORT_UNMAPPED_CATEGORY", system, resource, evidence_id=evidence_id, state="PRESENT"),
                _step("VERIFICATION", "VERIFY_RECORD_PRESENT", system, resource, evidence_id=evidence_id, state="PRESENT"),
            ])
    for row in relevant_activity:
        action = str(_value(row, "action", "activity_type", "event_type", "operation", default="")).upper()
        if any(term in action for term in {"SYNC", "IMPORT", "EXPORT"}) and str(_value(row, "status", "state", "reported_result", default="ACTIVE")).upper() not in {"DISABLED", "INACTIVE", "FAILED", "BLOCKED"}:
            system = _value(row, "system_id", default="")
            resource = _value(row, "resource_id", default="")
            finding = _step("FINDING", "REPORT_ACTIVE_DATA_FLOW", system, resource, evidence_id="", state="ACTIVE")
            if not str(system).strip() or not str(resource).strip():
                continue
            steps.extend([finding, _step("REMEDIATION", "DISABLE_DATA_FLOW", system, resource, state="DISABLED"), _step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", system, resource, state="DISABLED")])
        resource = str(_value(row, "resource_id", "resource", default="")).strip()
        details = str(_value(row, "details", "description", default="")).casefold()
        if action in {"CHECK_DATA_FLOW", "CHECK_SYNC_STATUS"} and resource and not any(str(_value(flow, "flow_id", "resource_id", default="")) == resource for flow in all_flows):
            system = str(_value(row, "system_id", "target_system", default="integration_service")) or "integration_service"
            if any(term in details for term in ("enabled", "active", "running", "remains on")):
                steps.extend([
                    _step("FINDING", "REPORT_ACTIVE_DATA_FLOW", system, resource, evidence_id="", state="ACTIVE"),
                    _step("REMEDIATION", "DISABLE_DATA_FLOW", system, resource, state="DISABLED"),
                    _step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", system, resource, state="DISABLED"),
                ])
            elif any(term in details for term in ("disabled", "inactive", "stopped")):
                steps.append(_step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", system, resource, evidence_id="", state="DISABLED"))
        if action in {"CHECK_RESTORE_ACCESS", "RESTORE_POLICY_CHECK"} and resource and not any(str(_value(risk, "backup_id", "resource_id", default="")) == resource for risk in all_risks):
            system = str(_value(row, "system_id", "target_system", default="backup_service")) or "backup_service"
            if any(term in details for term in ("can still be restored", "restore allowed", "restore enabled", "restorable")):
                steps.extend([
                    _step("FINDING", "REPORT_RESTORE_RISK", system, resource, evidence_id="", state="ACTIVE"),
                    _step("REMEDIATION", "BLOCK_RESTORE", system, resource, state="BLOCKED"),
                    _step("VERIFICATION", "VERIFY_RESTORE_BLOCKED", system, resource, state="BLOCKED"),
                ])
            elif any(term in details for term in ("blocked", "cannot be restored", "restore disabled")):
                steps.append(_step("VERIFICATION", "VERIFY_RESTORE_BLOCKED", system, resource, evidence_id="", state="BLOCKED"))
    for flow in all_flows:
        system = _value(flow, "system_id", default="")
        flow_id = _value(flow, "flow_id", "resource_id", default="")
        status = str(_value(flow, "status", default="UNKNOWN")).upper()
        if not str(system).strip() or not str(flow_id).strip():
            continue
        if status in {"ACTIVE", "ENABLED", "PRESENT"}:
            finding = _step("FINDING", "REPORT_ACTIVE_DATA_FLOW", system, flow_id, evidence_id=flow.get("evidence_id", ""), state="ACTIVE")
            steps.extend([finding, _step("REMEDIATION", "DISABLE_DATA_FLOW", system, flow_id, state="DISABLED"), _step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", system, flow_id, state="DISABLED")])
        elif status in {"INACTIVE", "DISABLED", "STOPPED", "BLOCKED"}:
            steps.append(_step("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", system, flow_id, evidence_id=flow.get("evidence_id", ""), state="DISABLED"))
    for risk in all_risks:
        system = _value(risk, "system_id", default="")
        backup = _value(risk, "backup_id", "resource_id", default="")
        if not str(system).strip() or not str(backup).strip():
            continue
        allowed = _value(risk, "restore_allowed", default=None)
        risk_status = str(_value(risk, "status", "state", default="ACTIVE")).upper()
        if allowed is not None:
            risk_status = "ACTIVE" if (allowed if isinstance(allowed, bool) else str(allowed).strip().casefold() in {"1", "true", "yes", "on"}) else "BLOCKED"
        if risk_status in {"ACTIVE", "PRESENT", "ENABLED"}:
            finding = _step("FINDING", "REPORT_RESTORE_RISK", system, backup, evidence_id=risk.get("evidence_id", ""), state="ACTIVE")
            steps.extend([finding, _step("REMEDIATION", "BLOCK_RESTORE", system, backup, state="BLOCKED"), _step("VERIFICATION", "VERIFY_RESTORE_BLOCKED", system, backup, state="BLOCKED")])
        elif risk_status in {"BLOCKED", "DISABLED", "INACTIVE"}:
            steps.append(_step("VERIFICATION", "VERIFY_RESTORE_BLOCKED", system, backup, evidence_id=risk.get("evidence_id", ""), state="BLOCKED"))

    # Repeated identifier hits in nested exports often describe the same source
    # record. Keep one action for each distinct phase, operation, resource, and
    # evidence citation.
    unique_steps: dict[tuple[str, ...], dict[str, Any]] = {}
    for step in steps:
        key = tuple(str(step.get(field, "")) for field in ("phase", "operation", "system_id", "resource_id", "state", "evidence_id"))
        unique_steps.setdefault(key, step)
    steps = list(unique_steps.values())

    if not steps:
        # Do not turn an ungrounded follow-up query into a deletion finding.
        # A verification-only INCOMPLETE result is structurally misleading and
        # cannot satisfy the output contract. The caller must surface the case
        # for repair instead of serializing an orphan verification.
        raise ValueError(
            f"{case_id}: no identity-linked finding was extracted; refusing to emit an INCOMPLETE case with orphan verification steps"
        )

    return _status_from_steps(case_id, steps), steps


class RuleEngine:
    """Deterministic policy and status engine for a single deletion request."""

    def __init__(self, rules_dict: Mapping[str, str]) -> None:
        self.rules_dict = rules_dict

    def evaluate(
        self,
        request: Mapping[str, Any],
        identity: Mapping[str, Any] | None,
        activity: Any,
        evidence_facts: Mapping[Any, Mapping[str, Any]],
        *,
        audit_at: str | None = None,
    ) -> tuple[str, list[dict[str, Any]]]:
        return evaluate_case(
            request, identity, activity, evidence_facts, self.rules_dict, audit_at=audit_at
        )
