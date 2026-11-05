"""Fast unit tests for core privacy-pipeline business rules."""

from __future__ import annotations

import json
import importlib.util
import sqlite3
from pathlib import Path
import sys
from typing import Any

import pandas as pd
import pytest
from pydantic import ValidationError

from models import AuditResult, build_with_retry
from main import _case_activity


def _load_numbered_module(name: str, filename: str) -> Any:
    path = Path(__file__).resolve().parents[1] / "src" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


normalizer = _load_numbered_module("test_normalizer", "07_normalizer.py")
query_audit = _load_numbered_module("test_query_audit", "08_query_audit.py")

def _record(*, resource: str, category: str, state: str, user_id: str = "user_test") -> dict[str, Any]:
    return {
        "system_id": "account_service",
        "resource_id": resource,
        "data_category": category,
        "record_state": state,
        "identifiers_matched": [user_id],
    }


@pytest.mark.validation
def test_incomplete_without_verification_raises_validation_error() -> None:
    with pytest.raises(ValidationError, match="requires at least one verification step"):
        AuditResult.build(case_id="case_bad", deletion_status="INCOMPLETE", steps=[])


@pytest.mark.validation
def test_incomplete_requires_finding_and_verification() -> None:
    finding = {
        "step_no": 1,
        "phase": "FINDING",
        "system_id": "account_service",
        "resource_id": "account_test",
        "operation": "REPORT_REMAINING_RECORD",
        "state": "PRESENT",
        "evidence_id": "evidence_1",
    }
    check = {
        "step_no": 2,
        "phase": "VERIFICATION",
        "system_id": "account_service",
        "resource_id": "account_test",
        "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT",
        "evidence_id": "",
    }
    result = AuditResult.build(case_id="case_ok", deletion_status="INCOMPLETE", steps=[finding, check])
    assert result.verification_steps == [result.steps[1]]
    assert "verification_steps" not in result.model_dump()


@pytest.mark.validation
def test_incomplete_with_only_verification_raises_validation_error() -> None:
    check = {
        "step_no": 1, "phase": "VERIFICATION", "system_id": "account_service",
        "resource_id": "account_test", "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT", "evidence_id": "",
    }
    with pytest.raises(ValidationError, match="requires at least one identity-linked finding"):
        AuditResult.build(case_id="case_orphan", deletion_status="INCOMPLETE", steps=[check])


@pytest.mark.validation
def test_invalid_result_retries_then_accepts_repaired_output() -> None:
    calls = 0
    valid_steps = [
        {"step_no": 1, "phase": "FINDING", "system_id": "account_service",
        "resource_id": "account_test", "operation": "REPORT_REMAINING_RECORD",
        "state": "PRESENT", "evidence_id": "evidence_1"},
        {"step_no": 2, "phase": "VERIFICATION", "system_id": "account_service",
        "resource_id": "account_test", "operation": "VERIFY_RECORD_ABSENT",
        "state": "ABSENT", "evidence_id": ""},
    ]

    def generate() -> tuple[str, list[dict[str, Any]]]:
        nonlocal calls
        calls += 1
        return ("INCOMPLETE", []) if calls == 1 else ("INCOMPLETE", valid_steps)

    result = build_with_retry(case_id="case_retry", generate=generate, max_attempts=2)
    assert calls == 2
    assert result.deletion_status == "INCOMPLETE"


@pytest.mark.validation
def test_invalid_operation_state_raises_validation_error() -> None:
    bad_step = {
        "step_no": 1, "phase": "FINDING", "system_id": "account_service",
        "resource_id": "account_test", "operation": "REPORT_REMAINING_RECORD",
        "state": "ABSENT", "evidence_id": "evidence_1",
    }
    with pytest.raises(ValidationError, match="Invalid state"):
        AuditResult.build(case_id="case_bad_state", deletion_status="INCOMPLETE", steps=[bad_step])


@pytest.mark.validation
def test_complete_result_requires_evidence_backed_verification() -> None:
    with pytest.raises(ValidationError, match="requires evidence-backed verification"):
        AuditResult.build(case_id="case_unproven", deletion_status="COMPLETE", steps=[])


@pytest.mark.sequencing
def test_happy_path_step_sequence_is_deterministic(
    evaluator: Any, step_sorter: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    facts = {
        "e_record": {"records_found": [_record(resource="search_1", category="SEARCH_INDEX_ENTRY", state="PRESENT")]},
        "e_flow": {"data_flows_found": [{"flow_id": "sync_1", "system_id": "integration_service", "status": "ACTIVE", "identifiers_matched": ["user_test"]}]},
        "e_backup": {"restore_risks_found": [{"backup_id": "backup_1", "system_id": "backup_service", "identifiers_matched": ["user_test"]}]},
    }
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [], facts,
        {"SEARCH_INDEX_ENTRY": "DELETE"}, audit_at="2026-09-01T00:00:00Z",
    )
    ordered = step_sorter.number_steps(step_sorter.sort_steps(steps))
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in ordered] == [
        "REPORT_REMAINING_RECORD", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
        "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
        "VERIFY_RECORD_ABSENT", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    ]
    assert [step["step_no"] for step in ordered] == list(range(1, 10))


@pytest.mark.business
def test_no_evidence_fails_closed_without_orphan_verification(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    with pytest.raises(ValueError, match="no identity-linked finding was extracted"):
        evaluator.evaluate_case(
            request_payload, identity_payload, [], {}, {}, audit_at="2026-09-01T00:00:00Z"
        )


@pytest.mark.parametrize(
    ("category", "state", "policy", "expected_status", "expected_operation"),
    [
        ("USER_PROFILE", "ABSENT", "DELETE", "COMPLETE", "VERIFY_RECORD_ABSENT"),
    ],
    ids=["standard-record-deleted"],
)
@pytest.mark.business
def test_policy_decisions_are_deterministic(
    evaluator: Any,
    request_payload: dict[str, str],
    identity_payload: dict[str, set[str]],
    category: str,
    state: str,
    policy: str,
    expected_status: str,
    expected_operation: str,
) -> None:
    evidence = {"e_policy": {"records_found": [_record(resource="resource_1", category=category, state=state)]}}
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [], evidence, {category: policy}, audit_at="2026-09-01T00:00:00Z"
    )
    assert status == expected_status
    assert [step["operation"] for step in steps] == [expected_operation]


@pytest.mark.business
def test_legal_hold_is_preserved_while_other_data_remains_incomplete(
    evaluator: Any,
    request_payload: dict[str, str],
    identity_payload: dict[str, set[str]],
) -> None:
    evidence = {
        "e_policy": {
            "records_found": [
                _record(resource="ledger_1", category="LEGAL_HOLD_RECORD", state="PRESENT"),
                _record(resource="profile_1", category="USER_PROFILE", state="PRESENT"),
            ]
        }
    }
    status, steps = evaluator.evaluate_case(
        request_payload,
        identity_payload,
        [],
        evidence,
        {"LEGAL_HOLD_RECORD": "RETAIN", "USER_PROFILE": "DELETE"},
        audit_at="2026-09-01T00:00:00Z",
    )
    assert status == "INCOMPLETE"  # Contract equivalent of partial deletion.
    assert any(
        step["operation"] == "VERIFY_RECORD_PRESENT" and step["resource_id"] == "ledger_1"
        for step in steps
    )
    assert any(step["operation"] == "DELETE_RECORD" and step["resource_id"] == "profile_1" for step in steps)


@pytest.mark.business
def test_evidence_normalizer_standardizes_system_and_state() -> None:
    result = normalizer.normalize_evidence({
        "evidence_1": {"records_found": [{
            "resource": "search_001", "state": "FOUND", "category": "SEARCH_INDEX_ENTRY",
            "identifiers_matched": "user_test",
        }]}
    })
    record = result["evidence_1"]["records_found"][0]
    assert record["system_id"] == "search_service"
    assert record["record_state"] == "PRESENT"
    assert record["identifiers_matched"] == ["user_test"]


@pytest.mark.parametrize(
    "request_text",
    [
        "I'm deleting my account.",
        "Please check my data before deleting it.",
        "I want to close this account permanently.",
        "Please confirm the prior deletion of my account.",
        "Je demande la suppression définitive du compte associé à cette adresse.",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
    ],
)
@pytest.mark.business
def test_intent_classifier_accepts_implicit_prior_and_japanese_deletion(
    evaluator: Any, request_text: str
) -> None:
    assert evaluator._authorizes_deletion(request_text) is True


@pytest.mark.parametrize(
    "request_text",
    [
        "Please stop the promotional emails. I still need the account and my order history, so I am not asking for deletion.",
        "My surname is misspelled on the account. Can you correct it without removing any of my records?",
        "Please remove me from marketing lists only. I still want receipts and service messages for this account.",
        "Can you tell me what personal information you hold about me? This is an information request, not a request to erase it.",
    ],
    ids=["explicit-no-deletion", "correction-only", "marketing-only", "access-not-erasure"],
)
@pytest.mark.business
def test_intent_classifier_rejects_non_deletion_requests(evaluator: Any, request_text: str) -> None:
    assert evaluator._authorizes_deletion(request_text) is False


@pytest.mark.parametrize(
    "request_text",
    [
        "Please delete my account and unsubscribe me from marketing emails.",
        "Please delete my account without removing my order history.",
    ],
    ids=["deletion-plus-unsubscribe", "deletion-with-retained-history"],
)
@pytest.mark.business
def test_explicit_deletion_remains_authorized_with_other_preferences(
    evaluator: Any, request_text: str
) -> None:
    assert evaluator._authorizes_deletion(request_text) is True


@pytest.mark.business
def test_concrete_negative_lookup_proves_completion(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    evidence = {
        "evidence_404": {
            "records_found": [{
                **_record(resource="account_001", category="USER_PROFILE", state="ABSENT"),
                "fact_type": "negative_lookup",
                "evidence_id": "evidence_404",
            }]
        }
    }
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [], evidence, {"USER_PROFILE": "DELETE"}
    )
    assert status == "COMPLETE"
    assert steps == [{
        "phase": "VERIFICATION", "operation": "VERIFY_RECORD_ABSENT",
        "system_id": "account_service", "resource_id": "account_001",
        "evidence_id": "evidence_404", "state": "ABSENT",
    }]


@pytest.mark.business
def test_absence_in_one_snapshot_cannot_hide_a_present_copy(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    evidence = {
        "evidence_replica": {"records_found": [
            _record(resource="account_001", category="USER_PROFILE", state="PRESENT")
        ]},
        "evidence_primary": {"records_found": [{
            **_record(resource="account_001", category="USER_PROFILE", state="ABSENT"),
            "fact_type": "negative_lookup",
        }]},
    }
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [], evidence, {"USER_PROFILE": "DELETE"}
    )
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in steps] == [
        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
    ]


@pytest.mark.business
def test_unknown_policy_is_reviewed_instead_of_deleted(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    evidence = {"e_unknown": {"records_found": [
        _record(resource="mystery_1", category="UNMAPPED", state="PRESENT")
    ]}}
    status, steps = evaluator.evaluate_case(request_payload, identity_payload, [], evidence, {})
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in steps] == [
        "REPORT_UNMAPPED_CATEGORY", "VERIFY_RECORD_PRESENT"
    ]


@pytest.mark.business
def test_normalizer_preserves_tombstone_as_exposed_pii() -> None:
    result = normalizer.normalize_evidence({"e_tomb": {"records_found": [{
        "system_id": "identity_service", "resource_id": "tombstone_9",
        "data_category": "ACCOUNT_TOMBSTONE", "record_state": "DELETED",
        "is_tombstone": "true", "email": "person@example.test",
        "identifiers_matched": ["user_test"],
    }]}})
    record = result["e_tomb"]["records_found"][0]
    assert record["is_tombstone"] is True
    assert record["record_state"] == "PRESENT"  # exposed PII overrides the generic deleted marker
    assert record["data_category"] == "ACCOUNT_TOMBSTONE"


@pytest.mark.business
def test_tombstone_creates_exposed_pii_finding_and_redaction(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    evidence = {"e_tomb": {"records_found": [
        _record(resource="tombstone_9", category="ACCOUNT_TOMBSTONE", state="PRESENT")
        | {"system_id": "identity_service", "is_tombstone": True, "evidence_id": "e_tomb"}
    ]}}
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [], evidence, {"ACCOUNT_TOMBSTONE": "REDACT"}
    )
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in steps] == [
        "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
    ]


@pytest.mark.business
def test_identifiable_analytics_pii_uses_anonymize_policy(
    evaluator: Any, request_payload: dict[str, str], identity_payload: dict[str, set[str]]
) -> None:
    record = _record(resource="analytics_1", category="ANALYTICS_PROFILE", state="PRESENT")
    record["identifiers_matched"] = ["user@example.test"]
    record["has_exposed_pii"] = True
    status, steps = evaluator.evaluate_case(
        request_payload, identity_payload, [],
        {"e_analytics": {"records_found": [record]}},
        {"ANALYTICS_PROFILE": "ANONYMIZE"},
    )
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in steps] == [
        "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"
    ]


@pytest.mark.business
def test_sql_parser_maps_data_flows_backups_and_unknown_categories() -> None:
    parser = _load_numbered_module("test_evidence_sql_categories", "03_evidence.py")
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        "CREATE TABLE customer_profiles (resource_id TEXT, email TEXT);"
        "INSERT INTO customer_profiles VALUES ('account_7', 'user_test');"
        "CREATE TABLE connector_subscriptions (resource_id TEXT, customer_email TEXT, enabled INTEGER, last_delivery_status TEXT);"
        "INSERT INTO connector_subscriptions VALUES ('data_flow_7', 'user_test', 1, 'delivered');"
        "CREATE TABLE backup_restore_entries (resource_id TEXT, customer_email TEXT, restore_allowed INTEGER);"
        "INSERT INTO backup_restore_entries VALUES ('backup_7', 'user_test', 0);"
        "CREATE TABLE mystery_records (resource_id TEXT, email TEXT);"
        "INSERT INTO mystery_records VALUES ('mystery_7', 'user_test');"
        "CREATE TABLE shadow_analytics_profiles (resource_id TEXT, email TEXT);"
        "INSERT INTO shadow_analytics_profiles VALUES ('shadow_7', 'user_test');"
    )
    facts = parser._sql_facts(connection, ["user_test"])
    assert next(row for row in facts["records_found"] if row["resource_id"] == "account_7")["data_category"] == "USER_PROFILE"
    assert next(row for row in facts["records_found"] if row["resource_id"] == "mystery_7")["data_category"] == "UNMAPPED"
    assert next(row for row in facts["records_found"] if row["resource_id"] == "shadow_7")["data_category"] == "UNMAPPED"
    assert facts["data_flows_found"][0]["status"] == "ACTIVE"
    assert facts["restore_risks_found"][0]["status"] == "BLOCKED"
    connection.close()


@pytest.mark.business
def test_pdf_text_parser_links_each_resource_to_identifiers_nearby() -> None:
    parser = _load_numbered_module("test_evidence_pdf_text", "03_evidence.py")
    facts = parser._parse_document_text(
        "Delivery correction support_001. Customer: Priya Raman. Email: priya@example.test. "
        "An unrelated file support_002 belongs to another contact.",
        "delivery_correction_attachment.pdf", ["priya@example.test"],
    )
    assert len(facts["records_found"]) == 1
    assert facts["records_found"][0]["resource_id"] == "support_001"
    assert facts["records_found"][0]["data_category"] == "SUPPORT_ATTACHMENT"


@pytest.mark.business
def test_structured_logs_emit_negative_lookup_and_system_mapping() -> None:
    parser = _load_numbered_module("test_evidence_structured", "03_evidence.py")
    facts = parser._parse_log_facts(
        "2026-09-01T10:00:00Z level=DEBUG service=account_service trace_id=t1 event=profile_lookup_started resource_id=account_9 lookup_key=user_test\n"
        "2026-09-01T10:00:01Z level=INFO service=account_service trace_id=t1 event=profile_lookup_completed resource_id=account_9 rows=0 http_status=404 lookup_key=user_test",
        ["user_test"],
    )
    record = facts["records_found"][0]
    assert record["record_state"] == "ABSENT"
    assert record["fact_type"] == "negative_lookup"
    assert record["resource_id"] == "account_9"
    assert record["system_id"] == "account_service"


@pytest.mark.business
def test_nested_message_logs_extract_resource_facts_and_request_id_traces() -> None:
    parser = _load_numbered_module("test_evidence_nested_message", "03_evidence.py")
    facts = parser._parse_log_facts(
        '2026-06-08T09:51:47Z requestId=tr-0310343 level=INFO function="support_platform" '
        'message="instance=\\"support-5\\" resource_id=\\"support_9996\\" '
        'event=\\"message_read\\" subject_ref=\\"user_262\\" message_text=\\"[REDACTED]\\""',
        ["user_262"],
    )
    assert len(facts["records_found"]) == 1
    record = facts["records_found"][0]
    assert record["resource_id"] == "support_9996"
    assert record["system_id"] == "support_platform"
    assert record["record_state"] == "REDACTED"
    assert record["identifiers_matched"] == ["user_262"]


@pytest.mark.business
def test_connector_screenshot_extracts_identity_linked_active_flow() -> None:
    parser = _load_numbered_module("test_evidence_ocr_flow", "03_evidence.py")
    flow = parser._ocr_data_flow_fact(
        "data_flow_1121 Status Healthy Owner Data Platform "
        "Selector jain.aditi@gmail.com Sync mode Continuous sync",
        ["jain.aditi@gmail.com"],
    )
    assert flow == {
        "flow_id": "data_flow_1121",
        "resource_id": "data_flow_1121",
        "system_id": "integration_service",
        "status": "ACTIVE",
        "identifiers_matched": ["jain.aditi@gmail.com"],
    }


@pytest.mark.business
def test_connector_screenshot_requires_identity_and_sync_context() -> None:
    parser = _load_numbered_module("test_evidence_ocr_flow_context", "03_evidence.py")
    assert parser._ocr_data_flow_fact(
        "data_flow_1121 Status Healthy Sync mode Continuous sync", ["other@example.test"]
    ) is None
    assert parser._ocr_data_flow_fact(
        "marketing_001 Status Healthy Selector person@example.test", ["person@example.test"]
    ) is None


@pytest.mark.business
def test_marketing_profile_ocr_maps_live_resource_to_present_record() -> None:
    parser = _load_numbered_module("test_evidence_ocr_marketing", "03_evidence.py")
    record = parser._ocr_record_fact(
        "Soo-jin Park\nmarketing_001-sj.park@naver.com\nLive\nEmail opt-in Yes",
        ["marketing_001", "sj.park@naver.com"],
    )
    assert record is not None
    assert record["system_id"] == "marketing_platform"
    assert record["resource_id"] == "marketing_001"
    assert record["data_category"] == "MARKETING_PROFILE"
    assert record["record_state"] == "PRESENT"


@pytest.mark.business
def test_pipe_and_syslog_records_link_subject_by_trace_id() -> None:
    parser = _load_numbered_module("test_evidence_trace_formats", "03_evidence.py")
    pipe = parser._parse_log_facts(
        "2026-02-03T05:57:41Z | DEBUG | security_service | tr-1 | audit_record_query_started | subject_ref=\"user_511\"\n"
        "2026-02-03T05:57:45Z | DEBUG | security_service | tr-1 | audit_record_read_completed | resource_id=\"audit_record_2044\" rows=\"1\"",
        ["user_511"],
    )
    assert any(row["resource_id"] == "audit_record_2044" for row in pipe["records_found"])
    syslog = parser._parse_log_facts(
        '2026-03-25T08:57:00Z <15>1 node-3 security_service tr-2 - - level=DEBUG event="audit_record_query_started" subject_ref="user_414"\n'
        '2026-03-25T08:57:06Z <15>1 node-3 security_service tr-2 - - level=DEBUG resource_id="audit_record_8832" event="audit_record_read_completed" rows="1"',
        ["user_414"],
    )
    assert any(row["resource_id"] == "audit_record_8832" for row in syslog["records_found"])


@pytest.mark.business
def test_json_log_emits_connector_and_blocked_backup_facts() -> None:
    parser = _load_numbered_module("test_evidence_json_log", "03_evidence.py")
    facts = parser._parse_log_facts(
        '2026-09-01T10:00:00Z {"service":"integration_service","trace_id":"f1","event":"connector_config_read_completed","resource_id":"data_flow_9","lookup_key":"user_test","enabled":false}\n'
        '2026-09-01T10:00:01Z {"service":"backup_service","trace_id":"b1","event":"restore_policy_read_completed","resource_id":"backup_9","lookup_key":"user_test","restore_allowed":false}',
        ["user_test"],
    )
    assert facts["data_flows_found"][0]["status"] == "DISABLED"
    assert facts["restore_risks_found"][0]["status"] == "BLOCKED"


@pytest.mark.business
def test_pipe_handover_emits_resource_facts_and_flows() -> None:
    parser = _load_numbered_module("test_evidence_pipe", "03_evidence.py")
    facts = parser._parse_pipe_log_facts(
        "- 2026-09-01T10:00:00Z | integration_service | data_flow_9 | DATA_FLOW | ACTIVE | user_test\n"
        "- 2026-09-01T10:00:01Z | account_service | account_9 | USER_PROFILE | NOT_FOUND | user_test",
        ["user_test"],
    )
    assert facts["data_flows_found"][0]["status"] == "ACTIVE"
    assert facts["records_found"][0]["fact_type"] == "negative_lookup"
    assert facts["records_found"][0]["resource_id"] == "account_9"


@pytest.mark.business
def test_ocr_email_with_resource_prefix_matches_known_identity(evaluator: Any) -> None:
    observed = evaluator._conflicting_ocr_emails(
        "user_20-analytics_7438-darwish.omar@icloud.com",
        {"darwish.omar@icloud.com"},
        "analytics_7438",
    )
    assert observed == set()


@pytest.mark.business
def test_ocr_email_conflict_remains_visible(evaluator: Any) -> None:
    observed = evaluator._conflicting_ocr_emails(
        "marketing_001-sj.park@naver.com",
        {"kwame-mensah@proton.me"},
        "marketing_001",
    )
    assert observed == {"marketing_001-sj.park@naver.com"}


@pytest.mark.business
def test_conflicting_resource_owner_is_held_for_review(
    evaluator: Any, request_payload: dict[str, str]
) -> None:
    request = {**request_payload, "case_id": "case_review"}
    identity = {"user_ids": {"user_09"}, "emails": {"kwame-mensah@proton.me"}}
    activity = [{
        "event_type": "LINK_RESOURCE_IDENTITY",
        "resource_id": "marketing_001",
        "target_system": "marketing_platform",
        "timestamp": "2026-09-16T07:27:01Z",
        "_case_linked": True,
    }]
    evidence = {"evidence_60": {
        "ocr_text": "marketing_001-sj.park@naver.com",
        "_ocr_captured_at": "2026-09-16T07:30:00Z",
    }}
    with pytest.raises(ValueError, match="NEEDS_REVIEW: identity-link evidence conflicts"):
        evaluator.evaluate_case(
            request, identity, activity, evidence, {}, audit_at="2026-09-17T09:20:00Z"
        )


@pytest.mark.business
def test_newer_identity_link_supersedes_older_profile_screenshot(
    evaluator: Any, request_payload: dict[str, str]
) -> None:
    request = {**request_payload, "case_id": "case_temporal_link"}
    identity = {"user_ids": {"user_09"}, "emails": {"kwame-mensah@proton.me"}}
    activity = [{
        "event_type": "LINK_RESOURCE_IDENTITY",
        "resource_id": "marketing_001",
        "target_system": "marketing_platform",
        "timestamp": "2026-09-16T07:27:01Z",
        "_case_linked": True,
    }]
    evidence = {"evidence_60": {
        "ocr_text": "marketing_001-sj.park@naver.com",
        "_ocr_captured_at": "2026-09-16T07:20:00Z",
        "records_found": [{
            "system_id": "marketing_platform",
            "resource_id": "marketing_001",
            "data_category": "MARKETING_PROFILE",
            "record_state": "PRESENT",
            "identifiers_matched": ["sj.park@naver.com"],
            "evidence_id": "evidence_60",
        }],
    }}
    status, steps = evaluator.evaluate_case(
        request, identity, activity, evidence,
        {"MARKETING_PROFILE": "DELETE"}, audit_at="2026-09-17T09:20:00Z",
    )
    assert status == "INCOMPLETE"
    assert [step["operation"] for step in steps] == [
        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT",
    ]


@pytest.mark.business
def test_ocr_email_check_does_not_cross_resource_rows(evaluator: Any) -> None:
    observed = evaluator._conflicting_ocr_emails(
        "data_flow_1121\nSelector\njain.aditi@gmail.com\n"
        "data_flow_9846\nSelector\nlucia-torres@gmail.com",
        {"jain.aditi@gmail.com"},
        "data_flow_1121",
    )
    assert observed == set()


@pytest.mark.business
def test_ocr_email_check_treats_export_filename_as_same_resource(evaluator: Any) -> None:
    observed = evaluator._conflicting_ocr_emails(
        "export_1260\ningrid.dahl@outlook.com\n"
        "export_1261\nmarcus.lee@northstar.shop\n"
        "export_1260\ncustomer_export_1260.zip\n"
        "ingrid.dahl@outlook.com\nexport_1259\nsara.kim@northstar.shop",
        {"ingrid.dahl@outlook.com"},
        "export_1260",
    )
    assert observed == set()


@pytest.mark.business
def test_cache_key_changes_with_prompt_logic_version() -> None:
    parser = _load_numbered_module("test_evidence_cache", "03_evidence.py")
    assert parser._cache_logic_fingerprint("prompt-v1") != parser._cache_logic_fingerprint("prompt-v2")


@pytest.mark.business
def test_activity_linking_uses_unique_request_time_match_and_skips_ambiguous_matches() -> None:
    request = pd.Series({
        "case_id": "case_flow", "request_text": "An integration still sends my data to other systems.",
        "reported_at": "2026-08-22T12:00:00Z",
    })
    identity = {"user_ids": {"user_flow"}, "emails": {"flow@example.test"}}
    activity = pd.DataFrame([{
        "timestamp": "2026-08-22T12:51:10Z", "action": "CHECK_DATA_FLOW",
        "resource_id": "data_flow_9846", "system_id": "integration_service",
        "status": "SUCCESS", "details": "Connector remains enabled.",
    }])
    activity_text = activity.fillna("").astype(str).agg(" ".join, axis=1).str.casefold()
    selected = _case_activity(request, identity, activity, activity_text)
    assert selected.iloc[0]["resource_id"] == "data_flow_9846"
    assert bool(selected.iloc[0]["_case_linked"]) is True

    ambiguous = pd.DataFrame([
        {"timestamp": "2026-08-22T11:59:00Z", "action": "DELETE_RECORD", "resource_id": "account_1", "system_id": "account_service"},
        {"timestamp": "2026-08-22T12:01:00Z", "action": "DELETE_RECORD", "resource_id": "account_2", "system_id": "account_service"},
    ])
    ambiguous_text = ambiguous.fillna("").astype(str).agg(" ".join, axis=1).str.casefold()
    assert _case_activity(request, identity, ambiguous, ambiguous_text).empty


@pytest.mark.business
def test_validation_query_executes_against_local_evidence(tmp_path: Path) -> None:
    evidence = tmp_path / "snapshot.txt"
    evidence.write_text("resource_id=account_001\n", encoding="utf-8")
    found = query_audit.execute_query(evidence, "account_001", "PRESENT")
    missing = query_audit.execute_query(evidence, "account_999", "ABSENT")
    assert found["passed"] is True
    assert missing["passed"] is True


@pytest.mark.business
def test_sqlite_snapshot_parser_uses_exact_identifier_matching(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.sql"
    snapshot.write_text(
        "CREATE TABLE search_index (resource_id TEXT, user_id TEXT);"
        "INSERT INTO search_index VALUES ('search_10', 'user_010');",
        encoding="utf-8",
    )
    parser_module = _load_numbered_module("test_evidence_parser", "03_evidence.py")
    false_prefix_match = parser_module.EvidenceParser.parse_sqlite(snapshot, {"user_01"})
    exact_match = parser_module.EvidenceParser.parse_sqlite(snapshot, {"user_010"})
    assert false_prefix_match == []
    assert exact_match[0]["resource_id"] == "search_10"


@pytest.mark.parametrize("case_index", range(32), ids=lambda i: f"case_{i + 1:02d}")
@pytest.mark.samples
def test_public_sample_rows_have_valid_step_payload(case_index: int, public_sample_rows: list[dict[str, str]]) -> None:
    """Parameterized contract scaffold over all 32 public reference cases."""
    rows = public_sample_rows
    assert len(rows) == 32
    row = rows[case_index]
    assert row["case_id"] == f"case_{case_index + 1:02d}"
    assert row["deletion_status"] in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    steps = json.loads(row["steps_json"])
    assert isinstance(steps, list)
    assert [step["step_no"] for step in steps] == list(range(1, len(steps) + 1))
