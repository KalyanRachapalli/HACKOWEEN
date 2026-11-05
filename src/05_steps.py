"""Stable ordering and numbering for evaluation steps."""

from __future__ import annotations

from typing import Any

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "REPORT_UNMAPPED_CATEGORY": 4,
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def sort_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort by phase, operation, system, and resource using specified orders."""
    return sorted(
        steps,
        key=lambda step: (
            PHASE_ORDER.get(str(step.get("phase", "")).upper(), len(PHASE_ORDER)),
            OP_ORDER.get(str(step.get("operation", "")).upper(), len(OP_ORDER)),
            str(step.get("system_id", "")),
            str(step.get("resource_id", "")),
        ),
    )


def number_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return copied steps numbered consecutively from one."""
    return [dict(step, step_no=index) for index, step in enumerate(steps, start=1)]


class ResponseFormatter:
    """Produce stable, sequentially numbered output steps and CSV rows."""

    def format_steps(self, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return number_steps(sort_steps(steps))

    def output_row(self, case_id: str, deletion_status: str, steps: list[dict[str, Any]]) -> dict[str, str]:
        import json

        return {
            "case_id": case_id,
            "deletion_status": deletion_status,
            "steps_json": json.dumps(self.format_steps(steps), ensure_ascii=False),
        }
