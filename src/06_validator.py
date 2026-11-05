"""Fail-fast validation gate for the generated compliance output CSV."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": {"PRESENT"},
        "REPORT_EXPOSED_PII": {"PRESENT"},
        "REPORT_ACTIVE_DATA_FLOW": {"ACTIVE"},
        "REPORT_RESTORE_RISK": {"ACTIVE"},
        "REPORT_UNMAPPED_CATEGORY": {"PRESENT"},
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": {"DISABLED"},
        "BLOCK_RESTORE": {"BLOCKED"},
        "DELETE_RECORD": {"ABSENT"},
        "REDACT_RECORD": {"REDACTED"},
        "ANONYMIZE_RECORD": {"ANONYMIZED"},
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": {"ABSENT"},
        "VERIFY_RECORD_PRESENT": {"PRESENT"},
        "VERIFY_RECORD_REDACTED": {"REDACTED"},
        "VERIFY_RECORD_ANONYMIZED": {"ANONYMIZED"},
        "VERIFY_DATA_FLOW_DISABLED": {"DISABLED"},
        "VERIFY_RESTORE_BLOCKED": {"BLOCKED"},
    },
}


def _fail(messages: list[str]) -> None:
    for message in messages[:20]:
        print(message, file=sys.stderr)
    sys.exit(1)


def validate(path: str | Path = "output.csv") -> None:
    """Validate output row count, order, status, JSON, steps, and evidence rules."""
    errors: list[str] = []
    try:
        frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    except (FileNotFoundError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        _fail([f"Cannot read {path}: {exc}"])
        return
    required = {"case_id", "deletion_status", "steps_json"}
    missing = required.difference(frame.columns)
    if missing:
        _fail([f"Missing required CSV columns: {', '.join(sorted(missing))}"])
    if len(frame) != 518:
        errors.append(f"Expected exactly 518 rows; found {len(frame)}")
    case_ids = frame["case_id"].tolist()
    if case_ids != sorted(case_ids):
        errors.append("Rows are not sorted by case_id")

    for row_number, row in frame.iterrows():
        case_id = row["case_id"]
        status = row["deletion_status"]
        if status not in VALID_STATUSES:
            errors.append(f"Row {row_number + 2} ({case_id}): invalid status {status!r}")
        try:
            steps: Any = json.loads(row["steps_json"])
            if not isinstance(steps, list):
                raise ValueError("steps JSON must be a list")
        except json.JSONDecodeError as exc:
            errors.append(f"Row {row_number + 2} ({case_id}): invalid steps JSON: {exc}")
            continue
        numbers: list[int] = []
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                errors.append(f"Row {row_number + 2} ({case_id}): step {index} is not an object")
                continue
            step_no = step.get("step_no")
            if isinstance(step_no, bool) or not isinstance(step_no, int):
                errors.append(f"Row {row_number + 2} ({case_id}): step {index} has invalid step_no")
            else:
                numbers.append(step_no)
            phase = str(step.get("phase", "")).upper()
            operation = str(step.get("operation", step.get("op", ""))).upper()
            state = str(step.get("state", "")).upper()
            allowed_states = PHASE_OPERATIONS.get(phase, {}).get(operation)
            if allowed_states is None:
                errors.append(f"Row {row_number + 2} ({case_id}): invalid phase/operation {phase}/{operation}")
            elif state not in allowed_states:
                errors.append(f"Row {row_number + 2} ({case_id}): invalid state {state!r} for {phase}/{operation}")
            evidence_id = step.get("evidence_id", "")
            if not str(step.get("system_id", "")).strip() or not str(step.get("resource_id", "")).strip():
                errors.append(f"Row {row_number + 2} ({case_id}): step {index} has an empty system_id or resource_id")
            if status == "COMPLETE":
                if phase != "VERIFICATION":
                    errors.append(f"Row {row_number + 2} ({case_id}): COMPLETE contains a non-verification step")
                if not evidence_id:
                    errors.append(f"Row {row_number + 2} ({case_id}): COMPLETE step lacks evidence_id")
            elif status == "INCOMPLETE" and phase in {"REMEDIATION", "VERIFICATION"} and evidence_id != "":
                errors.append(f"Row {row_number + 2} ({case_id}): proposed step must have empty evidence_id")
        if numbers != list(range(1, len(steps) + 1)):
            errors.append(f"Row {row_number + 2} ({case_id}): step numbers are not consecutive from 1")
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"Row {row_number + 2} ({case_id}): NOT_APPLICABLE must have no steps")
        if status == "INCOMPLETE" and not any(step.get("phase") == "VERIFICATION" for step in steps if isinstance(step, dict)):
            errors.append(f"Row {row_number + 2} ({case_id}): INCOMPLETE case has no verification steps")
        if status == "INCOMPLETE" and not any(step.get("phase") == "FINDING" for step in steps if isinstance(step, dict)):
            errors.append(f"Row {row_number + 2} ({case_id}): INCOMPLETE case has no finding steps")
    if errors:
        _fail(errors)
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    empty_identifier_steps = 0
    incomplete_without_verification = 0
    incomplete_without_finding = 0
    for _, row in frame.iterrows():
        steps = json.loads(row["steps_json"])
        empty_identifier_steps += sum(not str(step.get("system_id", "")).strip() or not str(step.get("resource_id", "")).strip() for step in steps)
        if row["deletion_status"] == "INCOMPLETE" and not any(step.get("phase") == "VERIFICATION" for step in steps):
            incomplete_without_verification += 1
        if row["deletion_status"] == "INCOMPLETE" and not any(step.get("phase") == "FINDING" for step in steps):
            incomplete_without_finding += 1
    print("PASSED: output.csv is valid")
    print(f"Empty system_id/resource_id steps: {empty_identifier_steps}")
    print(f"INCOMPLETE cases without VERIFICATION: {incomplete_without_verification}")
    print(f"INCOMPLETE cases without FINDING: {incomplete_without_finding}")


if __name__ == "__main__":
    validate()
