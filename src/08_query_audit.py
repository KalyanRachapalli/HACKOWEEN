"""Generate and execute resource-presence checks against supplied evidence."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import pandas as pd


def _has_exact_identifier(text: str, identifier: str) -> bool:
    return re.search(rf"(?<![\w]){re.escape(identifier)}(?![\w])", text, re.IGNORECASE) is not None


def execute_query(evidence_path: str | Path, resource_id: str, expected_state: str) -> dict[str, Any]:
    """Run a resource-presence query over one manifest-listed evidence file."""
    path = Path(evidence_path)
    if not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_bytes().decode("utf-8", errors="replace")
    present = _has_exact_identifier(text, resource_id)
    expects_present = expected_state.upper() == "PRESENT"
    passed = present == expects_present
    return {
        "evidence_path": str(path),
        "resource_id": resource_id,
        "expected_state": expected_state.upper(),
        "resource_present": present,
        "passed": passed,
        "scope": "resource-presence check against supplied evidence; does not query production systems",
    }


def generate_validation_queries(
    output: pd.DataFrame,
    evidence_manifest: pd.DataFrame,
    *,
    dataset_dir: str | Path = "dataset",
) -> list[dict[str, Any]]:
    """Create one executable resource-presence query per COMPLETE verification."""
    id_col = next((c for c in evidence_manifest.columns if str(c).casefold() in {"file_id", "evidence_id"}), None)
    path_col = next((c for c in evidence_manifest.columns if str(c).casefold() in {"file_path", "file_name", "path"}), None)
    if id_col is None or path_col is None:
        raise ValueError("Evidence manifest must include file_id and file_path columns")
    source_by_id = {str(row[id_col]): str(row[path_col]) for _, row in evidence_manifest.iterrows()}
    root = Path(dataset_dir)
    queries: list[dict[str, Any]] = []
    for _, row in output.iterrows():
        if str(row.get("deletion_status")) != "COMPLETE":
            continue
        steps = json.loads(str(row.get("steps_json", "[]")))
        for step in steps:
            if step.get("phase") != "VERIFICATION":
                raise ValueError(f"{row['case_id']}: COMPLETE contains a non-verification step")
            evidence_id = str(step.get("evidence_id", ""))
            if evidence_id not in source_by_id:
                raise ValueError(f"{row['case_id']}: verification cites unknown evidence {evidence_id!r}")
            relative = Path(source_by_id[evidence_id])
            evidence_path = relative if relative.is_absolute() else root / relative
            operation = str(step.get("operation", ""))
            expected = str(step.get("state", ""))
            expected_presence = "ABSENT" if operation == "VERIFY_RECORD_ABSENT" else "PRESENT"
            query = {
                "case_id": str(row["case_id"]),
                "evidence_id": evidence_id,
                "system_id": str(step.get("system_id", "")),
                "resource_id": str(step.get("resource_id", "")),
                "operation": operation,
                "expected_state": expected,
                "expected_resource_presence": expected_presence,
                "evidence_path": str(evidence_path),
                "command": [
                    "python", "src/08_query_audit.py", "--evidence-path", str(evidence_path),
                    "--resource-id", str(step.get("resource_id", "")), "--expected-state", expected_presence,
                ],
                "scope": "checks the cited local evidence file; does not query production systems",
            }
            queries.append(query)
    return queries


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-path", required=True)
    parser.add_argument("--resource-id", required=True)
    parser.add_argument("--expected-state", required=True, choices=["PRESENT", "ABSENT"])
    args = parser.parse_args()
    result = execute_query(args.evidence_path, args.resource_id, args.expected_state)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result["passed"] else 1)
