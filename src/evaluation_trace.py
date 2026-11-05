"""Compare generated output against a public reference and trace first divergence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd

STEP_FIELDS = ("phase", "operation", "system_id", "resource_id", "state", "evidence_id")


def _steps(value: str) -> list[dict[str, Any]]:
    parsed = json.loads(value or "[]")
    if not isinstance(parsed, list):
        raise ValueError("steps_json must contain a JSON array")
    return parsed


def _signature(step: dict[str, Any]) -> tuple[str, ...]:
    return tuple(str(step.get(field, "")) for field in STEP_FIELDS)


def compare(actual_path: str | Path, expected_path: str | Path) -> tuple[int, int]:
    """Print first status/step divergence per case; return sequence matches and total."""
    actual = pd.read_csv(actual_path, dtype=str, keep_default_na=False).set_index("case_id")
    expected = pd.read_csv(expected_path, dtype=str, keep_default_na=False).set_index("case_id")
    shared = sorted(set(actual.index) & set(expected.index))
    exact_matches = 0
    for case_id in shared:
        got = _steps(actual.at[case_id, "steps_json"])
        want = _steps(expected.at[case_id, "steps_json"])
        status_differs = actual.at[case_id, "deletion_status"] != expected.at[case_id, "deletion_status"]
        divergence = next(
            (
                index
                for index in range(min(len(got), len(want)))
                if _signature(got[index]) != _signature(want[index])
            ),
            None,
        )
        if not status_differs and divergence is None and len(got) == len(want):
            exact_matches += 1
            continue
        print(f"DIVERGENCE {case_id}: status {actual.at[case_id, 'deletion_status']} != {expected.at[case_id, 'deletion_status']}" if status_differs else f"DIVERGENCE {case_id}: status matches")
        if divergence is not None:
            print(f"  first differing step #{divergence + 1}")
            print(f"  actual:   {_signature(got[divergence])}")
            print(f"  expected: {_signature(want[divergence])}")
        elif len(got) != len(want):
            print(f"  first missing/extra step #{min(len(got), len(want)) + 1}")
            print(f"  actual steps={len(got)} expected steps={len(want)}")
    print(f"Exact status + ordered step sequence: {exact_matches}/{len(shared)}")
    return exact_matches, len(shared)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--actual", required=True, help="Generated output CSV")
    parser.add_argument("--expected", required=True, help="Reference output CSV")
    args = parser.parse_args()
    compare(args.actual, args.expected)
