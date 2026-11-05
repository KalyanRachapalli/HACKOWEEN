"""Load compliance inputs once and build in-memory indexes."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Any

import pandas as pd
from pydantic import TypeAdapter

from input_models import (
    DeletionRequestInput, DeletionRuleInput, EvidenceFileInput, SystemActivityInput,
    UserAuditInput, UserIdentityInput,
)


INPUT_SCHEMAS = {
    "requests_df": DeletionRequestInput,
    "identities_df": UserIdentityInput,
    "audit_log_df": UserAuditInput,
    "activity_df": SystemActivityInput,
    "rules_df": DeletionRuleInput,
    "evidence_df": EvidenceFileInput,
}


def _validate_frame(frame: pd.DataFrame, schema: type[Any], source_name: str) -> list[dict[str, Any]]:
    """Validate rows once at ingestion without replacing DataFrame processing."""
    records = frame.astype(object).where(pd.notna(frame), None).to_dict(orient="records")
    try:
        parsed = TypeAdapter(list[schema]).validate_python(records)
        return [item.model_dump(mode="python") for item in parsed]
    except Exception as exc:
        raise ValueError(f"Invalid input rows in {source_name}: {exc}") from exc


def load_data(dataset_dir: str | Path = "dataset") -> dict[str, Any]:
    """Load source CSVs and SQL snapshots, supporting both dataset/ and root layouts."""
    root = Path(dataset_dir)
    if not (root / "deletion_requests.csv").exists():
        if Path("deletion_requests.csv").exists():
            root = Path(".")
        elif (Path(__file__).parent.parent / "deletion_requests.csv").exists():
            root = Path(__file__).parent.parent

    requests_df = pd.read_csv(root / "deletion_requests.csv")
    identities_df = pd.read_csv(root / "user_identities.csv")
    audit_log_df = pd.read_csv(root / "user_audit_log.csv")
    activity_df = pd.read_csv(root / "system_activity.csv")
    rules_df = pd.read_csv(root / "deletion_rules.csv")
    evidence_df = pd.read_csv(root / "evidence_files.csv")

    # Canonical evaluator aliases for the source activity schema.
    activity_df["timestamp"] = activity_df["event_time"]
    activity_df["action"] = activity_df["event_type"]
    activity_df["system_id"] = activity_df["target_system"].fillna("").replace("", pd.NA).fillna(activity_df["source_system"])
    activity_df["status"] = activity_df["reported_result"]

    frames = {
            "requests_df": requests_df, "identities_df": identities_df,
            "audit_log_df": audit_log_df, "activity_df": activity_df,
            "rules_df": rules_df, "evidence_df": evidence_df,
    }
    normalized_frames: dict[str, pd.DataFrame] = {}
    for key, schema in INPUT_SCHEMAS.items():
        original = frames[key]
        normalized_frames[key] = pd.DataFrame(
            _validate_frame(original, schema, f"{key}.csv"), columns=original.columns
        )
    requests_df = normalized_frames["requests_df"]
    identities_df = normalized_frames["identities_df"]
    audit_log_df = normalized_frames["audit_log_df"]
    activity_df = normalized_frames["activity_df"]
    rules_df = normalized_frames["rules_df"]
    evidence_df = normalized_frames["evidence_df"]

    audit_idx = audit_log_df.groupby("user_id", sort=False)
    activity_by_user = activity_df.groupby("user_id", sort=False) if "user_id" in activity_df.columns else None
    activity_by_resource = activity_df.groupby("resource_id", sort=False) if "resource_id" in activity_df.columns else None
    treatment_col = "required_treatment" if "required_treatment" in rules_df.columns else "required_action"
    rules_dict = dict(zip(rules_df["data_category"], rules_df[treatment_col]))

    sql_snapshots: dict[Any, sqlite3.Connection] = {}
    path_col = "file_name" if "file_name" in evidence_df.columns else "file_path"
    file_types = evidence_df[path_col].astype(str).map(lambda item: Path(item).suffix.lstrip(".").lower())
    sql_rows = evidence_df.loc[file_types == "sql"]
    try:
        for _, row in sql_rows.iterrows():
            relative = Path(str(row[path_col]))
            candidates = [
                root / relative,
                Path(str(relative).replace("evidence/", "")),
                Path(str(relative).replace("evidence\\", "")),
                Path(__file__).parent.parent / relative,
            ]
            path = next((c for c in candidates if c.exists()), root / relative)
            connection = sqlite3.connect(":memory:")
            try:
                script = path.read_text(encoding="utf-8")
                connection.executescript(script)
            except Exception:
                connection.close()
                raise
            sql_snapshots[row["file_id"]] = connection
    except Exception:
        for connection in sql_snapshots.values():
            connection.close()
        raise

    return {
        "requests_df": requests_df,
        "identities_df": identities_df,
        "audit_log_df": audit_log_df,
        "activity_df": activity_df,
        "rules_df": rules_df,
        "evidence_df": evidence_df,
        "audit_idx": audit_idx,
        "activity_by_user": activity_by_user,
        "activity_by_resource": activity_by_resource,
        "rules_dict": rules_dict,
        "sql_snapshots": sql_snapshots,
        "identities_by_email": {
            str(row["email"]).strip().casefold(): row
            for row in identities_df.to_dict(orient="records")
            if pd.notna(row.get("email")) and str(row["email"]).strip()
        },
        "audit_by_user": {key: group for key, group in audit_idx},
        "evidence_by_id": evidence_df.set_index("file_id", drop=False).to_dict(orient="index"),
    }


class DataLoader:
    """Small object interface around the project-compatible `load_data` API."""

    def __init__(self, dataset_dir: str | Path = "dataset") -> None:
        self.dataset_dir = Path(dataset_dir)

    def load(self) -> dict[str, Any]:
        return load_data(self.dataset_dir)
