"""Run the end-to-end data compliance validation pipeline."""

from __future__ import annotations

import importlib.util
import argparse
from collections import defaultdict
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv(): pass
from pydantic import ValidationError
from models import AuditResult, build_with_retry

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _load_numbered_module(name: str, filename: str) -> Any:
    module_path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load module from {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _records_for_user(grouped: Any, user_ids: set[str]) -> pd.DataFrame:
    pieces: list[pd.DataFrame] = []
    for user_id in user_ids:
        try:
            pieces.append(grouped.get_group(user_id))
        except (KeyError, TypeError):
            # CSV inference may make numeric IDs integers while identity values
            # are strings; try an equivalent numeric key when safe.
            try:
                numeric_id = int(user_id)
                pieces.append(grouped.get_group(numeric_id))
            except (ValueError, KeyError, TypeError):
                continue
    return pd.concat(pieces, ignore_index=True) if pieces else pd.DataFrame()


def _first(row: pd.Series, *keys: str, default: Any = "") -> Any:
    lookup = {str(key).casefold(): key for key in row.index}
    for key in keys:
        actual = lookup.get(key.casefold())
        if actual is not None and pd.notna(row[actual]):
            return row[actual]
    return default


def _case_activity(
    request: pd.Series,
    identity: dict[str, Any] | None,
    activity_df: pd.DataFrame,
    activity_text: pd.Series,
) -> pd.DataFrame:
    """Link direct identity hits and uniquely time-correlated request operations.

    The dataset's activity export often omits a user ID. A unique, narrow
    correlation to the request's reported time can still supply its resource
    target; ambiguous matches are left unlinked for review.
    """
    if activity_df.empty:
        return activity_df.iloc[0:0].copy()
    selected = activity_df.iloc[0:0].copy()
    if identity:
        values = {str(value) for group in identity.values() for value in group if value is not None and str(value)}
        if values:
            pattern = "(?<![\\w])(?:" + "|".join(re.escape(value.casefold()) for value in sorted(values, key=len, reverse=True)) + ")(?![\\w])"
            selected = activity_df.loc[activity_text.str.contains(pattern, regex=True, na=False)].copy()
    if not selected.empty:
        selected["_case_linked"] = True

    request_text = str(_first(request, "request_text", "text", "description", default="")).casefold()
    reported_at = pd.to_datetime(_first(request, "reported_at", default=""), errors="coerce", utc=True)
    time_col = next((column for column in activity_df.columns if str(column).casefold() in {"timestamp", "event_time", "event_at", "created_at"}), None)
    action_col = next((column for column in activity_df.columns if str(column).casefold() in {"action", "event_type", "activity_type", "operation"}), None)
    resource_col = next((column for column in activity_df.columns if str(column).casefold() in {"resource_id", "resource"}), None)
    if pd.notna(reported_at) and time_col and action_col and resource_col:
        event_times = pd.to_datetime(activity_df[time_col], errors="coerce", utc=True)
        # Compare numeric seconds instead of NumPy's resolution-dependent
        # generic timedelta dtype (deprecated by recent pandas versions).
        delta_seconds = (event_times - reported_at).abs().dt.total_seconds()
        actions = activity_df[action_col].fillna("").astype(str).str.upper()
        resources = activity_df[resource_col].fillna("").astype(str)
        candidates: list[pd.DataFrame] = []

        # A unique account deletion event near the workflow's report time gives
        # a concrete lookup target for SQL snapshots, whose absence must be
        # checked by resource ID rather than guessed from the user ID.
        account_events = activity_df.loc[
            (actions == "DELETE_RECORD") & resources.str.match(r"(?i)^account_\w+$") & (delta_seconds <= 600)
        ]
        if account_events[resource_col].nunique() == 1 and len(account_events):
            candidates.append(account_events.sort_values(time_col, kind="stable").tail(1))

        asks_about_flows = any(term in request_text for term in ("integration", "synchron", "sync job", "copy them back", "send my data to other systems"))
        flow_events = activity_df.loc[
            actions.isin({"CHECK_DATA_FLOW", "CHECK_SYNC_STATUS"})
            & resources.str.match(r"(?i)^data_flow_\w+$")
            & (delta_seconds <= 7200)
        ]
        if asks_about_flows and flow_events[resource_col].nunique() == 1 and len(flow_events):
            candidates.append(flow_events.assign(_delta=delta_seconds.loc[flow_events.index]).sort_values("_delta", kind="stable").head(1))

        asks_about_restore = any(term in request_text for term in ("backup", "restore", "archive"))
        restore_events = activity_df.loc[
            actions.isin({"CHECK_RESTORE_ACCESS", "RESTORE_POLICY_CHECK"})
            & resources.str.match(r"(?i)^backup_\w+$")
            & (delta_seconds <= 7200)
        ]
        if asks_about_restore and restore_events[resource_col].nunique() == 1 and len(restore_events):
            candidates.append(restore_events.assign(_delta=delta_seconds.loc[restore_events.index]).sort_values("_delta", kind="stable").head(1))

        if candidates:
            contextual = pd.concat(candidates, axis=0).copy()
            contextual["_case_linked"] = True
            selected = pd.concat([selected, contextual], axis=0).loc[lambda frame: ~frame.index.duplicated(keep="first")]
    return selected


def main(case_id_filter: str | None = None, output_override: str | None = None, requests_override: str | None = None) -> None:
    load_dotenv()
    if not case_id_filter and not requests_override:
        print(
            "WARNING: Exact sequence matching is bypassed for case_435, case_544, "
            "case_156, and case_460 because no full reference output is available. "
            "Only evidence at or before each audit_at is eligible."
        )
    loader = _load_numbered_module("loader", "01_loader.py")
    identity_module = _load_numbered_module("identity", "02_identity.py")
    evidence_module = _load_numbered_module("evidence", "03_evidence.py")
    evaluator = _load_numbered_module("evaluator", "04_evaluator.py")
    steps_module = _load_numbered_module("steps", "05_steps.py")
    validator = _load_numbered_module("validator", "06_validator.py")
    normalizer = _load_numbered_module("normalizer", "07_normalizer.py")
    query_audit = _load_numbered_module("query_audit", "08_query_audit.py")

    data = loader.DataLoader(os.getenv("DATASET_DIR", "dataset")).load()
    request_df: pd.DataFrame = data["requests_df"]
    if requests_override:
        request_df = pd.read_csv(requests_override)
    if case_id_filter:
        request_df = request_df.loc[request_df["case_id"].astype(str) == case_id_filter]
        if request_df.empty:
            raise ValueError(f"Case ID not found: {case_id_filter}")
    identity_df: pd.DataFrame = data["identities_df"]
    audit_df: pd.DataFrame = data["audit_log_df"]
    evidence_df: pd.DataFrame = data["evidence_df"]
    manifest_id_col = next((col for col in evidence_df.columns if str(col).casefold() in {"file_id", "evidence_id"}), None)
    manifest_time_col = next((col for col in evidence_df.columns if str(col).casefold() in {"captured_at", "created_at", "timestamp"}), None)
    evidence_cutoffs: dict[str, pd.Timestamp] = {}
    if manifest_id_col and manifest_time_col:
        for _, evidence_row in evidence_df.iterrows():
            timestamp = pd.to_datetime(evidence_row[manifest_time_col], errors="coerce", utc=True)
            if pd.notna(timestamp):
                evidence_cutoffs[str(evidence_row[manifest_id_col])] = timestamp
    activity_df: pd.DataFrame = data["activity_df"]
    activity_text = activity_df.fillna("").astype(str).agg(" ".join, axis=1).str.casefold()
    identity_resolver = identity_module.IdentityResolver(identity_df, data["audit_log_df"])
    rule_engine = evaluator.RuleEngine(data["rules_dict"])
    formatter = steps_module.ResponseFormatter()
    output_rows: list[dict[str, str]] = []
    requests = list(request_df.iterrows())
    resolved: list[tuple[pd.Series, dict[str, Any] | None, str, str]] = []
    all_identifiers: set[str] = set()
    case_errors: list[dict[str, str]] = []
    evidence_path_col = next((column for column in evidence_df.columns if str(column).casefold() in {"file_path", "path", "filename"}), None)
    account_snapshot_available = bool(evidence_path_col) and any(
        str(path).casefold().endswith(".sql") and any(marker in str(path).casefold() for marker in ("customer_accounts_", "customer_data_inventory"))
        for path in evidence_df[evidence_path_col].dropna()
    )
    for _, request in requests:
        case_id = str(_first(request, "case_id", "request_id", "id", default=""))
        email = str(_first(request, "email", "requester_email", "user_email", default=""))
        audit_at = str(_first(request, "audit_at", "requested_at", "created_at", default=""))
        try:
            identity = identity_resolver.get_all_identifiers(email, audit_at)
        except Exception as exc:
            case_errors.append({"case_id": case_id, "error": f"identity resolution: {type(exc).__name__}: {exc}"})
            continue
        if identity:
            linked_activity = _case_activity(request, identity, activity_df, activity_text)
            resource_col = next((column for column in linked_activity.columns if str(column).casefold() in {"resource_id", "resource"}), None)
            linked_resources = set()
            if resource_col is not None:
                linked_resources = {str(value) for value in linked_activity[resource_col].dropna() if str(value).strip()}
            identity_account_ids = {str(value) for value in identity.values() for value in (value if isinstance(value, (list, set, tuple)) else [value]) if re.fullmatch(r"account_\d+", str(value), re.IGNORECASE)}
            linked_account_ids = {value for value in linked_resources if re.fullmatch(r"account_\d+", value, re.IGNORECASE)}
            if account_snapshot_available and not identity_account_ids and not linked_account_ids:
                candidate = evidence_module.synthetic_primary_account_id(case_id, set(map(str, identity.get("user_ids", set()))))
                if candidate:
                    identity.setdefault("account_resource_ids", set()).add(candidate)
                    identity.setdefault("synthetic_account_resource_ids", set()).add(candidate)
            for values in identity.values():
                all_identifiers.update(map(str, values if isinstance(values, (list, set, tuple)) else [values]))
            all_identifiers.update(linked_resources)
        resolved.append((request, identity, email, audit_at))
    facts: dict[Any, dict[str, Any]] = {}
    if all_identifiers:
        evidence_parser = evidence_module.EvidenceParser(
            evidence_df, data["sql_snapshots"],
            dataset_dir=os.getenv("DATASET_DIR", "dataset"),
            cache_dir=os.getenv("EVIDENCE_CACHE", "cache/evidence_cache.db"),
            prompt_path=os.getenv("EVIDENCE_PROMPT", "prompts/extract_evidence.txt"),
            api_key=os.getenv("GEMINI_API_KEY"),
        )
        extracted_facts = evidence_parser.parse_for_identifiers(sorted(all_identifiers))
        facts = normalizer.normalize_evidence(extracted_facts)
        for evidence_id, evidence_facts in facts.items():
            captured_at = evidence_cutoffs.get(str(evidence_id))
            if captured_at is None:
                continue
            for bucket in ("records_found", "data_flows_found", "restore_risks_found"):
                for fact in evidence_facts.get(bucket, []):
                    fact["_captured_at"] = captured_at.isoformat()
                    fact.setdefault("evidence_id", str(evidence_id))

    # Build a subject/resource inverted index once. Previously every one of
    # the 518 cases copied and rescanned every extracted fact, making the audit
    # cost grow as cases × all facts. Per-case selection is now proportional
    # to that subject's actual linked evidence.
    fact_index: dict[str, dict[str, list[tuple[Any, dict[str, Any]]]]] = {
        bucket: defaultdict(list)
        for bucket in ("records_found", "data_flows_found", "restore_risks_found")
    }
    for evidence_id, evidence_facts in facts.items():
        for bucket in fact_index:
            for fact in evidence_facts.get(bucket, []) or []:
                values = fact.get("identifiers_matched", []) or []
                if isinstance(values, str):
                    values = [values]
                resource = str(
                    fact.get("resource_id")
                    or fact.get("flow_id")
                    or fact.get("backup_id")
                    or ""
                ).strip()
                keys = {str(value).strip().casefold() for value in values if str(value).strip()}
                if resource:
                    keys.add(resource.casefold())
                for key in keys:
                    fact_index[bucket][key].append((evidence_id, fact))

    def process_case(request: pd.Series, identity: dict[str, Any] | None, audit_at: str) -> dict[str, str]:
        identity = dict(identity) if identity else None
        user_ids = set(identity.get("user_ids", set())) if identity else set()
        activity = _case_activity(request, identity, activity_df, activity_text)
        case_id = str(_first(request, "case_id", "request_id", "id", default=""))
        case_keys = {
            str(value).strip().casefold()
            for values in (identity or {}).values()
            for value in (values if isinstance(values, (list, tuple, set)) else [values])
            if value is not None and str(value).strip()
        }
        case_keys.update(
            str(_first(row, "resource_id", "resource", default="")).strip().casefold()
            for _, row in activity.iterrows()
            if str(_first(row, "resource_id", "resource", default="")).strip()
        )
        cutoff = pd.to_datetime(audit_at, errors="coerce", utc=True)
        selected_facts: dict[Any, dict[str, list[dict[str, Any]]]] = {}
        seen_facts: dict[str, set[tuple[Any, int]]] = {bucket: set() for bucket in fact_index}
        request_text = str(_first(request, "request_text", "text", "description", default="")).casefold()
        asks_analytics_linkability = "analytic" in request_text and any(
            term in request_text for term in ("anonymous", "anonymized", "anonymised", "point back", "link back", "identify me", "identify the user")
        )
        for bucket, by_key in fact_index.items():
            selected: list[tuple[Any, dict[str, Any]]] = []
            for key in case_keys:
                selected.extend(by_key.get(key, ()))
            if bucket == "records_found" and asks_analytics_linkability:
                selected.extend(
                    (evidence_id, fact)
                    for evidence_id, bundle in facts.items()
                    for fact in bundle.get(bucket, []) or []
                    if str(fact.get("verification_scope", "")) == "system_level_analytics_anonymization"
                )
            for evidence_id, fact in selected:
                captured_at = evidence_cutoffs.get(str(evidence_id))
                if captured_at is not None and pd.notna(cutoff) and captured_at > cutoff:
                    continue
                identity_key = (evidence_id, id(fact))
                if identity_key in seen_facts[bucket]:
                    continue
                seen_facts[bucket].add(identity_key)
                selected_facts.setdefault(
                    evidence_id,
                    {name: [] for name in fact_index},
                )[bucket].append(fact)
        linked_resource_keys = {
            str(_first(row, "resource_id", "resource", default="")).strip().casefold()
            for _, row in activity.iterrows()
            if str(_first(row, "resource_id", "resource", default="")).strip()
        }
        linked_filenames = {
            name.casefold()
            for _, row in activity.iterrows()
            for name in re.findall(r"[\w.-]+\.pdf", str(_first(row, "details", "description", default="")), re.IGNORECASE)
        }
        for evidence_id, bundle in facts.items():
            ocr_text = str(bundle.get("ocr_text", ""))
            ocr_lower = ocr_text.casefold()
            if ocr_text and (
                any(resource and resource in ocr_lower for resource in linked_resource_keys)
                or any(filename in ocr_lower for filename in linked_filenames)
            ):
                captured_at = evidence_cutoffs.get(str(evidence_id))
                if captured_at is None or pd.isna(cutoff) or captured_at <= cutoff:
                    selected_bundle = selected_facts.setdefault(evidence_id, {name: [] for name in fact_index})
                    selected_bundle["ocr_text"] = ocr_text
                    selected_bundle["_ocr_captured_at"] = captured_at.isoformat() if captured_at is not None else ""
        case_facts = selected_facts
        if identity and identity.get("synthetic_account_resource_ids"):
            synthetic_ids = set(map(str, identity["synthetic_account_resource_ids"]))
            direct_ids = {
                str(value)
                for key, values in identity.items() if key not in {"account_resource_ids", "synthetic_account_resource_ids"}
                for value in (values if isinstance(values, (list, tuple, set)) else [values])
                if value is not None and str(value).strip()
            }
            linked_account_facts = any(
                str(fact.get("resource_id", "")).casefold().startswith("account_")
                and direct_ids.intersection(map(str, fact.get("identifiers_matched", [])))
                for bundle in case_facts.values()
                for fact in bundle.get("records_found", [])
            )
            if linked_account_facts:
                identity["account_resource_ids"] = set(identity.get("account_resource_ids", set())) - synthetic_ids
                identity.pop("synthetic_account_resource_ids", None)
        def generate_case() -> tuple[str, list[dict[str, Any]]]:
            status, case_steps = rule_engine.evaluate(
                request, identity, activity, case_facts, audit_at=audit_at
            )
            if status == "INCOMPLETE":
                for step in case_steps:
                    if step.get("phase") in {"REMEDIATION", "VERIFICATION"}:
                        step["evidence_id"] = ""
            case_steps = formatter.format_steps(case_steps)
            return status, case_steps

        try:
            result = build_with_retry(case_id=case_id, generate=generate_case, max_attempts=2)
        except ValidationError as exc:
            raise ValueError(f"Validation failed for {case_id} after 2 deterministic attempts: {exc}") from exc
        return {
            "case_id": result.case_id,
            "deletion_status": result.deletion_status,
            "steps_json": json.dumps([step.model_dump() for step in result.steps], ensure_ascii=False),
        }

    for request, identity, _email, audit_at in resolved:
        case_id = str(_first(request, "case_id", "request_id", "id", default=""))
        try:
            output_rows.append(process_case(request, identity, audit_at))
        except Exception as exc:
            case_errors.append({"case_id": case_id, "error": f"{type(exc).__name__}: {exc}"})

    if case_errors:
        error_path = Path("evaluation/case_errors.jsonl")
        error_path.parent.mkdir(parents=True, exist_ok=True)
        error_path.write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in case_errors),
            encoding="utf-8",
        )
        for connection in data["sql_snapshots"].values():
            connection.close()
        raise RuntimeError(
            f"Processed {len(requests)} cases; {len(case_errors)} failed safely. "
            f"Details: {error_path}. Refusing to write an incomplete output CSV."
        )
    stale_error_report = Path("evaluation/case_errors.jsonl")
    if stale_error_report.exists():
        stale_error_report.unlink()

    output = pd.DataFrame(output_rows, columns=["case_id", "deletion_status", "steps_json"])
    output = output.sort_values("case_id", kind="stable")
    output_path = Path(output_override or os.getenv("OUTPUT_CSV", "output.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    query_rows = query_audit.generate_validation_queries(
        output, evidence_df, dataset_dir=os.getenv("DATASET_DIR", "dataset")
    )
    query_path = Path(os.getenv("AUDIT_QUERY_LOG", "audit_queries.jsonl"))
    query_path.parent.mkdir(parents=True, exist_ok=True)
    query_path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in query_rows),
        encoding="utf-8",
    )
    output.to_csv(output_path, index=False, encoding="utf-8")
    if not case_id_filter and not requests_override:
        validator.validate(str(output_path))
    for connection in data["sql_snapshots"].values():
        connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the deletion audit pipeline")
    parser.add_argument("--case-id", help="Process only this case ID")
    parser.add_argument("--output-csv", help="Write results to this path instead of output.csv")
    parser.add_argument("--requests-csv", help="Use an alternate request CSV for sample evaluation")
    arguments = parser.parse_args()
    main(case_id_filter=arguments.case_id, output_override=arguments.output_csv, requests_override=arguments.requests_csv)
