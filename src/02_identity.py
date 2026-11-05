"""Resolve an email to all identities known by a request's audit cutoff."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pandas as pd


_IDENTITY_FIELDS = {
    "email": "emails",
    "phone": "phones",
    "email_hash": "email_hashes",
    "name": "names",
}


def _normalized(value: Any) -> str:
    return str(value).strip().casefold() if pd.notna(value) else ""


def _column(frame: pd.DataFrame, *names: str) -> str | None:
    lookup = {str(name).casefold(): str(name) for name in frame.columns}
    return next((lookup[name.casefold()] for name in names if name.casefold() in lookup), None)


def _add(values: set[str], value: Any) -> None:
    if pd.notna(value) and str(value).strip():
        values.add(str(value).strip())


def resolve_identifiers(
    email: str,
    audit_at: str,
    identities_df: pd.DataFrame,
    audit_log_df: pd.DataFrame,
) -> dict[str, set[str]] | None:
    """Resolve current and historical identifiers through ``audit_at``.

    Audit logs may use either a wide schema (email/phone/name columns) or a
    change schema (field/attribute plus old_value and new_value).
    """
    cutoff = pd.Timestamp(audit_at)
    target_email = _normalized(email)
    identity_user_col = _column(identities_df, "user_id")
    identity_email_col = _column(identities_df, "email")
    if identity_user_col is None:
        raise ValueError("identities_df must contain a user_id column")

    normalized_cutoff = cutoff.tz_localize("UTC") if cutoff.tzinfo is None else cutoff
    snapshot_time_col = _column(identities_df, "updated_at", "snapshot_at", "as_of")
    snapshot_mask = pd.Series(True, index=identities_df.index)
    if snapshot_time_col is not None:
        snapshot_times = pd.to_datetime(identities_df[snapshot_time_col], errors="coerce", utc=True)
        snapshot_mask = snapshot_times.notna() & (snapshot_times <= normalized_cutoff)
    current_matches = pd.DataFrame()
    if identity_email_col is not None:
        current_matches = identities_df.loc[
            (identities_df[identity_email_col].map(_normalized) == target_email) & snapshot_mask
        ]
    user_ids = set(current_matches[identity_user_col].dropna().tolist())

    audit_user_col = _column(audit_log_df, "user_id")
    if audit_user_col is None:
        raise ValueError("audit_log_df must contain a user_id column")
    audit_time_col = _column(audit_log_df, "timestamp", "audit_at", "event_at", "event_time", "created_at")
    old_col = _column(audit_log_df, "old_value")
    new_col = _column(audit_log_df, "new_value")
    if old_col is not None or new_col is not None:
        historical = pd.Series(False, index=audit_log_df.index)
        for value_col in (old_col, new_col):
            if value_col is not None:
                historical |= audit_log_df[value_col].map(_normalized) == target_email
        if audit_time_col is not None:
            times = pd.to_datetime(audit_log_df[audit_time_col], errors="coerce", utc=True)
            historical &= times <= normalized_cutoff
        user_ids.update(audit_log_df.loc[historical, audit_user_col].dropna().tolist())

    if not user_ids:
        return None

    identifiers: dict[str, set[str]] = {
        "user_ids": set(map(str, user_ids)),
        "emails": set(),
        "phones": set(),
        "email_hashes": set(),
        "names": set(),
        "secondary_system_ids": set(),
    }
    for _, row in current_matches.iterrows():
        for column, output_key in _IDENTITY_FIELDS.items():
            actual = _column(identities_df, column)
            if actual is not None:
                _add(identifiers[output_key], row[actual])

    scoped = audit_log_df.loc[audit_log_df[audit_user_col].isin(user_ids)]
    if audit_time_col is not None:
        times = pd.to_datetime(scoped[audit_time_col], errors="coerce", utc=True)
        scoped = scoped.loc[times <= normalized_cutoff]
        scoped = scoped.assign(_parsed_event_time=pd.to_datetime(scoped[audit_time_col], errors="coerce", utc=True)).sort_values(
            "_parsed_event_time", kind="stable"
        ).drop(columns="_parsed_event_time")

    # Wide audit schemas expose values directly by field name.
    for field, output_key in _IDENTITY_FIELDS.items():
        actual = _column(scoped, field)
        if actual is not None:
            for value in scoped[actual]:
                _add(identifiers[output_key], value)

    # Change schemas store the identity attribute in a field/attribute column.
    field_col = _column(scoped, "field", "field_name", "attribute", "column", "key")
    if field_col is not None:
        for _, row in scoped.iterrows():
            field_name = str(row[field_col]).casefold().strip()
            output_key = _IDENTITY_FIELDS.get(field_name)
            if output_key:
                for value_col in (old_col, new_col):
                    if value_col is not None:
                        _add(identifiers[output_key], row[value_col])
            elif field_name in {"legacy_account_id", "account_id", "customer_id", "external_id", "system_id"}:
                for value_col in (old_col, new_col):
                    if value_col is not None:
                        _add(identifiers["secondary_system_ids"], row[value_col])
    return identifiers


class IdentityResolver:
    """Resolve a point-in-time identity profile from current and audit snapshots."""

    def __init__(self, identities_df: pd.DataFrame, audit_log_df: pd.DataFrame) -> None:
        self.identities_df = identities_df
        self.audit_log_df = audit_log_df

    def get_all_identifiers(self, email: str, audit_at: str) -> dict[str, set[str]] | None:
        return resolve_identifiers(email, audit_at, self.identities_df, self.audit_log_df)
