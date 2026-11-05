"""Pydantic schemas for participant-provided CSV inputs."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator


class CsvInput(BaseModel):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    @model_validator(mode="before")
    @classmethod
    def blank_strings_to_none(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {key: (None if isinstance(item, str) and not item.strip() else item) for key, item in value.items()}
        return value


class DeletionRequestInput(CsvInput):
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str | None = None
    reported_at: datetime | None = None
    audit_at: datetime
    request_text: str


class UserIdentityInput(CsvInput):
    user_id: str
    name: str | None = None
    email: str | None = None
    phone: str | None = None
    email_hash: str | None = None
    updated_at: datetime | None = None


class UserAuditInput(CsvInput):
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str | None = None
    new_value: str | None = None


class SystemActivityInput(CsvInput):
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str | None = None
    target_system: str | None = None
    resource_id: str | None = None
    reported_result: str | None = None
    details: str | None = None


class DeletionRuleInput(CsvInput):
    rule_id: str
    data_category: str
    condition: str
    required_action: str


class EvidenceFileInput(CsvInput):
    file_id: str
    file_path: str
    origin: str | None = None
    captured_at: datetime
