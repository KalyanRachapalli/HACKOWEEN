"""Typed, validated models for deletion-audit output records."""

from __future__ import annotations

from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class AuditStep(BaseModel):
    """One serialized finding, planned action, or verification check."""

    model_config = ConfigDict(extra="forbid", strict=True)

    step_no: int
    phase: Literal["FINDING", "REMEDIATION", "VERIFICATION"]
    system_id: str
    resource_id: str
    operation: Literal[
        "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK", "REPORT_UNMAPPED_CATEGORY", "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD",
        "REDACT_RECORD", "ANONYMIZE_RECORD", "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    ]
    state: Literal[
        "PRESENT", "ACTIVE", "ABSENT", "REDACTED", "ANONYMIZED", "DISABLED", "BLOCKED"
    ]
    evidence_id: str

    @model_validator(mode="after")
    def operation_state_matches_phase(self) -> "AuditStep":
        allowed: dict[str, dict[str, set[str]]] = {
            "FINDING": {
                "REPORT_REMAINING_RECORD": {"PRESENT"}, "REPORT_EXPOSED_PII": {"PRESENT"},
                "REPORT_ACTIVE_DATA_FLOW": {"ACTIVE"}, "REPORT_RESTORE_RISK": {"ACTIVE"},
                "REPORT_UNMAPPED_CATEGORY": {"PRESENT"},
            },
            "REMEDIATION": {
                "DISABLE_DATA_FLOW": {"DISABLED"}, "BLOCK_RESTORE": {"BLOCKED"},
                "DELETE_RECORD": {"ABSENT"}, "REDACT_RECORD": {"REDACTED"},
                "ANONYMIZE_RECORD": {"ANONYMIZED"},
            },
            "VERIFICATION": {
                "VERIFY_RECORD_ABSENT": {"ABSENT"}, "VERIFY_RECORD_PRESENT": {"PRESENT"},
                "VERIFY_RECORD_REDACTED": {"REDACTED"}, "VERIFY_RECORD_ANONYMIZED": {"ANONYMIZED"},
                "VERIFY_DATA_FLOW_DISABLED": {"DISABLED"}, "VERIFY_RESTORE_BLOCKED": {"BLOCKED"},
            },
        }
        if self.state not in allowed[self.phase].get(self.operation, set()):
            raise ValueError(f"Invalid state {self.state!r} for {self.phase}/{self.operation}")
        if self.step_no < 1:
            raise ValueError("step_no must be a positive integer")
        return self


class AuditResult(BaseModel):
    """One case result with an internal completeness invariant.

    ``verification_steps`` is derived by the caller and excluded from the
    output schema. It exists so incomplete results cannot be emitted without
    a populated follow-up verification plan.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    case_id: str
    deletion_status: Literal["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]
    steps: list[AuditStep]
    verification_steps: list[AuditStep] = Field(default_factory=list, exclude=True)

    @model_validator(mode="after")
    def incomplete_requires_verification(self) -> "AuditResult":
        if self.deletion_status == "INCOMPLETE" and not self.verification_steps:
            raise ValueError(
                f"INCOMPLETE case {self.case_id} requires at least one verification step"
            )
        if self.deletion_status == "INCOMPLETE" and not any(
            step.phase == "FINDING" for step in self.steps
        ):
            raise ValueError(
                f"INCOMPLETE case {self.case_id} requires at least one identity-linked finding"
            )
        actual_verification_steps = [step for step in self.steps if step.phase == "VERIFICATION"]
        if self.verification_steps != actual_verification_steps:
            raise ValueError("verification_steps must exactly match VERIFICATION steps in steps")
        if self.deletion_status == "COMPLETE" and any(
            step.phase != "VERIFICATION" for step in self.steps
        ):
            raise ValueError(f"COMPLETE case {self.case_id} may contain only verification steps")
        if self.deletion_status == "COMPLETE" and not actual_verification_steps:
            raise ValueError(f"COMPLETE case {self.case_id} requires evidence-backed verification")
        if self.deletion_status == "COMPLETE" and any(not step.evidence_id.strip() for step in actual_verification_steps):
            raise ValueError(f"COMPLETE case {self.case_id} verification requires evidence IDs")
        if self.deletion_status == "NOT_APPLICABLE" and self.steps:
            raise ValueError(f"NOT_APPLICABLE case {self.case_id} must not contain steps")
        return self

    @classmethod
    def build(
        cls, *, case_id: str, deletion_status: str, steps: list[dict[str, Any]]
    ) -> "AuditResult":
        typed_steps = [AuditStep.model_validate(step) for step in steps]
        verification_steps = [step for step in typed_steps if step.phase == "VERIFICATION"]
        return cls(
            case_id=case_id,
            deletion_status=deletion_status,
            steps=typed_steps,
            verification_steps=verification_steps,
        )


def build_with_retry(
    *,
    case_id: str,
    generate: Callable[[], tuple[str, list[dict[str, Any]]]],
    max_attempts: int = 2,
) -> AuditResult:
    """Regenerate and validate deterministically, failing closed after retries."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    last_error: ValidationError | None = None
    for _attempt in range(max_attempts):
        status, steps = generate()
        try:
            return AuditResult.build(case_id=case_id, deletion_status=status, steps=steps)
        except ValidationError as exc:
            last_error = exc
    assert last_error is not None
    raise last_error
