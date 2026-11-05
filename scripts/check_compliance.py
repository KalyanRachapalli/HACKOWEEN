"""Full compliance check of output.csv against the problem statement rules."""
import pandas as pd
import json
import sys

sys.stdout.reconfigure(encoding="utf-8")

df = pd.read_csv("output.csv", dtype=str, keep_default_na=False)

VALID_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
PHASE_OPS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD":  "PRESENT",
        "REPORT_EXPOSED_PII":       "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW":  "ACTIVE",
        "REPORT_RESTORE_RISK":      "ACTIVE",
        "REPORT_UNMAPPED_CATEGORY": "PRESENT",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW":  "DISABLED",
        "BLOCK_RESTORE":      "BLOCKED",
        "DELETE_RECORD":      "ABSENT",
        "REDACT_RECORD":      "REDACTED",
        "ANONYMIZE_RECORD":   "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT":    "ABSENT",
        "VERIFY_RECORD_PRESENT":   "PRESENT",
        "VERIFY_RECORD_REDACTED":  "REDACTED",
        "VERIFY_RECORD_ANONYMIZED":"ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED":"DISABLED",
        "VERIFY_RESTORE_BLOCKED":  "BLOCKED",
    },
}
REQUIRED_STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}

# Each rule: (passed: bool, failures: list[str])
rules = {
    "R1  Header must have exactly 3 columns (case_id, deletion_status, steps_json)": [True, []],
    "R2  Exactly 518 data rows":                                                       [True, []],
    "R3  Rows sorted by case_id":                                                      [True, []],
    "R4  deletion_status values only COMPLETE/INCOMPLETE/NOT_APPLICABLE":              [True, []],
    "R5  steps_json is valid JSON list":                                                [True, []],
    "R6  Every step has all 7 required fields":                                        [True, []],
    "R7  step_no starts at 1 and is consecutive":                                      [True, []],
    "R8  phase/operation/state combination is valid per allowed-ops table":            [True, []],
    "R9  system_id and resource_id are non-empty in every step":                       [True, []],
    "R10 COMPLETE cases: only VERIFICATION steps":                                     [True, []],
    "R11 COMPLETE VERIFICATION steps must have a non-empty evidence_id":               [True, []],
    "R12 INCOMPLETE cases: must have at least one FINDING step":                       [True, []],
    "R13 INCOMPLETE cases: must have at least one VERIFICATION step":                  [True, []],
    "R14 INCOMPLETE REMEDIATION/VERIFICATION steps: evidence_id must be empty":        [True, []],
    "R15 NOT_APPLICABLE cases: steps_json must be []":                                 [True, []],
}

def fail(rule_key, msg):
    rules[rule_key][0] = False
    rules[rule_key][1].append(msg)

# ── R1: columns ──────────────────────────────────────────────────────────────
req = {"case_id", "deletion_status", "steps_json"}
missing_cols = req - set(df.columns)
if missing_cols:
    fail("R1  Header must have exactly 3 columns (case_id, deletion_status, steps_json)",
         f"Missing: {missing_cols}")
extra_cols = set(df.columns) - req
if extra_cols:
    fail("R1  Header must have exactly 3 columns (case_id, deletion_status, steps_json)",
         f"Extra columns found: {extra_cols}")

# ── R2: row count ─────────────────────────────────────────────────────────────
if len(df) != 518:
    fail("R2  Exactly 518 data rows", f"Found {len(df)} rows")

# ── R3: sorted ────────────────────────────────────────────────────────────────
ids = df["case_id"].tolist()
if ids != sorted(ids):
    fail("R3  Rows sorted by case_id", "Rows are not sorted by case_id")

# ── Per-row checks ────────────────────────────────────────────────────────────
sc = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0, "INVALID": 0}

for _, row in df.iterrows():
    cid    = row["case_id"]
    status = row["deletion_status"]

    # R4
    if status not in VALID_STATUSES:
        fail("R4  deletion_status values only COMPLETE/INCOMPLETE/NOT_APPLICABLE",
             f"{cid}: got {status!r}")
        sc["INVALID"] += 1
        continue
    sc[status] += 1

    # R5 parse JSON
    raw_json = row["steps_json"]
    try:
        steps = json.loads(raw_json)
    except Exception as exc:
        fail("R5  steps_json is valid JSON list", f"{cid}: JSON error — {exc}")
        continue
    if not isinstance(steps, list):
        fail("R5  steps_json is valid JSON list", f"{cid}: top-level value is not a list")
        continue

    # R15
    if status == "NOT_APPLICABLE" and steps:
        fail("R15 NOT_APPLICABLE cases: steps_json must be []",
             f"{cid}: has {len(steps)} step(s)")

    if not steps:
        continue

    nums = []
    for idx, step in enumerate(steps, 1):
        phase  = str(step.get("phase",  "")).upper()
        op     = str(step.get("operation", "")).upper()
        state  = str(step.get("state",  "")).upper()
        sys_id = str(step.get("system_id", "")).strip()
        res_id = str(step.get("resource_id", "")).strip()
        eid    = str(step.get("evidence_id", "")).strip()
        sno    = step.get("step_no")

        # R6: all 7 fields
        missing = REQUIRED_STEP_FIELDS - set(step.keys())
        if missing:
            fail("R6  Every step has all 7 required fields",
                 f"{cid} step {idx}: missing field(s) {missing}")

        # R7: step_no
        if isinstance(sno, int) and not isinstance(sno, bool):
            nums.append(sno)
        else:
            fail("R7  step_no starts at 1 and is consecutive",
                 f"{cid} step {idx}: bad step_no {sno!r}")

        # R8: phase/op/state
        expected_state = PHASE_OPS.get(phase, {}).get(op)
        if expected_state is None:
            fail("R8  phase/operation/state combination is valid per allowed-ops table",
                 f"{cid} step {idx}: unknown combination phase={phase!r} op={op!r}")
        elif state != expected_state:
            fail("R8  phase/operation/state combination is valid per allowed-ops table",
                 f"{cid} step {idx}: {phase}/{op} requires state={expected_state!r}, got {state!r}")

        # R9
        if not sys_id or not res_id:
            fail("R9  system_id and resource_id are non-empty in every step",
                 f"{cid} step {idx}: sys_id={sys_id!r} res_id={res_id!r}")

        # R10
        if status == "COMPLETE" and phase != "VERIFICATION":
            fail("R10 COMPLETE cases: only VERIFICATION steps",
                 f"{cid} step {idx}: found phase={phase!r}")

        # R11
        if status == "COMPLETE" and phase == "VERIFICATION" and not eid:
            fail("R11 COMPLETE VERIFICATION steps must have a non-empty evidence_id",
                 f"{cid} step {idx}: evidence_id is empty")

        # R14
        if status == "INCOMPLETE" and phase in ("REMEDIATION", "VERIFICATION") and eid != "":
            fail("R14 INCOMPLETE REMEDIATION/VERIFICATION steps: evidence_id must be empty",
                 f"{cid} step {idx}: {phase} step has evidence_id={eid!r}")

    # R7 consecutive check
    if nums and nums != list(range(1, len(steps) + 1)):
        fail("R7  step_no starts at 1 and is consecutive",
             f"{cid}: step_no sequence is {nums}")

    # R12
    if status == "INCOMPLETE" and not any(str(s.get("phase", "")).upper() == "FINDING" for s in steps):
        fail("R12 INCOMPLETE cases: must have at least one FINDING step", f"{cid}")

    # R13
    if status == "INCOMPLETE" and not any(str(s.get("phase", "")).upper() == "VERIFICATION" for s in steps):
        fail("R13 INCOMPLETE cases: must have at least one VERIFICATION step", f"{cid}")

# ── Print report ──────────────────────────────────────────────────────────────
SEP = "=" * 66
print(SEP)
print("  OUTPUT.CSV COMPLIANCE REPORT  (Problem Statement + PDF Rules)")
print(SEP)
print(f"  File         : output.csv")
print(f"  Total rows   : {len(df)}  (required: exactly 518)")
print(f"  COMPLETE     : {sc['COMPLETE']}")
print(f"  INCOMPLETE   : {sc['INCOMPLETE']}")
print(f"  NOT_APPLIC.  : {sc['NOT_APPLICABLE']}")
if sc["INVALID"]:
    print(f"  INVALID      : {sc['INVALID']}")
print()
print("  RULE-BY-RULE RESULTS")
print("  " + "-" * 64)

all_pass = True
for rule_name, (passed, msgs) in rules.items():
    tag = "[PASS]" if passed else "[FAIL]"
    if not passed:
        all_pass = False
    print(f"  {tag}  {rule_name}")
    for m in msgs[:5]:
        print(f"           -> {m}")
    if len(msgs) > 5:
        print(f"           -> ... and {len(msgs) - 5} more violation(s)")

print()
print(SEP)
if all_pass:
    print("  OVERALL RESULT : ALL 15 RULES PASS — OUTPUT IS FULLY COMPLIANT")
else:
    failed = [k for k, (p, _) in rules.items() if not p]
    print(f"  OVERALL RESULT : {len(failed)} RULE(S) FAILED — FIXES REQUIRED")
    for f in failed:
        print(f"    * {f}")
print(SEP)
