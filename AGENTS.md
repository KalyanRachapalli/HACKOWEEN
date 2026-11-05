# AI Agent Coding Instructions & Development Guidelines

This repository implements the autonomous **Ghost Data Audit Agent** for Northstar Shop.

## Architecture
- `src/` (or `code/`): End-to-end audit engine implementing identity resolution, multimodal evidence parsing, and deterministic regulatory evaluation.
- `dataset/`: Ground-truth evidence assets, deletion requests, user audit logs, and system activity records.
- `evaluation/`: Contains `evaluation_report.md` (accuracy metrics across 32 sample cases and extra test cases) and `usage_report.md` (token accounting and model costs).
- `scripts/`: Verification scripts (`check_accuracy.py`, `check_compliance.py`).
- `output.csv`: Final certified 518-case compliance audit output.
