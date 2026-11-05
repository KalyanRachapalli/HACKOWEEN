# Ghost Data Still Exists

A local dashboard and evidence-review pipeline for auditing whether deletion requests were completed. Start the dashboard with `python -m streamlit run app.py`. Install packages first with `python -m pip install -r requirements.txt`.

## How the audit works

1. Load the request, identity, activity, policy, and evidence-manifest CSV files.
2. Resolve current and historical identifiers for each request.
3. Parse relevant SQL, JSON, log, PDF, and image evidence, then normalize extracted facts to a common schema.
4. Apply the deletion rules and generate ordered findings, proposed actions, and verification checks.
5. Write `output.csv` and run the output validator.

Python performs identity resolution, policy matching, step ordering, and validation. Pydantic validates every result before CSV output and retries deterministic generation once on schema failure. Evidence extraction uses local parsers, PDF text extraction, and RapidOCR; Gemini is optional for supported unstructured evidence when configured.

For COMPLETE cases, `audit_queries.jsonl` contains executable resource-presence checks against the cited local evidence file. These checks validate the supplied dataset only; they do not connect to production systems.

## Output contract

`output.csv` must use the header `case_id,deletion_status,steps_json`, contain one sorted row for each of 518 requests, and use valid step JSON. COMPLETE cases require evidence-backed verification only. INCOMPLETE cases require findings, remediation, and future verification steps. NOT_APPLICABLE cases use `[]`.

## Project structure

- `app.py` — Streamlit dashboard, case explorer, evidence catalog, analytics, exports, and run controls.
- **Benchmark (32)** page — loads GitHub public sample requests and expected ordered outputs for in-app review.
- `src/main.py` — Pipeline entry point; supports full-dataset and single-case execution.
- `src/01_loader.py` — Loads CSVs and SQL snapshots into shared indexes.
- `src/02_identity.py` — Resolves current and historical identifiers.
- `src/03_evidence.py` — Extracts facts from evidence files and caches results.
- `src/04_evaluator.py` — Applies policy rules and generates steps.
- `src/05_steps.py` — Sorts and numbers steps.
- `src/06_validator.py` — Checks output columns, row count, ordering, states, IDs, and verification requirements.
- `src/07_normalizer.py` — Converts heterogeneous extracted facts to a canonical evidence schema.
- `src/08_query_audit.py` — Emits and runs resource-presence checks against cited local evidence.
- `src/input_models.py` — Pydantic schemas for all six source CSVs.
- `src/models.py` — Strict Pydantic schemas for steps and case results.
- `token_logger.py` — Appends thread-safe token usage records.
- `requirements.txt` — Python package requirements.
- `requirements-dev.txt` — Pytest, coverage, and parallelization tools.
- `prompts/extract_evidence.txt` — Evidence extraction prompt.
- `dataset/` — Input and evidence files; excluded from `code.zip`.
- `cache/` — Local evidence extraction cache; excluded from `code.zip`.
- `evaluation/evaluation_report.md` — Current validation and evaluation notes.
- `evaluation/usage_report.md` — Model and token usage notes.

## Local run

```powershell
python -m pip install -r requirements.txt
python -m streamlit run app.py
python src/06_validator.py
python -m pytest -q
```

