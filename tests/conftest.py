"""Fast, offline fixtures shared by the deletion-pipeline tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("tested_evaluator", SRC / "04_evaluator.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load src/04_evaluator.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def step_sorter() -> Any:
    spec = importlib.util.spec_from_file_location("tested_steps", SRC / "05_steps.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load src/05_steps.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def request_payload() -> dict[str, str]:
    return {"case_id": "case_test", "request_text": "Please delete my account."}


@pytest.fixture
def identity_payload() -> dict[str, set[str]]:
    return {"user_ids": {"user_test"}, "emails": {"user@example.test"}}


@pytest.fixture
def mock_database_session() -> MagicMock:
    """In-memory boundary double; tests never connect to or write a database."""
    return MagicMock(name="mock_database_session")


@pytest.fixture(autouse=True)
def no_external_services(monkeypatch: pytest.MonkeyPatch) -> None:
    """Guard tests against accidental external API usage."""
    monkeypatch.setenv("GEMINI_API_KEY", "")


@pytest.fixture(scope="session")
def public_sample_rows() -> list[dict[str, str]]:
    import csv

    with (ROOT / "dataset" / "sample_output.csv").open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))
