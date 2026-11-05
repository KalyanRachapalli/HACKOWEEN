"""Append structured model usage records to ``token_log.jsonl``."""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
_LOG_PATH = Path("token_log.jsonl")


def log_tokens(
    *,
    model: str,
    file_id: str,
    input_tokens: int,
    output_tokens: int,
    total_tokens: int | None = None,
    path: str | Path = _LOG_PATH,
) -> None:
    """Append one token usage record; token counts must be non-negative."""
    if min(input_tokens, output_tokens) < 0:
        raise ValueError("Token counts cannot be negative")
    total = total_tokens if total_tokens is not None else input_tokens + output_tokens
    if total < 0:
        raise ValueError("Total token count cannot be negative")
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "file_id": file_id,
        "input": input_tokens,
        "output": output_tokens,
        "total": total,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
