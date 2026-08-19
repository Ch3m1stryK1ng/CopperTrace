#!/usr/bin/env python3
"""Require one exact CLIProxy model before CopperTrace LLM review."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ct-mini-cliproxy-preflight-v1"


def fetch_models(base_url: str, api_key: str, *, timeout: float) -> dict[str, Any]:
    endpoint = base_url.rstrip("/") + "/models"
    request = urllib.request.Request(
        endpoint,
        headers={"Authorization": f"Bearer {api_key}"},
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("CLIProxy /models response has an invalid schema")
    return payload


def probe_model(
    base_url: str,
    api_key: str,
    model: str,
    *,
    timeout: float,
    attempts: int = 2,
    retry_delay: float = 2.0,
) -> dict[str, Any]:
    endpoint = base_url.rstrip("/") + "/chat/completions"
    body = json.dumps(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Reply with OK."}],
            "reasoning_effort": "high",
            # Match the parameter family SourceAgent emits so the probe covers
            # the same OpenAI-to-Codex translation path as the live reviewer.
            "max_completion_tokens": 16384,
        }
    ).encode("utf-8")
    last_error: Exception | None = None
    payload: dict[str, Any] = {}
    completed_attempts = 0
    for attempt in range(1, max(1, attempts) + 1):
        completed_attempts = attempt
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
            last_error = None
            break
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
            last_error = exc
            if attempt < max(1, attempts):
                time.sleep(max(0.0, retry_delay))
    if last_error is not None:
        raise last_error
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        raise ValueError("CLIProxy model probe returned no completion choice")
    resolved_model = str(payload.get("model", "") or "")
    return {
        "resolved_model": resolved_model,
        "choice_count": len(choices),
        "attempts": completed_attempts,
    }


def build_preflight_record(
    *,
    base_url: str,
    api_key: str,
    expected_model_alias: str,
    timeout: float,
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        payload = fetch_models(base_url, api_key, timeout=timeout)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "PROXY_UNAVAILABLE",
            "base_url": base_url.rstrip("/"),
            "expected_model_alias": expected_model_alias,
            "exact_model_available": False,
            "exact_model_callable": False,
            "available_model_ids": [],
            "fallback_allowed": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    model_ids = sorted(
        {
            str(row.get("id", ""))
            for row in payload.get("data", [])
            if isinstance(row, dict) and str(row.get("id", ""))
        }
    )
    exact = expected_model_alias in model_ids
    base_record = {
        "schema_version": SCHEMA_VERSION,
        "base_url": base_url.rstrip("/"),
        "expected_model_alias": expected_model_alias,
        "exact_model_available": exact,
        "available_model_ids": model_ids,
        "fallback_allowed": False,
    }
    if not exact:
        return {
            **base_record,
            "status": "MODEL_UNAVAILABLE",
            "exact_model_callable": False,
            "probe": {},
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    try:
        probe = probe_model(
            base_url,
            api_key,
            expected_model_alias,
            timeout=timeout,
        )
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as exc:
        return {
            **base_record,
            "status": "MODEL_UNCALLABLE",
            "exact_model_callable": False,
            "probe": {},
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    callable_exact = probe.get("resolved_model") == expected_model_alias
    return {
        **base_record,
        "status": "READY" if callable_exact else "MODEL_ID_MISMATCH",
        "exact_model_callable": callable_exact,
        "probe": probe,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8318/v1")
    parser.add_argument("--api-key", default="coppertrace-review-local-key")
    parser.add_argument("--expected-model-alias", default="gpt-5.6-sol")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()
    record = build_preflight_record(
        base_url=args.base_url,
        api_key=args.api_key,
        expected_model_alias=args.expected_model_alias,
        timeout=max(0.1, args.timeout),
    )
    write_json(args.out, record)
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0 if record["status"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
