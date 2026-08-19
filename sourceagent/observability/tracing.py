"""Langfuse observability integration for BinAgent.

Opt-in: only active when ``langfuse`` is installed **and**
``LANGFUSE_PUBLIC_KEY`` is set in the environment.  When disabled every
public helper returns a lightweight no-op stub so callers never need
conditional logic.
"""

from __future__ import annotations

import functools
import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

logger = logging.getLogger("sourceagent.observability")

# ---------------------------------------------------------------------------
# No-op stubs (zero overhead when Langfuse is disabled)
# ---------------------------------------------------------------------------

class _NoOpSpan:
    """Drop-in replacement for ``langfuse.client.StatefulSpanClient``."""

    id: str = ""
    trace_id: str = ""

    def end(self, **kwargs: Any) -> None:  # noqa: D401
        pass

    def span(self, **kwargs: Any) -> "_NoOpSpan":
        return _NoOpSpan()

    def generation(self, **kwargs: Any) -> "_NoOpSpan":
        return _NoOpSpan()

    def update(self, **kwargs: Any) -> None:
        pass


class _NoOpTrace(_NoOpSpan):
    """Drop-in replacement for ``langfuse.client.StatefulTraceClient``."""

    pass


# ---------------------------------------------------------------------------
# Singleton / feature-flag
# ---------------------------------------------------------------------------

_langfuse_client: Any = None  # Will hold Langfuse() instance


@functools.lru_cache(maxsize=1)
def langfuse_enabled() -> bool:
    """Return *True* if Langfuse is both installed and configured."""
    if not os.getenv("LANGFUSE_PUBLIC_KEY"):
        return False
    try:
        import langfuse  # noqa: F401
        return True
    except ImportError:
        return False


def get_langfuse() -> Any:
    """Return the singleton ``Langfuse`` client (lazy-initialised).

    Returns ``None`` when Langfuse is disabled.
    """
    global _langfuse_client
    if not langfuse_enabled():
        return None
    if _langfuse_client is None:
        from langfuse import Langfuse
        _langfuse_client = Langfuse()
        logger.info("Langfuse client initialised")
    return _langfuse_client


# ---------------------------------------------------------------------------
# litellm callback registration
# ---------------------------------------------------------------------------

def configure_litellm_callbacks(litellm_module: Any) -> None:
    """Append ``"langfuse"`` to litellm success/failure callbacks.

    Safe to call multiple times — the callback is only added once.
    """
    if not langfuse_enabled():
        return
    if "langfuse" not in litellm_module.success_callback:
        litellm_module.success_callback.append("langfuse")
    if "langfuse" not in litellm_module.failure_callback:
        litellm_module.failure_callback.append("langfuse")
    logger.info("Registered langfuse litellm callbacks")


# ---------------------------------------------------------------------------
# Trace / span helpers
# ---------------------------------------------------------------------------

def create_trace(
    name: str,
    session_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    tags: Optional[list] = None,
) -> Any:
    """Create a Langfuse root trace (or ``_NoOpTrace`` when disabled)."""
    client = get_langfuse()
    if client is None:
        return _NoOpTrace()
    kwargs: Dict[str, Any] = {"name": name}
    if session_id:
        kwargs["session_id"] = session_id
    if metadata:
        kwargs["metadata"] = metadata
    if tags:
        kwargs["tags"] = tags
    return client.trace(**kwargs)


@contextmanager
def span_context(
    parent: Any,
    name: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Iterator[Any]:
    """Context manager that opens and auto-closes a Langfuse span.

    *parent* can be a trace or another span.  When Langfuse is disabled
    the block receives a ``_NoOpSpan``.
    """
    if not langfuse_enabled() or isinstance(parent, (_NoOpTrace, _NoOpSpan)):
        yield _NoOpSpan()
        return

    kwargs: Dict[str, Any] = {"name": name}
    if metadata:
        kwargs["metadata"] = metadata
    span = parent.span(**kwargs)
    try:
        yield span
    finally:
        try:
            span.end()
        except Exception:
            pass


def build_litellm_metadata(
    trace_id: str,
    span_id: str,
    generation_name: str,
) -> Dict[str, Any]:
    """Build the ``metadata`` dict that correlates a litellm call to Langfuse.

    Returns an empty dict when Langfuse is disabled so the caller can
    always unpack ``**metadata`` without branching.
    """
    if not langfuse_enabled():
        return {}
    return {
        "existing_trace_id": trace_id,
        "parent_observation_id": span_id,
        "generation_name": generation_name,
    }


# ---------------------------------------------------------------------------
# Shutdown
# ---------------------------------------------------------------------------

def flush() -> None:
    """Flush pending events to Langfuse.  No-op when disabled."""
    client = get_langfuse()
    if client is not None:
        try:
            client.flush()
        except Exception:
            logger.debug("langfuse flush failed", exc_info=True)
