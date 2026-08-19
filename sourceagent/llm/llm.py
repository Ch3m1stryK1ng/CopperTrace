"""LiteLLM wrapper for PentestAgent."""

import asyncio
import os
import random
import warnings
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, AsyncIterator, List, Optional

from ..config.constants import DEFAULT_MODEL
from .config import ModelConfig, is_reasoning_model
from .memory import ConversationMemory

if TYPE_CHECKING:
    from ..knowledge import RAGEngine
    from ..tools import Tool


@dataclass
class LLMResponse:
    """Response from LLM."""

    content: Optional[str]
    tool_calls: Optional[List[Any]]
    usage: Optional[dict]
    model: str = ""
    finish_reason: str = ""


def sanitize_tool_protocol_messages(messages: List[dict]) -> List[dict]:
    """
    Ensure tool-role messages only appear after matching assistant tool_calls.

    Memory summarization/truncation can remove the assistant tool_calls message
    while leaving trailing tool messages, which OpenAI rejects as invalid.
    """
    sanitized: List[dict] = []
    open_tool_ids: set[str] = set()

    for message in messages:
        role = message.get("role")

        if role == "assistant":
            open_tool_ids = set()
            for tool_call in message.get("tool_calls") or []:
                tc_id = tool_call.get("id")
                if tc_id:
                    open_tool_ids.add(tc_id)
            sanitized.append(message)
            continue

        if role == "tool":
            tool_call_id = message.get("tool_call_id")
            if tool_call_id and tool_call_id in open_tool_ids:
                sanitized.append(message)
                open_tool_ids.discard(tool_call_id)
            continue

        sanitized.append(message)

    return sanitized


class LLM:
    """LiteLLM wrapper with tool calling support."""

    def __init__(
        self,
        model: str = None,
        config: Optional[ModelConfig] = None,
        rag_engine: Optional["RAGEngine"] = None,
    ):
        """
        Initialize the LLM wrapper.

        Args:
            model: The model to use (supports LiteLLM model names)
            config: Model configuration
            rag_engine: Optional RAG engine for context injection
        """
        self.model = model or DEFAULT_MODEL
        self.config = config or ModelConfig.for_model(self.model)
        self.rag_engine = rag_engine
        self.memory = ConversationMemory(max_tokens=self.config.max_context_tokens)

        # Ensure litellm is available
        try:
            # If user provided an Ollama base URL (e.g. via .env), map it to
            # several common environment variable names that LiteLLM or
            # underlying Ollama clients may read. This helps when different
            # naming conventions are used (OLLAMA_BASE_URL vs LITELLM_OLLAMA_*).
            ollama_base = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_URL")
            if ollama_base:
                # Populate a few possible names without overwriting any that
                # are already set by the environment.
                os.environ.setdefault("OLLAMA_BASE_URL", ollama_base)
                os.environ.setdefault("OLLAMA_URL", ollama_base)
                os.environ.setdefault("OLLAMA_API_URL", ollama_base)
                os.environ.setdefault("LITELLM_OLLAMA_BASE_URL", ollama_base)
                os.environ.setdefault("LITELLM_OLLAMA_URL", ollama_base)
                # Some clients expect a host without scheme
                host_only = ollama_base.replace("http://", "").replace("https://", "")
                os.environ.setdefault("OLLAMA_HOST", host_only)

            import litellm

            # Suppress harmless pydantic serialization warnings from litellm
            # (ResponseAPIUsage schema mismatches with newer OpenAI models)
            warnings.filterwarnings("ignore", message="Pydantic serializer warnings")

            # Drop unsupported params for models that don't support them
            litellm.drop_params = True

            # Enable debug mode if SOURCEAGENT_DEBUG is set
            if os.getenv("SOURCEAGENT_DEBUG", "false").lower() in ("true", "1", "yes"):
                litellm.set_verbose = True
                import logging

                logging.basicConfig(level=logging.DEBUG)

            self._litellm = litellm

            # Register Langfuse observability callbacks (no-op if disabled)
            from ..observability import configure_litellm_callbacks
            configure_litellm_callbacks(litellm)
        except ImportError as e:
            raise ImportError(
                "litellm is required for LLM functionality. "
                "Install with: pip install litellm"
            ) from e

    def _is_rate_limit_error(self, error: Exception) -> bool:
        """Check if an error is a rate limit error."""
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()
        return (
            "rate" in error_str
            and "limit" in error_str
            or "ratelimit" in error_type
            or "429" in error_str
            or "too many requests" in error_str
        )

    async def _retry_with_backoff(self, coro_factory, max_retries: int = None):
        """
        Retry a coroutine with exponential backoff for rate limits.

        Args:
            coro_factory: A callable that returns a new coroutine each call
            max_retries: Max retry attempts (uses config if not specified)
        """
        retries = max_retries or self.config.max_retries
        base_delay = self.config.retry_delay

        for attempt in range(retries + 1):
            try:
                return await coro_factory()
            except Exception as e:
                if not self._is_rate_limit_error(e) or attempt >= retries:
                    raise

                # Exponential backoff with jitter
                delay = base_delay * (2**attempt) + random.uniform(0, 1)
                await asyncio.sleep(delay)

        # Should not reach here
        raise RuntimeError("Retry logic failed unexpectedly")

    async def generate(
        self,
        system_prompt: str,
        messages: List[dict],
        tools: Optional[List["Tool"]] = None,
        stream: bool = False,
        metadata: Optional[dict] = None,
    ) -> LLMResponse:
        """
        Generate a response from the LLM.

        Args:
            system_prompt: The system prompt
            messages: Conversation messages
            tools: Available tools for function calling
            stream: Whether to stream the response

        Returns:
            LLMResponse with the result
        """
        # Build messages list
        llm_messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history with summarization if needed
        history = await self.memory.get_messages_with_summary(
            messages, llm_call=self._summarize_call
        )
        llm_messages.extend(history)
        llm_messages = sanitize_tool_protocol_messages(llm_messages)

        # Build tools list
        llm_tools = None
        if tools:
            llm_tools = [tool.to_llm_format() for tool in tools if tool.enabled]

        try:
            # Build call kwargs - only pass non-default optional params
            # to avoid conflicts (e.g., Claude doesn't allow temperature + top_p together)
            _is_reasoning = is_reasoning_model(self.model)

            call_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": llm_messages,
            }
            call_kwargs.update(self._provider_call_overrides())

            if _is_reasoning:
                # Reasoning models (o1, o3, gpt-5) consume internal reasoning
                # tokens.  They require max_completion_tokens (not max_tokens)
                # and only accept temperature=1.
                call_kwargs["max_completion_tokens"] = self.config.max_tokens
                if self.config.reasoning_effort:
                    call_kwargs["reasoning_effort"] = self.config.reasoning_effort
            else:
                call_kwargs["temperature"] = self.config.temperature
                call_kwargs["max_tokens"] = self.config.max_tokens

            # Only include tools if they exist (Anthropic requires tools param to be omitted, not None/empty)
            if llm_tools:
                call_kwargs["tools"] = llm_tools

            # Forward Langfuse tracing metadata when provided
            if metadata:
                call_kwargs["metadata"] = metadata

            # Only add optional params if explicitly changed from defaults
            # (reasoning models don't support these sampling params)
            if not _is_reasoning:
                if self.config.top_p != 1.0:
                    call_kwargs["top_p"] = self.config.top_p
                if self.config.frequency_penalty != 0.0:
                    call_kwargs["frequency_penalty"] = self.config.frequency_penalty
                if self.config.presence_penalty != 0.0:
                    call_kwargs["presence_penalty"] = self.config.presence_penalty

            # Call LLM with retry for rate limits
            async def _call():
                return await self._litellm.acompletion(**call_kwargs)

            response = await self._retry_with_backoff(_call)

            # Parse response
            choice = response.choices[0]
            message = choice.message

            # Handle usage - convert to dict safely
            usage_dict = None
            if response.usage:
                try:
                    usage_dict = dict(response.usage)
                except (TypeError, ValueError):
                    usage_dict = {
                        "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
                        "completion_tokens": getattr(
                            response.usage, "completion_tokens", 0
                        ),
                        "total_tokens": getattr(response.usage, "total_tokens", 0),
                    }

            # Record usage to persistent tracker if available (best-effort)
            try:
                from ..tools import token_tracker

                if usage_dict:
                    p = usage_dict.get("prompt_tokens", 0) or 0
                    c = usage_dict.get("completion_tokens", 0) or 0
                    # Use sync record helper to avoid event-loop coupling
                    try:
                        token_tracker.record_usage_sync(int(p), int(c))
                    except Exception:
                        # Swallow tracker errors - usage recording is best-effort
                        pass
            except Exception:
                # Tools package or token_tracker missing - ignore
                pass

            return LLMResponse(
                content=message.content,
                tool_calls=message.tool_calls,
                usage=usage_dict,
                model=response.model if hasattr(response, "model") else self.model,
                finish_reason=choice.finish_reason or "",
            )

        except Exception as e:
            # Walk the exception chain to include root causes — litellm
            # sometimes wraps the real error (e.g. 401 invalid_api_key) in a
            # secondary TypeError, losing the original message.
            parts = [f"LLM Error: {e}"]
            cause = e.__cause__ or e.__context__
            depth = 0
            while cause and depth < 5:
                parts.append(f"  Caused by: {cause}")
                cause = cause.__cause__ or cause.__context__
                depth += 1
            error_text = "\n".join(parts)
            # Return error as response (after retries exhausted)
            return LLMResponse(
                content=error_text,
                tool_calls=None,
                usage=None,
                model=self.model,
                finish_reason="error",
            )

    async def generate_stream(
        self,
        system_prompt: str,
        messages: List[dict],
        tools: Optional[List["Tool"]] = None,
    ) -> AsyncIterator[str]:
        """
        Stream a response from the LLM.

        Args:
            system_prompt: The system prompt
            messages: Conversation messages
            tools: Available tools for function calling

        Yields:
            Response content chunks
        """
        llm_messages = [{"role": "system", "content": system_prompt}]
        history = await self.memory.get_messages_with_summary(
            messages, llm_call=self._summarize_call
        )
        llm_messages.extend(history)
        llm_messages = sanitize_tool_protocol_messages(llm_messages)

        llm_tools = None
        if tools:
            llm_tools = [tool.to_llm_format() for tool in tools if tool.enabled]

        try:
            _is_reasoning = is_reasoning_model(self.model)
            stream_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": llm_messages,
                "tools": llm_tools,
                "stream": True,
            }
            stream_kwargs.update(self._provider_call_overrides())
            if _is_reasoning:
                stream_kwargs["max_completion_tokens"] = self.config.max_tokens
                if self.config.reasoning_effort:
                    stream_kwargs["reasoning_effort"] = self.config.reasoning_effort
            else:
                stream_kwargs["temperature"] = self.config.temperature
                stream_kwargs["max_tokens"] = self.config.max_tokens

            response = await self._litellm.acompletion(**stream_kwargs)

            async for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            yield f"\nLLM Error: {str(e)}"

    async def simple_completion(
        self, prompt: str, system: str = "You are a helpful assistant."
    ) -> str:
        """
        Simple completion without tools.

        Args:
            prompt: The user prompt
            system: The system prompt

        Returns:
            The response text
        """
        response = await self.generate(
            system_prompt=system,
            messages=[{"role": "user", "content": prompt}],
            tools=None,
        )
        return response.content or ""

    def set_model(self, model: str):
        """Change the model."""
        self.model = model

    def update_config(self, **kwargs):
        """Update configuration parameters."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    async def _summarize_call(self, prompt: str) -> str:
        """
        Internal LLM call for summarization.

        Args:
            prompt: The summarization prompt

        Returns:
            Summary text
        """
        try:
            _is_reasoning = is_reasoning_model(self.model)
            sum_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a terse summarizer for a pentesting agent.",
                    },
                    {"role": "user", "content": prompt},
                ],
            }
            sum_kwargs.update(self._provider_call_overrides())
            if _is_reasoning:
                sum_kwargs["max_completion_tokens"] = 1000
                if self.config.reasoning_effort:
                    sum_kwargs["reasoning_effort"] = self.config.reasoning_effort
            else:
                sum_kwargs["temperature"] = 0.3
                sum_kwargs["max_tokens"] = 1000

            response = await self._litellm.acompletion(**sum_kwargs)
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"[Summarization failed: {e}]"

    def clear_memory(self):
        """Clear conversation memory and summary cache."""
        self.memory.clear_summary_cache()

    def _provider_call_overrides(self) -> dict[str, Any]:
        """Return provider-specific call kwargs needed by LiteLLM.

        We keep this narrow on purpose so existing OpenAI/Anthropic behavior
        does not change. Ollama Cloud needs the remote host + bearer key
        propagated explicitly; otherwise LiteLLM may fall back to the local
        Ollama default at ``localhost:11434``.
        """
        model = str(self.model or "").strip().lower()
        if not (model.startswith("ollama/") or model.startswith("ollama_chat/")):
            return {}

        api_base = os.getenv("OLLAMA_BASE_URL") or os.getenv("OLLAMA_URL")
        api_key = os.getenv("OLLAMA_API_KEY")
        overrides: dict[str, Any] = {}
        if api_base:
            overrides["api_base"] = api_base
        if api_key:
            overrides["api_key"] = api_key
        return overrides

    def get_memory_stats(self) -> dict:
        """Get memory usage statistics."""
        return self.memory.get_stats()

    def get_available_models(self) -> List[str]:
        """
        Get list of commonly available models.

        Returns:
            List of model names
        """
        return [
            # OpenAI
            "gpt-5",
            "gpt-4.1",
            "gpt-4.1-mini",
            "gpt-4.1-nano",
            # Anthropic
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            # Google
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            # Others via LiteLLM
            "ollama/llama3",
            "ollama/mixtral",
            "groq/llama3-70b-8192",
        ]
