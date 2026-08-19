"""LLM configuration for PentestAgent."""

import re
from dataclasses import dataclass
from typing import Optional

# Patterns that identify OpenAI reasoning models (o1, o3, gpt-5, etc.)
# These models use internal chain-of-thought and require max_completion_tokens
# instead of max_tokens, and do not support temperature != 1.
_REASONING_MODEL_RE = re.compile(
    r"(^|/)(o[0-9]|gpt-5)", re.IGNORECASE
)


def is_reasoning_model(model: str) -> bool:
    """Return True if *model* is an OpenAI reasoning model (o1, o3, gpt-5, …)."""
    return bool(_REASONING_MODEL_RE.search(model))


@dataclass
class ModelConfig:
    """LLM model configuration."""

    # Generation parameters
    temperature: float = 0.7
    max_tokens: int = 4096
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0

    # Context management
    max_context_tokens: int = 128000

    # Retry settings for rate limits
    max_retries: int = 5  # Retry up to 5 times for rate limits
    retry_delay: float = 2.0  # Base delay - will exponentially increase

    # Timeout
    timeout: int = 120

    # Whether this config targets a reasoning model (auto-detected)
    reasoning: bool = False
    reasoning_effort: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for LLM calls."""
        return {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": self.top_p,
            "frequency_penalty": self.frequency_penalty,
            "presence_penalty": self.presence_penalty,
        }

    @classmethod
    def for_model(cls, model: str) -> "ModelConfig":
        """Get configuration for a model. Uses sensible defaults for modern LLMs."""
        if is_reasoning_model(model):
            # Reasoning models (o1, o3, gpt-5) use internal chain-of-thought
            # tokens. They need a large max_completion_tokens budget so that
            # visible output isn't crowded out by reasoning tokens, and they
            # only accept temperature=1.
            return cls(
                temperature=1.0,
                max_tokens=16384,
                max_context_tokens=128000,
                reasoning=True,
            )
        return cls(temperature=0.7, max_tokens=4096, max_context_tokens=128000)


# Preset configurations
CREATIVE_CONFIG = ModelConfig(
    temperature=0.9, top_p=0.95, frequency_penalty=0.5, presence_penalty=0.5
)

PRECISE_CONFIG = ModelConfig(
    temperature=0.1, top_p=1.0, frequency_penalty=0.0, presence_penalty=0.0
)

BALANCED_CONFIG = ModelConfig(
    temperature=0.7, top_p=1.0, frequency_penalty=0.0, presence_penalty=0.0
)
