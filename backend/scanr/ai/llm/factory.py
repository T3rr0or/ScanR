"""Build a configured LLMProvider from settings.

Resolves provider name, model, and API key (from config / environment). The
Anthropic default model follows Anthropic guidance (latest Opus); OpenAI and
DeepSeek defaults use well-known stable model ids. All are overridable.
"""
from __future__ import annotations

from scanr.config import get_settings

from .anthropic import AnthropicProvider
from .base import LLMProvider
from .openai_compat import OpenAICompatProvider

SUPPORTED_PROVIDERS = ("anthropic", "openai", "deepseek")

_DEFAULT_MODEL = {
    "anthropic": "claude-opus-4-8",
    "openai": "gpt-4o",
    "deepseek": "deepseek-chat",
}

_DEEPSEEK_BASE_URL = "https://api.deepseek.com"


class AIProviderError(Exception):
    """Raised when an AI provider is misconfigured (unknown provider / missing key)."""


def _api_key_for(provider: str, settings) -> str:
    return {
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
        "deepseek": settings.deepseek_api_key,
    }.get(provider, "")


def build_provider(provider: str | None = None, model: str | None = None) -> LLMProvider:
    settings = get_settings()
    provider = (provider or settings.ai_provider or "anthropic").lower()

    if provider not in SUPPORTED_PROVIDERS:
        raise AIProviderError(
            f"Unknown AI provider {provider!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}."
        )

    api_key = _api_key_for(provider, settings)
    if not api_key:
        raise AIProviderError(
            f"No API key configured for provider {provider!r}. "
            f"Set {provider.upper()}_API_KEY in the environment."
        )

    chosen_model = model or settings.ai_model or _DEFAULT_MODEL[provider]

    if provider == "anthropic":
        return AnthropicProvider(model=chosen_model, api_key=api_key)
    if provider == "deepseek":
        return OpenAICompatProvider(
            name="deepseek", model=chosen_model, api_key=api_key, base_url=_DEEPSEEK_BASE_URL
        )
    return OpenAICompatProvider(name="openai", model=chosen_model, api_key=api_key)
