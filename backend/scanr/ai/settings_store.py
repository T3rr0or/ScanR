"""Runtime AI settings stored (encrypted) in the database.

API keys entered from the web app live here as Fernet ciphertext (via the
credential vault) and take precedence over environment variables. Keys are
never returned to the client — only whether one is configured.
"""
from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from scanr.config import get_settings
from scanr.credentials import vault
from scanr.models import AppSetting

SUPPORTED_PROVIDERS = ("anthropic", "openai", "deepseek")

_KEY_PREFIX = "ai.api_key."
_PROVIDER_KEY = "ai.provider"
_MODEL_PREFIX = "ai.model."  # per-provider model override, e.g. ai.model.anthropic


async def _get_raw(db: AsyncSession, key: str) -> str | None:
    row = await db.execute(select(AppSetting.value).where(AppSetting.key == key))
    return row.scalar_one_or_none()


async def _set_raw(db: AsyncSession, key: str, value: str) -> None:
    existing = await db.get(AppSetting, key)
    if existing is None:
        db.add(AppSetting(key=key, value=value))
    else:
        existing.value = value
    await db.commit()


async def _delete_raw(db: AsyncSession, key: str) -> None:
    await db.execute(delete(AppSetting).where(AppSetting.key == key))
    await db.commit()


async def _get_secret(db: AsyncSession, key: str) -> str | None:
    raw = await _get_raw(db, key)
    if not raw:
        return None
    try:
        return vault.decrypt(raw).get("v")
    except Exception:
        return None


async def set_api_key(db: AsyncSession, provider: str, api_key: str) -> None:
    """Store an encrypted provider API key. Raises VaultError if no VAULT_KEY."""
    await _set_raw(db, _KEY_PREFIX + provider, vault.encrypt({"v": api_key}))


async def clear_api_key(db: AsyncSession, provider: str) -> None:
    await _delete_raw(db, _KEY_PREFIX + provider)


async def get_stored_api_key(db: AsyncSession, provider: str) -> str | None:
    return await _get_secret(db, _KEY_PREFIX + provider)


def _env_api_key(provider: str) -> str:
    settings = get_settings()
    return {
        "anthropic": settings.anthropic_api_key,
        "openai": settings.openai_api_key,
        "deepseek": settings.deepseek_api_key,
    }.get(provider, "")


async def resolve_api_key(db: AsyncSession, provider: str) -> str:
    """Stored key wins over the environment variable; '' if neither is set."""
    return (await get_stored_api_key(db, provider)) or _env_api_key(provider)


async def key_sources(db: AsyncSession) -> dict[str, str | None]:
    """For each provider, where its key comes from: 'stored' | 'env' | None."""
    out: dict[str, str | None] = {}
    for provider in SUPPORTED_PROVIDERS:
        if await get_stored_api_key(db, provider):
            out[provider] = "stored"
        elif _env_api_key(provider):
            out[provider] = "env"
        else:
            out[provider] = None
    return out


async def get_default_provider(db: AsyncSession) -> str:
    return (await _get_raw(db, _PROVIDER_KEY)) or get_settings().ai_provider


async def set_default_provider(db: AsyncSession, provider: str) -> None:
    await _set_raw(db, _PROVIDER_KEY, provider)


async def get_model(db: AsyncSession, provider: str) -> str | None:
    """Stored per-provider model override, or the global AI_MODEL env, else None
    (None means: let the factory use the provider's built-in default)."""
    stored = await _get_raw(db, _MODEL_PREFIX + provider)
    if stored:
        return stored
    return get_settings().ai_model or None


async def set_model(db: AsyncSession, provider: str, model: str) -> None:
    """Set (or, with an empty string, clear) the model override for a provider."""
    if model.strip():
        await _set_raw(db, _MODEL_PREFIX + provider, model.strip())
    else:
        await _delete_raw(db, _MODEL_PREFIX + provider)


async def models(db: AsyncSession) -> dict[str, str | None]:
    """For each provider, its stored model override (None if using the default)."""
    return {p: await _get_raw(db, _MODEL_PREFIX + p) for p in SUPPORTED_PROVIDERS}
