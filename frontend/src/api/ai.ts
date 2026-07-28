import api from './client'

/** Display names for the provider ids the backend accepts. */
export const PROVIDER_LABEL: Record<string, string> = {
  anthropic: 'Claude',
  openai: 'ChatGPT',
  deepseek: 'DeepSeek',
}

export function providerLabel(id: string): string {
  return PROVIDER_LABEL[id] ?? id
}

export interface AiStatus {
  enabled: boolean
  default_provider: string
  providers: string[]
  /** provider -> "stored" | "env" | null */
  key_sources: Record<string, string | null>
  configured: Record<string, boolean>
  /** The operator's per-provider model override, or null. */
  model_overrides: Record<string, string | null>
  default_models: Record<string, string>
  /** Override if set, else the built-in default — what a run actually uses. */
  effective_models: Record<string, string>
}

export interface ProviderModel {
  id: string
  display_name: string
}

export const aiApi = {
  status: () => api.get<AiStatus>('/ai/status').then(r => r.data),

  /**
   * Models the provider's own API reports. Admin-only server-side (it spends the
   * stored key), so callers must tolerate a rejection and let the user type an
   * id instead.
   */
  availableModels: (provider: string) =>
    api
      .get<{ provider: string; models: ProviderModel[] }>(`/ai/models/available/${provider}`)
      .then(r => r.data.models),
}

/** Providers that actually have a key configured — the only ones worth offering. */
export function configuredProviders(status?: AiStatus): string[] {
  return (status?.providers ?? []).filter(p => status?.configured?.[p])
}

/**
 * The model a run would use given a (possibly empty) provider choice, for
 * labelling the "Default" option so the choice is never invisible.
 */
export function effectiveModelFor(status: AiStatus | undefined, provider: string): string {
  if (!status) return ''
  const p = provider || status.default_provider
  return status.effective_models?.[p] ?? ''
}
