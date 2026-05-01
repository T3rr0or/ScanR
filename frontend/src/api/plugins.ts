import api from './client'

export interface Plugin {
  id: string; name: string; description: string | null
  category: string; default_severity: string; enabled: boolean
  requires_auth: boolean; cve_ids: string | null
}

export interface PluginHealth {
  plugin_id: string
  total_runs: number
  success_count: number
  timeout_count: number
  error_count: number
  findings_count: number
  avg_duration_ms: number
  max_duration_ms: number
}

export const pluginsApi = {
  list: () => api.get<Plugin[]>('/plugins').then(r => r.data),
  health: (scanId?: string) =>
    api.get<PluginHealth[]>('/plugins/health', { params: scanId ? { scan_id: scanId } : undefined }).then(r => r.data),
  update: (id: string, body: { enabled?: boolean; config_json?: string }) =>
    api.patch<Plugin>(`/plugins/${id}`, body).then(r => r.data),
}
