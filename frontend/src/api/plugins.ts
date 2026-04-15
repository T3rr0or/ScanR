import api from './client'

export interface Plugin {
  id: string; name: string; description: string | null
  category: string; default_severity: string; enabled: boolean
  requires_auth: boolean; cve_ids: string | null
}

export const pluginsApi = {
  list: () => api.get<Plugin[]>('/plugins').then(r => r.data),
  update: (id: string, body: { enabled?: boolean; config_json?: string }) =>
    api.patch<Plugin>(`/plugins/${id}`, body).then(r => r.data),
}
