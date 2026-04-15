import api from './client'

export interface ScanTemplate {
  id: string
  name: string
  description: string | null
  profile_json: Record<string, unknown> | null
  is_system: boolean
  user_id: string | null
  created_at: string
}

export const templatesApi = {
  list: () => api.get<ScanTemplate[]>('/templates').then(r => r.data),
  get: (id: string) => api.get<ScanTemplate>(`/templates/${id}`).then(r => r.data),
  create: (body: { name: string; description?: string; profile_json?: Record<string, unknown> }) =>
    api.post<ScanTemplate>('/templates', body).then(r => r.data),
  update: (id: string, body: { name?: string; description?: string; profile_json?: Record<string, unknown> }) =>
    api.put<ScanTemplate>(`/templates/${id}`, body).then(r => r.data),
  delete: (id: string) => api.delete(`/templates/${id}`),
}
