import api from './client'

export interface Agent {
  id: string
  name: string
  description: string | null
  prefix: string
  enabled: boolean
  last_seen_at: string | null
  ip_address: string | null
  agent_version: string | null
  created_at: string
}

export interface AgentCreated extends Agent {
  token: string  // shown once
}

export const agentsApi = {
  list: (includeDisabled = false) =>
    api.get<Agent[]>('/agents', { params: { include_disabled: includeDisabled } }).then(r => r.data),
  create: (body: { name: string; description?: string }) =>
    api.post<AgentCreated>('/agents', body).then(r => r.data),
  update: (id: string, body: { enabled?: boolean; name?: string }) =>
    api.patch<Agent>(`/agents/${id}`, body).then(r => r.data),
  delete: (id: string) => api.delete(`/agents/${id}`),
}
