import api from './client'

export interface APIKey {
  id: string
  name: string
  prefix: string
  scopes: string[]
  last_used_at: string | null
  expires_at: string | null
  revoked: boolean
  created_at: string
}

export interface APIKeyCreated extends APIKey {
  key: string  // raw key shown once only
}

export const apiKeysApi = {
  list: () => api.get<APIKey[]>('/api-keys').then(r => r.data),
  create: (body: { name: string; scopes?: string[]; expires_at?: string }) =>
    api.post<APIKeyCreated>('/api-keys', body).then(r => r.data),
  revoke: (id: string) => api.delete(`/api-keys/${id}`),
}
