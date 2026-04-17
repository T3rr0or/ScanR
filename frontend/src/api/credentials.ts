import api from './client'

export interface Credential {
  id: string
  name: string
  type: string
  username: string | null
  description: string | null
  created_at: string
}

export interface CredentialCreate {
  name: string
  type: string
  username?: string
  description?: string
  secret_data: { password?: string; private_key?: string }
}

export const credentialsApi = {
  list: () => api.get<Credential[]>('/credentials').then(r => r.data),
  create: (body: CredentialCreate) =>
    api.post<Credential>('/credentials', body).then(r => r.data),
  delete: (id: string) => api.delete(`/credentials/${id}`),
}
