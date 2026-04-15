import api from './client'

export interface Webhook {
  id: string
  name: string
  url: string
  events: string[]
  enabled: boolean
  last_status: number | null
  last_triggered_at: string | null
  created_at: string
}

export const webhooksApi = {
  list: () => api.get<Webhook[]>('/webhooks').then(r => r.data),
  create: (body: { name: string; url: string; secret?: string; events?: string[]; enabled?: boolean }) =>
    api.post<Webhook>('/webhooks', body).then(r => r.data),
  update: (id: string, body: Partial<Webhook & { secret: string }>) =>
    api.put<Webhook>(`/webhooks/${id}`, body).then(r => r.data),
  delete: (id: string) => api.delete(`/webhooks/${id}`),
  test: (id: string) => api.post<{ status: string; last_status: number | null }>(`/webhooks/${id}/test`).then(r => r.data),
}
