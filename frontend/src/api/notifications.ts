import api from './client'

export type ChannelKind = 'email' | 'slack' | 'teams'
export type NotificationEvent = 'scan.completed' | 'scan.failed'

export interface NotificationChannel {
  id: string
  name: string
  kind: ChannelKind
  /** Email address, or only the host of a webhook URL. */
  target: string
  events: NotificationEvent[]
  min_priority: number | null
  enabled: boolean
  last_status: 'sent' | 'failed' | null
  last_error: string | null
  last_sent_at: string | null
  created_at: string
}

export interface ChannelInput {
  name: string
  kind: ChannelKind
  target: string
  events: NotificationEvent[]
  min_priority: number | null
}

export const notificationsApi = {
  config: () => api.get<{ email_enabled: boolean }>('/notifications/config').then(r => r.data),
  list: () => api.get<NotificationChannel[]>('/notifications').then(r => r.data),
  create: (body: ChannelInput) => api.post<NotificationChannel>('/notifications', body).then(r => r.data),
  update: (id: string, body: Partial<Omit<ChannelInput, 'kind'>> & { enabled?: boolean; clear_min_priority?: boolean }) =>
    api.patch<NotificationChannel>(`/notifications/${id}`, body).then(r => r.data),
  remove: (id: string) => api.delete(`/notifications/${id}`),
  test: (id: string) => api.post<NotificationChannel>(`/notifications/${id}/test`).then(r => r.data),
}
