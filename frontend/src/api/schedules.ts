import api from './client'

export interface Schedule {
  id: string
  name: string
  description: string | null
  targets: string[]
  cron_expr: string
  enabled: boolean
  next_run: string | null
  last_run: string | null
  last_scan_id: string | null
  created_at: string
}

export const schedulesApi = {
  list: () => api.get<Schedule[]>('/schedules').then(r => r.data),
  create: (body: {
    name: string
    description?: string
    targets: string[]
    cron_expr: string
    scan_profile_json?: string
    enabled?: boolean
  }) => api.post<Schedule>('/schedules', body).then(r => r.data),
  update: (id: string, body: Partial<{ name: string; description: string; targets: string[]; cron_expr: string; scan_profile_json: string; enabled: boolean }>) =>
    api.put<Schedule>(`/schedules/${id}`, body).then(r => r.data),
  delete: (id: string) => api.delete(`/schedules/${id}`),
}
