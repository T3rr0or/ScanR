import api from './client'

export interface AuditEvent {
  id: string
  created_at: string
  user_id: string | null
  user_email: string | null
  auth_method: 'session' | 'api_key' | null
  ip: string | null
  action: string
  target_type: string | null
  target_id: string | null
  method: string | null
  path: string | null
  status_code: number | null
  details: string | null
}

export type AuditFilters = { user?: string; action?: string; outcome?: '' | 'allowed' | 'denied'; limit?: number; offset?: number }

function clean(filters: AuditFilters) {
  return Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== '' && v !== undefined))
}

export const auditApi = {
  list: (filters: AuditFilters) => api.get<AuditEvent[]>('/audit', { params: clean(filters) }).then(r => r.data),
  /** CSV via the authenticated client; a plain link would not carry the token. */
  exportCsv: async (filters: AuditFilters) => {
    const { data } = await api.get<Blob>('/audit/export', { params: clean({ ...filters, limit: undefined, offset: undefined }), responseType: 'blob' })
    const url = URL.createObjectURL(data)
    const a = document.createElement('a')
    a.href = url
    a.download = `scanr-audit-${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  },
}
