import api from './client'

export interface ScanSummary {
  id: string; name: string; status: string; profile: string
  created_at: string; started_at: string | null; finished_at: string | null
  hosts_total: number; hosts_up: number
  findings_critical: number; findings_high: number; findings_medium: number
  findings_low: number; findings_info: number
  targets?: string[]
  duration_s?: number
  progress?: number
}

export interface ScanCredentialIn {
  role: string
  type: string
  username?: string
  domain?: string
  password?: string
  save_to_vault?: boolean
  vault_name?: string
}

export interface ScanCreate {
  name: string; targets: string[]; profile: string
  description?: string; credential_id?: string
  profile_json?: string
  credentials?: ScanCredentialIn[]
}

export const scansApi = {
  list: (params?: { limit?: number; offset?: number }) =>
    api.get<ScanSummary[]>('/scans', { params }).then(r => r.data),
  get: (id: string) => api.get<ScanSummary>(`/scans/${id}`).then(r => r.data),
  create: (body: ScanCreate) => api.post<ScanSummary>('/scans', body).then(r => r.data),
  launch: (id: string) => api.post(`/scans/${id}/launch`).then(r => r.data),
  cancel: (id: string) => api.post(`/scans/${id}/cancel`).then(r => r.data),
  delete: (id: string) => api.delete(`/scans/${id}`),
  hosts: (id: string) => api.get(`/scans/${id}/hosts`).then(r => r.data),
  delta: (id: string, baseline: string) =>
    api.get(`/scans/${id}/delta`, { params: { baseline } }).then(r => r.data),
}
