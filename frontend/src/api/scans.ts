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
  error_message?: string | null
  profile_json?: string | null
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

export interface ScanAiAgentConfig {
  enabled: boolean
  mode: 'guided' | 'autonomous'
  objective?: string
  provider?: string | null
  model?: string | null
  aggressive?: boolean
  allow_privilege_escalation?: boolean
  allow_exploitation?: boolean
  allow_command_exec?: boolean
}

export interface ScanCreate {
  name: string; targets: string[]; profile: string
  description?: string; credential_id?: string
  profile_json?: string
  credentials?: ScanCredentialIn[]
  exclusions?: string[]
  ai_agent?: ScanAiAgentConfig
}

export const scansApi = {
  list: (params?: { limit?: number; offset?: number }) =>
    api.get<ScanSummary[]>('/scans', { params }).then(r => r.data),
  get: (id: string) => api.get<ScanSummary>(`/scans/${id}`).then(r => r.data),
  create: (body: ScanCreate) => api.post<ScanSummary>('/scans', body).then(r => r.data),
  update: (id: string, body: Partial<ScanCreate> & { targets?: string[] }) =>
    api.patch<ScanSummary>(`/scans/${id}`, body).then(r => r.data),
  launch: (id: string) => api.post(`/scans/${id}/launch`).then(r => r.data),
  cancel: (id: string) => api.post(`/scans/${id}/cancel`).then(r => r.data),
  delete: (id: string) => api.delete(`/scans/${id}`),
  rerun: (id: string) => api.post<ScanSummary>(`/scans/${id}/rerun`).then(r => r.data),
  clone: (id: string) => api.post<ScanSummary>(`/scans/${id}/clone`).then(r => r.data),
  hosts: (id: string) => api.get(`/scans/${id}/hosts`).then(r => r.data),
  delta: (id: string, baseline: string) =>
    api.get(`/scans/${id}/delta`, { params: { baseline } }).then(r => r.data),
  latestDelta: (id: string) => api.get(`/scans/${id}/delta/latest`).then(r => r.data),
}
