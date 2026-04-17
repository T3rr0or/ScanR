import api from './client'

export interface Finding {
  id: string; scan_id: string; host_id: string | null; host_ip: string | null
  plugin_id: string; severity: string; title: string
  description: string | null; evidence: string | null
  remediation: string | null; cvss_score: number | null
  cvss_vector: string | null; cve_ids: string | null
  port_number: number | null; protocol: string | null
  false_positive: boolean; analyst_notes: string | null
  triaged_at: string | null; triaged_by: string | null
  compliance_tags: string | null
  mitre_tags: string | null
  references: string | null
  remediation_status: string
  created_at: string
}

export const findingsApi = {
  list: (params?: Record<string, string | number | boolean>) =>
    api.get<Finding[]>('/findings', { params }).then(r => r.data),
  get: (id: string) => api.get<Finding>(`/findings/${id}`).then(r => r.data),
  update: (id: string, body: Partial<Pick<Finding, 'false_positive' | 'analyst_notes' | 'remediation_status'>>) =>
    api.patch<Finding>(`/findings/${id}`, body).then(r => r.data),
  bulkUpdate: (ids: string[], body: { false_positive?: boolean; remediation_status?: string; analyst_notes?: string }) =>
    api.post<{ updated: number }>('/findings/bulk', { ids, ...body }).then(r => r.data),
}
