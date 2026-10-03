import api from './client'

export interface Finding {
  id: string; scan_id: string; host_id: string | null; host_ip: string | null
  plugin_id: string; severity: string; title: string
  description: string | null; evidence: string | null
  remediation: string | null; cvss_score: number | null; vpr_score: number | null
  impact: string | null; template_id: string | null
  /** Fix-first ranking 0-100; reasons is a JSON list of strings. */
  priority_score: number | null; priority_reasons: string | null
  epss_score: number | null; epss_percentile: number | null; is_kev: boolean
  cvss_vector: string | null; cve_ids: string | null
  first_seen_scan_id: string | null; last_seen_scan_id: string | null
  port_number: number | null; protocol: string | null
  false_positive: boolean; analyst_notes: string | null
  triaged_at: string | null; triaged_by: string | null
  compliance_tags: string | null
  mitre_tags: string | null
  references: string | null
  remediation_status: string
  /** Latest retest outcome, denormalised so lists need no extra request. */
  last_retest_at: string | null
  last_retest_verdict: RetestVerdict | null
  /** True only when ScanR mechanically reproduced the issue — never an opinion. */
  validated: boolean
  validated_at: string | null
  validation_method: string | null
  validation_evidence: string | null
  created_at: string
}

/** Report wording a tester may edit. The title is fixed: it identifies the issue across scans. */
export interface FindingTextEdit {
  severity?: string
  description?: string
  impact?: string
  remediation?: string
  evidence?: string
  cvss_score?: number
  cvss_vector?: string
  references?: string[]
}

export interface ManualFindingInput {
  template_id?: string
  title?: string
  severity?: string
  description?: string
  impact?: string
  remediation?: string
  evidence?: string
  cvss_score?: number
  cvss_vector?: string
  references?: string[]
  host?: string
  port_number?: number
  protocol?: 'tcp' | 'udp'
}

export type RetestVerdict = 'resolved' | 'still_present' | 'inconclusive'
export type RetestStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface FindingRetest {
  id: string
  finding_id: string
  status: RetestStatus
  verdict: RetestVerdict | null
  evidence: string | null
  error: string | null
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export const findingsApi = {
  list: (params?: Record<string, string | number | boolean>) =>
    api.get<Finding[]>('/findings', { params }).then(r => r.data),
  get: (id: string) => api.get<Finding>(`/findings/${id}`).then(r => r.data),
  update: (id: string, body: Partial<Pick<Finding, 'false_positive' | 'analyst_notes' | 'remediation_status'>> & FindingTextEdit) =>
    api.patch<Finding>(`/findings/${id}`, body).then(r => r.data),
  applyTemplate: (id: string, template_id: string, use_severity: boolean) =>
    api.post<Finding>(`/findings/${id}/apply-template`, { template_id, use_severity }).then(r => r.data),
  createManual: (scanId: string, body: ManualFindingInput) =>
    api.post<{ id: string }>(`/scans/${scanId}/findings/manual`, body).then(r => r.data),
  bulkUpdate: (ids: string[], body: { false_positive?: boolean; remediation_status?: string; analyst_notes?: string }) =>
    api.post<{ updated: number }>('/findings/bulk', { ids, ...body }).then(r => r.data),
  history: (id: string) => api.get<FindingHistoryEntry[]>(`/findings/${id}/history`).then(r => r.data),
  retest: (id: string) =>
    api.post<FindingRetest>(`/findings/${id}/retest`).then(r => r.data),
  retests: (id: string) =>
    api.get<FindingRetest[]>(`/findings/${id}/retests`).then(r => r.data),
}

export interface FindingHistoryEntry {
  finding_id: string
  scan_id: string
  scan_name: string
  scan_date: string | null
  remediation_status: string
  false_positive: boolean
  created_at: string
}
