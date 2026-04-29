import api from './client'

export interface VulnerabilityItem {
  plugin_id: string
  title: string
  severity: string
  total_instances: number
  host_count: number
  open_count: number
  first_seen_at: string | null
  last_seen_at: string | null
  max_cvss: number | null
  max_vpr: number | null
}

export interface VulnHost {
  ip: string
  hostname: string | null
  finding_id: string
  port_number: number | null
  remediation_status: string
  false_positive: boolean
  scan_name: string
  scan_id: string
  created_at: string | null
}

export const vulnerabilitiesApi = {
  list: (params?: { severity?: string; search?: string; limit?: number; offset?: number }) =>
    api.get<VulnerabilityItem[]>('/vulnerabilities', { params }).then(r => r.data),
  hosts: (pluginId: string) =>
    api.get<VulnHost[]>(`/vulnerabilities/${encodeURIComponent(pluginId)}/hosts`).then(r => r.data),
}
