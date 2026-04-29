import api from './client'
import type { Finding } from './findings'

export interface AssetItem {
  ip: string
  hostname: string | null
  os_name: string | null
  os_family: string | null
  last_seen_at: string | null
  first_seen_at: string | null
  scan_count: number
  findings_critical: number
  findings_high: number
  findings_medium: number
  findings_low: number
  risk_score: number
  tags?: string[]
}

export const assetsApi = {
  list: (params?: { search?: string; limit?: number; offset?: number }) =>
    api.get<AssetItem[]>('/assets', { params }).then(r => r.data),
  findings: (ip: string) =>
    api.get<Finding[]>(`/assets/${encodeURIComponent(ip)}/findings`).then(r => r.data),
  tags: (ip: string) =>
    api.get<string[]>('/host-tags', { params: { ip } }).then(r => r.data),
  allTags: () =>
    api.get<Record<string, string[]>>('/host-tags/all').then(r => r.data),
  addTag: (ip: string, tag: string) =>
    api.post('/host-tags', null, { params: { ip, tag } }).then(r => r.data),
  removeTag: (ip: string, tag: string) =>
    api.delete('/host-tags', { params: { ip, tag } }),
}
