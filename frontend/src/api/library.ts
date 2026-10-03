import api from './client'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface LibraryEntryInput {
  title: string
  severity: Severity
  cvss_score: number | null
  cvss_vector: string | null
  description: string
  impact: string | null
  remediation: string | null
  references: string[]
  cve_ids: string[]
  tags: string[]
  /** Scanner plugin ids this entry describes; optional title substring narrows it. */
  plugin_ids: string[]
  title_match: string | null
}

export interface LibraryEntry extends LibraryEntryInput {
  id: string
  created_by: string | null
  updated_by: string | null
  created_at: string
  updated_at: string
  usage_count: number
}

export const libraryApi = {
  list: (params?: { q?: string; severity?: string }) =>
    api.get<LibraryEntry[]>('/library', { params }).then(r => r.data),
  create: (body: LibraryEntryInput) => api.post<LibraryEntry>('/library', body).then(r => r.data),
  update: (id: string, body: LibraryEntryInput) => api.put<LibraryEntry>(`/library/${id}`, body).then(r => r.data),
  remove: (id: string) => api.delete(`/library/${id}`),
  exportAll: () => api.get<{ scanr_finding_library: number; entries: LibraryEntryInput[] }>('/library/export').then(r => r.data),
  importAll: (entries: LibraryEntryInput[], overwrite: boolean) =>
    api.post<{ added: number; updated: number; skipped: number }>('/library/import', { entries, overwrite }).then(r => r.data),
}
