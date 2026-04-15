import api from './client'

export interface Report {
  id: string; scan_id: string; format: string
  status: string; file_path: string | null; created_at: string
}

export const reportsApi = {
  list: (scan_id?: string) => api.get<Report[]>('/reports', { params: scan_id ? { scan_id } : {} }).then(r => r.data),
  create: (scan_id: string, format: string) =>
    api.post<Report>('/reports', { scan_id, format }).then(r => r.data),
  download: async (report: Report) => {
    const resp = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
    const ext = report.format
    const filename = `report-${report.id.slice(0, 8)}.${ext}`
    const url = URL.createObjectURL(new Blob([resp.data]))
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}
