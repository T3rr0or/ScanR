import api from './client'

export interface Report {
  id: string; scan_id: string; format: string
  status: string; file_path: string | null; created_at: string
  error_message?: string | null; template_id?: string | null
}

export interface DocxOptions {
  template_id?: string
  title?: string
  client?: string
  author?: string
  classification?: string
  include_info?: boolean
}

export interface ReportTemplate {
  id: string
  name: string
  description: string | null
  filename: string
  size: number
  uploaded_by: string | null
  created_at: string
}

function saveBlob(data: BlobPart, filename: string) {
  const url = URL.createObjectURL(new Blob([data]))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export const reportsApi = {
  list: (scan_id?: string) => api.get<Report[]>('/reports', { params: scan_id ? { scan_id } : {} }).then(r => r.data),
  create: (scan_id: string, format: string, options: DocxOptions = {}) =>
    api.post<Report>('/reports', { scan_id, format, ...(format === 'docx' ? options : {}) }).then(r => r.data),
  download: async (report: Report) => {
    const resp = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' })
    saveBlob(resp.data, `report-${report.id.slice(0, 8)}.${report.format}`)
  },
}

export const reportTemplatesApi = {
  list: () => api.get<ReportTemplate[]>('/report-templates').then(r => r.data),
  placeholders: () => api.get<{ placeholders: Record<string, string> }>('/report-templates/placeholders').then(r => r.data.placeholders),
  downloadDefault: async () => {
    const resp = await api.get('/report-templates/default/download', { responseType: 'blob' })
    saveBlob(resp.data, 'scanr-report-template.docx')
  },
  download: async (t: ReportTemplate) => {
    const resp = await api.get(`/report-templates/${t.id}/download`, { responseType: 'blob' })
    saveBlob(resp.data, t.filename)
  },
  upload: (file: File, name: string, description: string) => {
    const form = new FormData()
    form.append('file', file)
    form.append('name', name)
    form.append('description', description)
    return api.post<ReportTemplate>('/report-templates', form).then(r => r.data)
  },
  remove: (id: string) => api.delete(`/report-templates/${id}`),
}
