import api from './client'

export interface Attachment {
  id: string
  finding_id: string
  filename: string
  content_type: string
  size: number
  sha256: string
  caption: string | null
  uploaded_by: string | null
  created_at: string
}

export const attachmentsApi = {
  list: (findingId: string) => api.get<Attachment[]>(`/findings/${findingId}/attachments`).then(r => r.data),
  upload: (findingId: string, file: File, caption = '') => {
    const form = new FormData()
    form.append('file', file)
    form.append('caption', caption)
    return api.post<Attachment>(`/findings/${findingId}/attachments`, form, { timeout: 120_000 }).then(r => r.data)
  },
  /** Bytes through the authenticated client: an <img src> could not send the token. */
  blob: (id: string) => api.get<Blob>(`/attachments/${id}/content`, { responseType: 'blob' }).then(r => r.data),
  setCaption: (id: string, caption: string) => api.patch<Attachment>(`/attachments/${id}`, { caption }).then(r => r.data),
  remove: (id: string) => api.delete(`/attachments/${id}`),
}
