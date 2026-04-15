import api from './client'

export interface Screenshot {
  id: string
  scan_id: string
  host_id: string
  port_number: number
  url: string
  file_path: string | null
  title: string | null
  status_code: number | null
  content_type: string | null
  error: string | null
}

export const screenshotsApi = {
  list: (scan_id: string) =>
    api.get<Screenshot[]>('/screenshots', { params: { scan_id } }).then(r => r.data),
  imageUrl: (id: string) => `/api/v1/screenshots/${id}/image`,
}
