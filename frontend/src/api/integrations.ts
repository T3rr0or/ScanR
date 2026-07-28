import api from './client'

export interface TopdeskStatus {
  configured: boolean
  url: string | null
  username: string | null
  /** Whether an application password is stored. The password itself is never returned. */
  has_password: boolean
}

export interface TopdeskConfigBody {
  url: string
  username: string
  /** Omit to keep the stored password — lets the URL be edited without re-entering it. */
  password?: string
  defaults?: Record<string, unknown>
}

export interface TicketLink {
  id: string
  finding_id: string
  provider: string
  external_id: string
  external_key: string | null
  url: string | null
  external_status: string | null
  created_at: string
  /** False when an existing incident was adopted rather than a new one opened. */
  created?: boolean
}

export const integrationsApi = {
  topdeskStatus: () =>
    api.get<TopdeskStatus>('/integrations/topdesk').then(r => r.data),
  saveTopdesk: (body: TopdeskConfigBody) =>
    api.put('/integrations/topdesk', body).then(r => r.data),
  deleteTopdesk: () => api.delete('/integrations/topdesk').then(r => r.data),
  testTopdesk: () =>
    api.post<{ ok: boolean }>('/integrations/topdesk/test').then(r => r.data),
  getTicket: (findingId: string) =>
    api.get<TicketLink>(`/integrations/topdesk/findings/${findingId}/ticket`).then(r => r.data),
  createTicket: (findingId: string) =>
    api.post<TicketLink>(`/integrations/topdesk/findings/${findingId}/ticket`).then(r => r.data),
}
