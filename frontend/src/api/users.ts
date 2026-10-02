import api from './client'

export interface UserProfile {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  mfa_enabled?: boolean
}

export interface MfaStatus {
  enabled: boolean
  recovery_codes_remaining: number
}

export const usersApi = {
  me: () => api.get<UserProfile>('/users/me').then(r => r.data),
  updateMe: (body: { full_name?: string; email?: string }) =>
    api.patch<UserProfile>('/users/me', body).then(r => r.data),
  changePassword: (current_password: string, new_password: string) =>
    api.post('/users/me/change-password', { current_password, new_password }),
  list: () => api.get<UserProfile[]>('/users').then(r => r.data),
  create: (body: { email: string; password: string; full_name?: string; role?: string }) =>
    api.post<UserProfile>('/users', body).then(r => r.data),
  update: (id: string, body: { full_name?: string; email?: string; role?: string; is_active?: boolean }) =>
    api.patch<UserProfile>(`/users/${id}`, body).then(r => r.data),
  deactivate: (id: string) => api.delete(`/users/${id}`),
  resetMfa: (id: string) => api.post<UserProfile>(`/users/${id}/mfa/reset`).then(r => r.data),
  mfaStatus: () => api.get<MfaStatus>('/users/me/mfa').then(r => r.data),
  mfaSetup: (password: string) =>
    api.post<{ secret: string; otpauth_uri: string }>('/users/me/mfa/setup', { password }).then(r => r.data),
  mfaEnable: (code: string) =>
    api.post<{ recovery_codes: string[] }>('/users/me/mfa/enable', { code }).then(r => r.data),
  mfaDisable: (password: string, code: string) => api.post('/users/me/mfa/disable', { password, code }),
  mfaRegenerateRecoveryCodes: (code: string) =>
    api.post<{ recovery_codes: string[] }>('/users/me/mfa/recovery-codes', { code }).then(r => r.data),
}
