import api from './client'

export interface UserProfile {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
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
}
