import api from './client'

export interface Wordlist {
  id: string
  name: string
  description: string | null
  type: 'usernames' | 'passwords' | 'credentials' | 'paths'
  source: 'builtin' | 'custom' | 'seclists'
  entry_count: number
  is_builtin: boolean
}

export interface WordlistPreview {
  id: string
  name: string
  type: string
  entry_count: number
  preview: string[]
}

export const wordlistsApi = {
  list: () => api.get<Wordlist[]>('/wordlists').then(r => r.data),

  upload: (file: File, name: string, type: string, description = '') => {
    const form = new FormData()
    form.append('file', file)
    form.append('name', name)
    form.append('type', type)
    form.append('description', description)
    return api.post<Wordlist>('/wordlists', form).then(r => r.data)
  },

  preview: (id: string) =>
    api.get<WordlistPreview>(`/wordlists/${id}/preview`).then(r => r.data),

  delete: (id: string) => api.delete(`/wordlists/${id}`),
}
