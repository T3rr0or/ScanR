import axios from 'axios'
import { useAuthStore } from '@/store/auth'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true, // send HttpOnly refresh token cookie automatically
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// Queue concurrent requests that arrive during a token refresh
let refreshing = false
let refreshQueue: Array<(token: string | null) => void> = []

function drainQueue(token: string | null) {
  refreshQueue.forEach((cb) => cb(token))
  refreshQueue = []
}

api.interceptors.response.use(
  (r) => r,
  async (err) => {
    const originalRequest = err.config
    if (err.response?.status !== 401 || originalRequest._retry) {
      return Promise.reject(err)
    }

    const { setToken, logout } = useAuthStore.getState()

    if (refreshing) {
      return new Promise((resolve, reject) => {
        refreshQueue.push((token) => {
          if (token) {
            originalRequest.headers.Authorization = `Bearer ${token}`
            resolve(api(originalRequest))
          } else {
            reject(err)
          }
        })
      })
    }

    originalRequest._retry = true
    refreshing = true

    try {
      // Refresh token is sent automatically via HttpOnly cookie
      const resp = await axios.post('/api/v1/auth/refresh', {}, { withCredentials: true })
      const { access_token } = resp.data
      setToken(access_token)
      drainQueue(access_token)
      originalRequest.headers.Authorization = `Bearer ${access_token}`
      return api(originalRequest)
    } catch {
      drainQueue(null)
      logout()
      return Promise.reject(err)
    } finally {
      refreshing = false
    }
  }
)

export default api
