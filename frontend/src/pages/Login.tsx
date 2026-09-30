import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { useAuthStore } from '@/store/auth'
import api from '@/api/client'
import { Logo } from '@/components/Logo'

export default function Login() {
  const setToken = useAuthStore((s) => s.setToken)
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const { data } = await api.post('/auth/login', { email, password })
      qc.clear()  // purge any stale cached data from a previous session
      setToken(data.access_token)
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 401) {
        setError('Invalid credentials')
      } else {
        setError('Server unavailable. Try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-console">
      <header className="login-console-header"><Logo /><span className="mono">PENTESTING CONSOLE / AUTHENTICATION</span></header>
      <main className="login-console-main">
        <div className="login-console-title"><span className="mono">ACCESS REQUIRED</span><h1>Sign in</h1><p>Use your ScanR account to access scans, findings, and reports.</p></div>
        <form onSubmit={handleSubmit} className="login-console-form">
          <div className="login-field">
            <label htmlFor="login-email">Email address</label>
            <input id="login-email" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="admin@scanr.local" autoComplete="username" required />
          </div>
          <div className="login-field">
            <label htmlFor="login-password">Password</label>
            <input id="login-password" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
          </div>
          {error && <p className="login-error" role="alert">{error}</p>}
          <button type="submit" disabled={loading} className="login-submit">{loading ? 'Signing in…' : 'Sign in'} <span aria-hidden="true">→</span></button>
        </form>
        <p className="login-console-note">Authorized penetration testing use only.</p>
      </main>
      <footer className="login-console-footer mono"><span>SCAN/R</span><span>SELF-HOSTED SECURITY TOOL</span></footer>
    </div>
  )
}
