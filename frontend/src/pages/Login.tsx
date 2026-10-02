import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import axios from 'axios'
import { useAuthStore } from '@/store/auth'
import api from '@/api/client'
import { Logo } from '@/components/Logo'

interface SsoConfig {
  enabled: boolean
  display_name: string
}

const SSO_ERRORS: Record<string, string> = {
  no_account: 'There is no ScanR account for that identity. Ask an administrator to create one.',
  domain_not_allowed: 'Your organisation is not allowed to sign in to this ScanR instance.',
  account_disabled: 'This account is deactivated.',
  account_conflict: 'This email is already linked to a different single sign-on identity.',
  email_unverified: 'Your identity provider has not verified your email address.',
  provider_denied: 'Sign-in was cancelled or refused by the identity provider.',
  invalid_state: 'The sign-in attempt expired. Please try again.',
}

/** Read and strip the ?sso / ?sso_error parameters the SSO callback appends. */
function takeSsoResult(): { success: boolean; error: string | null } {
  const params = new URLSearchParams(window.location.search)
  const result = { success: params.get('sso') === 'success', error: params.get('sso_error') }
  if (result.success || result.error) {
    window.history.replaceState(null, '', '/')
  }
  return result
}

export default function Login() {
  const setToken = useAuthStore((s) => s.setToken)
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [sso, setSso] = useState<SsoConfig | null>(null)

  const finish = (accessToken: string) => {
    qc.clear()  // purge any stale cached data from a previous session
    setToken(accessToken)
  }

  useEffect(() => {
    const { success, error: ssoError } = takeSsoResult()
    if (ssoError) {
      setError(SSO_ERRORS[ssoError] ?? 'Single sign-on failed. Try again or use your password.')
    }
    if (success) {
      // The callback set the refresh cookie; trade it for an access token.
      setLoading(true)
      axios.post('/api/v1/auth/refresh', {}, { withCredentials: true })
        .then(({ data }) => {
          qc.clear()
          setToken(data.access_token)
        })
        .catch(() => setError('Single sign-on failed. Try again or use your password.'))
        .finally(() => setLoading(false))
    }
    api.get<SsoConfig>('/auth/oidc/config').then(({ data }) => setSso(data)).catch(() => setSso(null))
  }, [qc, setToken])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const { data } = await api.post('/auth/login', { email, password })
      if (data.mfa_required) {
        setMfaToken(data.mfa_token)
        setPassword('')
      } else {
        finish(data.access_token)
      }
    } catch (err) {
      if (axios.isAxiosError(err) && err.response?.status === 401) {
        setError('Invalid credentials')
      } else if (axios.isAxiosError(err) && err.response?.status === 429) {
        setError('Too many attempts. Wait a few minutes and try again.')
      } else {
        setError('Server unavailable. Try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleMfa = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const { data } = await api.post('/auth/login/mfa', { mfa_token: mfaToken, code })
      finish(data.access_token)
    } catch (err) {
      const status = axios.isAxiosError(err) ? err.response?.status : undefined
      const detail = axios.isAxiosError(err) ? err.response?.data?.detail : undefined
      if (status === 401 && typeof detail === 'string' && detail.startsWith('Sign-in expired')) {
        setMfaToken(null)
        setError(detail)
      } else if (status === 401) {
        setError('That code is not valid. Check your authenticator app and try again.')
      } else if (status === 429) {
        setMfaToken(null)
        setError('Too many attempts. Wait a few minutes and try again.')
      } else {
        setError('Server unavailable. Try again.')
      }
      setCode('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-console">
      <header className="login-console-header"><Logo /><span className="mono">PENTESTING CONSOLE / AUTHENTICATION</span></header>
      <main className="login-console-main">
        {mfaToken ? (
          <>
            <div className="login-console-title"><span className="mono">SECOND FACTOR</span><h1>Verify it's you</h1><p>Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p></div>
            <form onSubmit={handleMfa} className="login-console-form">
              <div className="login-field">
                <label htmlFor="login-code">Authentication code</label>
                <input id="login-code" value={code} onChange={e => setCode(e.target.value)} inputMode="numeric" autoComplete="one-time-code" autoFocus required minLength={6} maxLength={32} />
              </div>
              {error && <p className="login-error" role="alert">{error}</p>}
              <button type="submit" disabled={loading} className="login-submit">{loading ? 'Verifying…' : 'Verify'} <span aria-hidden="true">→</span></button>
              <button type="button" className="login-sso" onClick={() => { setMfaToken(null); setCode(''); setError('') }}>Back to sign in</button>
            </form>
          </>
        ) : (
          <>
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
              {sso?.enabled && (
                // A full-page navigation: the provider's login page cannot be fetched by XHR.
                <a className="login-sso" href="/api/v1/auth/oidc/login">Sign in with {sso.display_name}</a>
              )}
            </form>
          </>
        )}
        <p className="login-console-note">Authorized penetration testing use only.</p>
      </main>
      <footer className="login-console-footer mono"><span>SCAN/R</span><span>SELF-HOSTED SECURITY TOOL</span></footer>
    </div>
  )
}
