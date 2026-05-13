import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { type LucideIcon, Key, Webhook, Copy, Check, Trash2, Plus, Send, Database, RefreshCw, Settings as SettingsIcon, User, Users, Monitor, ExternalLink, Terminal } from 'lucide-react'
import { apiKeysApi, type APIKeyCreated } from '@/api/apiKeys'
import { webhooksApi } from '@/api/webhooks'
import api from '@/api/client'
import { relTime } from '@/components/ui'
import { useAuthStore } from '@/store/auth'

type Tab = 'profile' | 'api-keys' | 'webhooks' | 'cve' | 'users' | 'system'

const TABS: { id: Tab; label: string; Icon: LucideIcon; adminOnly?: boolean }[] = [
  { id: 'profile', label: 'Profile', Icon: User },
  { id: 'api-keys', label: 'API Keys', Icon: Key },
  { id: 'webhooks', label: 'Webhooks', Icon: Webhook },
  { id: 'cve', label: 'CVE Database', Icon: Database },
  { id: 'system', label: 'System', Icon: Monitor, adminOnly: true },
  { id: 'users', label: 'Users', Icon: Users, adminOnly: true },
]

export default function Settings() {
  const [activeTab, setActiveTab] = useState<Tab>('profile')
  const token = useAuthStore(s => s.token)

  // Decode role from JWT to show admin-only tabs
  let role = 'analyst'
  try {
    const payload = JSON.parse(atob(token!.split('.')[1]))
    role = payload.role ?? 'analyst'
  } catch {}

  const visibleTabs = TABS.filter(t => !t.adminOnly || role === 'admin')

  return (
    <div className="page-pad">
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
        <SettingsIcon size={18} style={{ color: 'var(--accent)' }} />
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Settings</h1>
      </div>

      <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div className="panel" style={{ width: 'clamp(140px, 25vw, 180px)', flexShrink: 0, padding: 6 }}>
          {visibleTabs.map(({ id, label, Icon }) => {
            const active = activeTab === id
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  width: '100%', padding: '8px 10px', borderRadius: 6,
                  background: active ? 'var(--bg-3)' : 'transparent',
                  border: active ? '1px solid var(--border)' : '1px solid transparent',
                  cursor: 'pointer', textAlign: 'left', marginBottom: 2,
                  color: active ? 'var(--text-0)' : 'var(--text-2)',
                }}
              >
                <Icon size={13} />
                <span style={{ fontSize: 13, fontWeight: active ? 600 : 400 }}>{label}</span>
              </button>
            )
          })}
        </div>

        <div style={{ flex: 1, minWidth: 0, maxWidth: 700 }}>
          {activeTab === 'profile' && <ProfileSection />}
          {activeTab === 'api-keys' && <ApiKeysSection />}
          {activeTab === 'webhooks' && <WebhooksSection />}
          {activeTab === 'cve' && <CveDatabaseSection />}
          {activeTab === 'system' && role === 'admin' && <SystemSection />}
          {activeTab === 'users' && role === 'admin' && <UserManagementSection />}
        </div>
      </div>
    </div>
  )
}

/* ── Profile ────────────────────────────────────────────────── */
function ProfileSection() {
  const qc = useQueryClient()
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => api.get('/users/me').then(r => r.data) })
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [curPwd, setCurPwd] = useState('')
  const [newPwd, setNewPwd] = useState('')
  const [pwdErr, setPwdErr] = useState<string | null>(null)
  const [pwdOk, setPwdOk] = useState(false)

  const profileMut = useMutation({
    mutationFn: () => api.patch('/users/me', {
      ...(name ? { full_name: name } : {}),
      ...(email ? { email } : {}),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['me'] }); setName(''); setEmail('') },
  })

  const pwdMut = useMutation({
    mutationFn: () => api.post('/users/me/change-password', { current_password: curPwd, new_password: newPwd }),
    onSuccess: () => { setCurPwd(''); setNewPwd(''); setPwdErr(null); setPwdOk(true); setTimeout(() => setPwdOk(false), 3000) },
    onError: (e: unknown) => setPwdErr(e instanceof Error ? e.message : 'Failed'),
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Identity */}
      <div className="panel" style={{ padding: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>Profile</div>
        {me && <div style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 12 }}>
          <strong>{me.email}</strong> · {me.role} · {me.full_name || <span style={{ opacity: 0.5 }}>no name set</span>}
        </div>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input className="input" placeholder="New display name" value={name} onChange={e => setName(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
          <input className="input" placeholder="New email" type="email" value={email} onChange={e => setEmail(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
          <button className="btn btn-primary btn-sm" onClick={() => profileMut.mutate()} disabled={(!name && !email) || profileMut.isPending}>
            {profileMut.isPending ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>

      {/* Password */}
      <div className="panel" style={{ padding: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>Change Password</div>
        {pwdErr && <div style={{ color: 'var(--sev-high)', fontSize: 12, marginBottom: 8 }}>{pwdErr}</div>}
        {pwdOk && <div style={{ color: 'var(--ok)', fontSize: 12, marginBottom: 8 }}>Password changed.</div>}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <input className="input" type="password" placeholder="Current password" value={curPwd} onChange={e => setCurPwd(e.target.value)} style={{ flex: 1, minWidth: 180 }} />
          <input className="input" type="password" placeholder="New password (min 10 chars)" value={newPwd} onChange={e => setNewPwd(e.target.value)} style={{ flex: 1, minWidth: 220 }} />
          <button className="btn btn-primary btn-sm" onClick={() => pwdMut.mutate()} disabled={!curPwd || newPwd.length < 10 || pwdMut.isPending}>
            {pwdMut.isPending ? 'Changing…' : 'Change'}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ── System ──────────────────────────────────────────────── */
function SystemSection() {
  const { data: ver } = useQuery({
    queryKey: ['system-version'],
    queryFn: () => api.get('/system/version').then(r => r.data),
    refetchInterval: 300_000, // every 5 min
  })

  const updateAvailable = ver?.update_available
  const latestVersion = ver?.latest
  const currentVersion = ver?.current
  const releaseUrl = ver?.release_url

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Version */}
      <div className="panel" style={{ padding: 16 }}>
        <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>ScanR Version</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <span className="mono" style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-0)' }}>v{currentVersion || '...'}</span>
          {updateAvailable && (
            <span style={{
              fontSize: 11, fontWeight: 600, padding: '2px 8px', borderRadius: 12,
              background: 'oklch(0.25 0.1 60 / 0.3)', color: 'var(--sev-medium)',
            }}>
              Update available: v{latestVersion}
            </span>
          )}
          {!updateAvailable && ver && (
            <span style={{ fontSize: 11, color: 'var(--ok)', fontWeight: 500 }}>Up to date</span>
          )}
        </div>

        {updateAvailable && (
          <>
            <div style={{
              background: 'var(--bg-1)', border: '1px solid var(--border)', borderRadius: 8,
              padding: 14, marginTop: 8, marginBottom: 12,
            }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-0)', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Terminal size={13} />
                Update via Docker Compose
              </div>
              <div style={{
                background: 'var(--bg-0)', border: '1px solid var(--border)', borderRadius: 6,
                padding: '10px 14px',
              }}>
                <code style={{ fontSize: 12, color: 'var(--text-1)', whiteSpace: 'pre-wrap' }}>
{`cd /opt/scanr
docker compose pull
docker compose up -d`}
                </code>
              </div>
              <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                <CopyButton text="cd /opt/scanr && docker compose pull && docker compose up -d" />
                {releaseUrl && (
                  <a
                    href={releaseUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-ghost btn-sm"
                    style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12, textDecoration: 'none' }}
                  >
                    <ExternalLink size={12} /> Release Notes
                  </a>
                )}
              </div>
            </div>
          </>
        )}
      </div>

      {/* Info */}
      <div className="panel" style={{ padding: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 8 }}>Deployment Info</div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', display: 'flex', flexDirection: 'column', gap: 4 }}>
          <div>• Images pulled from <code style={{ fontSize: 11 }}>ghcr.io/t3rr0or/scanr-*</code></div>
          <div>• Database migrations run automatically on startup</div>
          <div>• Restart with: <code style={{ fontSize: 11 }}>docker compose restart</code></div>
        </div>
      </div>
    </div>
  )
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="btn btn-primary btn-sm"
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12 }}
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
    >
      {copied ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy Command</>}
    </button>
  )
}

/* ── User Management (admin only) ───────────────────────────── */
function UserManagementSection() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ email: '', password: '', full_name: '', role: 'analyst' })
  const [err, setErr] = useState<string | null>(null)

  const { data: users = [] } = useQuery({ queryKey: ['admin-users'], queryFn: () => api.get('/users').then(r => r.data) })

  const createMut = useMutation({
    mutationFn: () => api.post('/users', form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin-users'] }); setShowCreate(false); setForm({ email: '', password: '', full_name: '', role: 'analyst' }); setErr(null) },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : 'Failed'),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, is_active }: { id: string; is_active: boolean }) => api.patch(`/users/${id}`, { is_active }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-users'] }),
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Manage user accounts. Deactivated users cannot log in.</p>
        <button className="btn btn-primary btn-sm" onClick={() => setShowCreate(v => !v)}><Plus size={13} /> New User</button>
      </div>

      {showCreate && (
        <div className="panel" style={{ padding: 14 }}>
          {err && <div style={{ color: 'var(--sev-high)', fontSize: 12, marginBottom: 8 }}>{err}</div>}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
            <input className="input" placeholder="Email" type="email" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
            <input className="input" placeholder="Password (min 10)" type="password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
            <input className="input" placeholder="Full name (optional)" value={form.full_name} onChange={e => setForm(f => ({ ...f, full_name: e.target.value }))} />
            <select className="select-field" value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
              <option value="analyst">Analyst</option>
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary btn-sm" onClick={() => createMut.mutate()} disabled={!form.email || form.password.length < 10 || createMut.isPending}>Create</button>
            <button className="btn btn-ghost btn-sm" onClick={() => setShowCreate(false)}>Cancel</button>
          </div>
        </div>
      )}

      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl" style={{ width: '100%' }}>
          <thead><tr><th>Email</th><th>Name</th><th>Role</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {(users as { id: string; email: string; full_name: string | null; role: string; is_active: boolean }[]).map(u => (
              <tr key={u.id}>
                <td style={{ fontSize: 12 }}>{u.email}</td>
                <td style={{ fontSize: 12, color: 'var(--text-2)' }}>{u.full_name || '—'}</td>
                <td><span className="pill">{u.role}</span></td>
                <td><span className={`pill pill-${u.is_active ? 'ok' : 'medium'}`}>{u.is_active ? 'Active' : 'Disabled'}</span></td>
                <td>
                  <button
                    className="btn btn-ghost btn-sm"
                    onClick={() => toggleMut.mutate({ id: u.id, is_active: !u.is_active })}
                    style={{ fontSize: 11 }}
                  >
                    {u.is_active ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── CVE Database ──────────────────────────────────────────── */
function CveDatabaseSection() {
  const qc = useQueryClient()
  const { data: status } = useQuery({
    queryKey: ['cve-status'],
    queryFn: () => api.get('/system/cve-status').then(r => r.data),
    refetchInterval: 5000,
  })

  const refreshMut = useMutation({
    mutationFn: () => api.post('/system/cve-refresh'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cve-status'] }),
  })

  return (
    <div className="panel" style={{ padding: 16 }}>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>CVE Feed Status</div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
        <div>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>NVD Database</div>
          <div style={{ fontSize: 13, fontWeight: 600, color: status?.nvd_db_exists ? 'var(--ok)' : 'var(--sev-high)' }}>
            {status?.nvd_db_exists ? 'Loaded' : 'Not downloaded'}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>CISA KEV Entries</div>
          <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)' }}>{status?.kev_count ?? '—'}</div>
        </div>
        <div style={{ gridColumn: '1 / -1' }}>
          <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 4 }}>Last Updated</div>
          <div className="mono" style={{ fontSize: 12, color: 'var(--text-2)' }}>
            {status?.last_updated ? new Date(status.last_updated).toLocaleString() : 'Never'}
          </div>
        </div>
      </div>

      <button
        onClick={() => refreshMut.mutate()}
        disabled={refreshMut.isPending}
        className="btn btn-primary btn-sm"
        style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}
      >
        <RefreshCw size={13} style={{ animation: refreshMut.isPending ? 'spin 1s linear infinite' : 'none' }} />
        {refreshMut.isPending ? 'Refreshing…' : 'Refresh CVE Feeds'}
      </button>

      <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 10 }}>
        Downloads NVD feeds (2020–present) and CISA Known Exploited Vulnerabilities catalog.
        Takes a few minutes. Runs automatically on first worker boot.
      </p>
    </div>
  )
}

/* ── API Keys ─────────────────────────────────────────────── */
const ALL_SCOPES = [
  { value: 'scans:read',        label: 'Scans — read',         desc: 'List and view scans' },
  { value: 'scans:write',       label: 'Scans — write',        desc: 'Create, launch, cancel, delete scans' },
  { value: 'findings:read',     label: 'Findings — read',      desc: 'List and view findings' },
  { value: 'findings:triage',   label: 'Findings — triage',    desc: 'Mark false positives, update status' },
  { value: 'reports:read',      label: 'Reports — read',       desc: 'View reports' },
  { value: 'reports:export',    label: 'Reports — export',     desc: 'Generate and download PDF reports' },
  { value: 'credentials:read',  label: 'Credentials — read',   desc: 'List credentials' },
  { value: 'credentials:write', label: 'Credentials — write',  desc: 'Create/delete credentials' },
  { value: 'agents:read',       label: 'Agents — read',        desc: 'List scan agents' },
  { value: 'agents:write',      label: 'Agents — write',       desc: 'Register/remove agents' },
  { value: '*',                 label: 'Full access',           desc: 'All scopes (same as a user session)' },
]

function ApiKeysSection() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [selectedScopes, setSelectedScopes] = useState<string[]>(['scans:read', 'findings:read'])
  const [createdKey, setCreatedKey] = useState<APIKeyCreated | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys = [] } = useQuery({ queryKey: ['api-keys'], queryFn: apiKeysApi.list })

  const toggleScope = (s: string) => {
    if (s === '*') { setSelectedScopes(['*']); return }
    setSelectedScopes(prev => {
      const without = prev.filter(x => x !== '*')
      return without.includes(s) ? without.filter(x => x !== s) : [...without, s]
    })
  }

  const [keyErr, setKeyErr] = useState<string | null>(null)
  const _onKeyErr = (e: unknown) => setKeyErr(e instanceof Error ? e.message : String(e))

  const createMut = useMutation({
    mutationFn: () => apiKeysApi.create({ name: newKeyName, scopes: selectedScopes }),
    onSuccess: (key) => {
      setCreatedKey(key); setShowCreate(false); setNewKeyName('')
      setSelectedScopes(['scans:read', 'findings:read'])
      qc.invalidateQueries({ queryKey: ['api-keys'] }); setKeyErr(null)
    },
    onError: _onKeyErr,
  })

  const revokeMut = useMutation({
    mutationFn: apiKeysApi.revoke,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['api-keys'] }); setKeyErr(null) },
    onError: _onKeyErr,
  })

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {keyErr && <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>{keyErr}</div>}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <p style={{ fontSize: 12, color: 'var(--text-3)' }}>API keys allow CI/CD pipelines and external tools to authenticate with ScanR.</p>
        <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
          <Plus size={13} /> New Key
        </button>
      </div>

      {createdKey && (
        <div style={{ padding: 14, borderRadius: 8, background: 'oklch(0.22 0.05 145 / 0.3)', border: '1px solid var(--ok)' }}>
          <p style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--ok)', marginBottom: 8 }}>
            API key created — copy it now, it won't be shown again:
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-0)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', marginBottom: 8 }}>
            <span className="mono" style={{ flex: 1, fontSize: 11, wordBreak: 'break-all', color: 'var(--text-0)' }}>{createdKey.key}</span>
            <button onClick={() => copyKey(createdKey.key)} className="btn btn-ghost btn-icon btn-sm">
              {copied ? <Check size={13} style={{ color: 'var(--ok)' }} /> : <Copy size={13} />}
            </button>
          </div>
          <button onClick={() => setCreatedKey(null)} style={{ fontSize: 11, color: 'var(--ok)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}>
            Dismiss
          </button>
        </div>
      )}

      {showCreate && (
        <div className="panel" style={{ padding: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>New API Key</div>
          <input
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. CI/CD pipeline)"
            className="input"
            style={{ marginBottom: 12 }}
          />
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>Scopes</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 12 }}>
            {ALL_SCOPES.map(s => (
              <label key={s.value} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', padding: '6px 8px', borderRadius: 6, background: selectedScopes.includes(s.value) || selectedScopes.includes('*') ? 'var(--accent-soft)' : 'transparent' }}>
                <input
                  type="checkbox"
                  checked={selectedScopes.includes(s.value) || selectedScopes.includes('*')}
                  onChange={() => toggleScope(s.value)}
                  style={{ marginTop: 1, accentColor: 'var(--accent)', flexShrink: 0 }}
                />
                <div>
                  <div style={{ fontSize: 11.5, fontWeight: 500, color: 'var(--text-0)' }}>{s.label}</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-3)' }}>{s.desc}</div>
                </div>
              </label>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => createMut.mutate()}
              disabled={!newKeyName || selectedScopes.length === 0 || createMut.isPending}
              className="btn btn-primary btn-sm"
            >
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Scopes</th>
              <th>Last Used</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {keys.map(k => (
              <tr key={k.id}>
                <td style={{ fontWeight: 500, color: 'var(--text-0)' }}>{k.name}</td>
                <td className="mono dimmer" style={{ fontSize: 11 }}>{k.prefix}…</td>
                <td>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {k.scopes.map(s => (
                      <span key={s} className="mono" style={{ fontSize: 10, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 5px', borderRadius: 4 }}>{s}</span>
                    ))}
                  </div>
                </td>
                <td className="dimmer" style={{ fontSize: 11 }}>{k.last_used_at ? relTime(k.last_used_at) : 'Never'}</td>
                <td className="dimmer" style={{ fontSize: 11 }}>{relTime(k.created_at)}</td>
                <td style={{ textAlign: 'right' }}>
                  <button onClick={() => revokeMut.mutate(k.id)} className="btn btn-ghost btn-icon btn-sm" title="Revoke" style={{ color: 'var(--sev-high)' }}>
                    <Trash2 size={13} />
                  </button>
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  No API keys
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ── Webhooks ─────────────────────────────────────────────── */
const ALL_EVENTS = ['scan.completed', 'scan.failed', 'finding.critical', 'finding.high', '*']

function WebhooksSection() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', url: '', secret: '', events: ['scan.completed', 'finding.critical'] })

  const { data: webhooks = [] } = useQuery({ queryKey: ['webhooks'], queryFn: webhooksApi.list })

  const [whErr, setWhErr] = useState<string | null>(null)
  const _onWhErr = (e: unknown) => setWhErr(e instanceof Error ? e.message : String(e))

  const createMut = useMutation({
    mutationFn: () => webhooksApi.create({ ...form, secret: form.secret || undefined }),
    onSuccess: () => {
      setShowCreate(false)
      setForm({ name: '', url: '', secret: '', events: ['scan.completed', 'finding.critical'] })
      qc.invalidateQueries({ queryKey: ['webhooks'] }); setWhErr(null)
    },
    onError: _onWhErr,
  })

  const deleteMut = useMutation({
    mutationFn: webhooksApi.delete,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['webhooks'] }); setWhErr(null) },
    onError: _onWhErr,
  })

  const testMut = useMutation({ mutationFn: webhooksApi.test, onError: _onWhErr })

  const toggleEvent = (event: string) => {
    setForm(f => ({
      ...f,
      events: f.events.includes(event) ? f.events.filter(e => e !== event) : [...f.events, event],
    }))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {whErr && <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>{whErr}</div>}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <p style={{ fontSize: 12, color: 'var(--text-3)' }}>Webhooks send HTTP POST requests to external URLs when scan events occur.</p>
        <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
          <Plus size={13} /> New Webhook
        </button>
      </div>

      {showCreate && (
        <div className="panel" style={{ padding: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>New Webhook</div>
          <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Name" className="input" style={{ marginBottom: 8 }} />
          <input value={form.url} onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
            placeholder="https://hooks.example.com/payload" className="input"
            style={{ marginBottom: 8, fontFamily: 'var(--font-mono)', fontSize: 12 }} />
          <input value={form.secret} onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
            placeholder="HMAC signing secret (optional)" className="input" style={{ marginBottom: 12 }} />
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-2)', marginBottom: 6 }}>Events</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
            {ALL_EVENTS.map(ev => (
              <label key={ev} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                <input type="checkbox" checked={form.events.includes(ev)} onChange={() => toggleEvent(ev)}
                  style={{ accentColor: 'var(--accent)' }} />
                <span className="mono" style={{ fontSize: 11, color: 'var(--text-1)' }}>{ev}</span>
              </label>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => createMut.mutate()} disabled={!form.name || !form.url || createMut.isPending} className="btn btn-primary btn-sm">
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {webhooks.map(w => (
          <div key={w.id} className="panel" style={{ padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)' }}>{w.name}</span>
                  {w.last_status != null && (
                    <span className="mono" style={{
                      fontSize: 10, padding: '1px 5px', borderRadius: 4,
                      background: w.last_status < 300 ? 'oklch(0.22 0.05 145 / 0.4)' : 'oklch(0.25 0.1 30 / 0.4)',
                      color: w.last_status < 300 ? 'var(--ok)' : 'var(--sev-high)',
                    }}>
                      {w.last_status}
                    </span>
                  )}
                  <span className={`pill ${w.enabled ? 'pill-completed' : 'pill-cancelled'}`} style={{ fontSize: 10 }}>
                    {w.enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <div className="mono dimmer" style={{ fontSize: 11, marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {w.url}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {w.events.map(ev => (
                    <span key={ev} className="mono" style={{ fontSize: 10, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 5px', borderRadius: 4 }}>{ev}</span>
                  ))}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                <button onClick={() => testMut.mutate(w.id)} disabled={testMut.isPending} className="btn btn-ghost btn-icon btn-sm" title="Send test payload">
                  <Send size={13} />
                </button>
                <button onClick={() => deleteMut.mutate(w.id)} className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: 'var(--sev-high)' }}>
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          </div>
        ))}
        {webhooks.length === 0 && (
          <div style={{ textAlign: 'center', padding: '32px', color: 'var(--text-3)', fontSize: 12 }}>
            No webhooks configured
          </div>
        )}
      </div>
    </div>
  )
}
