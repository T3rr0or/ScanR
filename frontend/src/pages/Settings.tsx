import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { type LucideIcon, Key, Webhook, Copy, Check, Trash2, Plus, Send, Database, RefreshCw, Settings as SettingsIcon } from 'lucide-react'
import { apiKeysApi, type APIKeyCreated } from '@/api/apiKeys'
import { webhooksApi } from '@/api/webhooks'
import api from '@/api/client'
import { relTime } from '@/components/ui'

type Tab = 'api-keys' | 'webhooks' | 'cve'

const TABS: { id: Tab; label: string; Icon: LucideIcon }[] = [
  { id: 'api-keys', label: 'API Keys', Icon: Key },
  { id: 'webhooks', label: 'Webhooks', Icon: Webhook },
  { id: 'cve', label: 'CVE Database', Icon: Database },
]

export default function Settings() {
  const [activeTab, setActiveTab] = useState<Tab>('api-keys')

  return (
    <div style={{ padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
        <SettingsIcon size={18} style={{ color: 'var(--accent)' }} />
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Settings</h1>
      </div>

      {/* Vertical sidebar layout */}
      <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
        {/* Left nav */}
        <div className="panel" style={{ width: 180, flexShrink: 0, padding: 6 }}>
          {TABS.map(({ id, label, Icon }) => {
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

        {/* Content */}
        <div style={{ flex: 1, minWidth: 0, maxWidth: 700 }}>
          {activeTab === 'api-keys' && <ApiKeysSection />}
          {activeTab === 'webhooks' && <WebhooksSection />}
          {activeTab === 'cve' && <CveDatabaseSection />}
        </div>
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

  const createMut = useMutation({
    mutationFn: () => apiKeysApi.create({ name: newKeyName, scopes: selectedScopes }),
    onSuccess: (key) => {
      setCreatedKey(key)
      setShowCreate(false)
      setNewKeyName('')
      setSelectedScopes(['scans:read', 'findings:read'])
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })

  const revokeMut = useMutation({
    mutationFn: apiKeysApi.revoke,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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

  const createMut = useMutation({
    mutationFn: () => webhooksApi.create({ ...form, secret: form.secret || undefined }),
    onSuccess: () => {
      setShowCreate(false)
      setForm({ name: '', url: '', secret: '', events: ['scan.completed', 'finding.critical'] })
      qc.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: webhooksApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })

  const testMut = useMutation({ mutationFn: webhooksApi.test })

  const toggleEvent = (event: string) => {
    setForm(f => ({
      ...f,
      events: f.events.includes(event) ? f.events.filter(e => e !== event) : [...f.events, event],
    }))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
