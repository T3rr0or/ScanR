import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, Plus, Trash2, Copy, Check, RotateCcw, EyeOff } from 'lucide-react'
import { agentsApi, type AgentCreated } from '@/api/agents'
import { relTime, EmptyState } from '@/components/ui'

export default function Agents() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [createdAgent, setCreatedAgent] = useState<AgentCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const [showDisabled, setShowDisabled] = useState(false)

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['agents', showDisabled],
    queryFn: () => agentsApi.list(showDisabled),
  })

  const activeAgents = agents.filter(a => a.enabled)
  const disabledAgents = agents.filter(a => !a.enabled)

  const createMut = useMutation({
    mutationFn: () => agentsApi.create({ name: form.name, description: form.description || undefined }),
    onSuccess: (agent) => {
      setCreatedAgent(agent)
      setShowCreate(false)
      setForm({ name: '', description: '' })
      qc.invalidateQueries({ queryKey: ['agents'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: agentsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const enableMut = useMutation({
    mutationFn: (id: string) => agentsApi.update(id, { enabled: true }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const copy = (s: string) => {
    navigator.clipboard.writeText(s)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function isOnline(last_seen: string | null) {
    if (!last_seen) return false
    return Date.now() - new Date(last_seen).getTime() < 90_000
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Bot size={18} style={{ color: 'var(--accent)' }} /> Scan Agents
          </h1>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>
            Remote agents scan internal / firewalled networks and report findings back
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={() => setShowDisabled(v => !v)} className="btn btn-ghost btn-sm" title={showDisabled ? 'Hide disabled' : 'Show disabled'}>
            {showDisabled ? <EyeOff size={13} /> : <EyeOff size={13} style={{ opacity: 0.4 }} />}
            {disabledAgents.length > 0 && !showDisabled && <span style={{ fontSize: 11 }}>{disabledAgents.length} disabled</span>}
          </button>
          <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
            <Plus size={13} /> Register Agent
          </button>
        </div>
      </div>

      {/* One-time token reveal */}
      {createdAgent && (
        <div style={{
          marginBottom: 24, padding: 16, borderRadius: 8,
          background: 'oklch(0.22 0.05 145 / 0.3)', border: '1px solid var(--ok)',
        }}>
          <p style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--ok)', marginBottom: 8 }}>
            Agent registered — copy the token now, it won't be shown again:
          </p>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, background: 'var(--bg-0)',
            border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', marginBottom: 12,
          }}>
            <span className="mono" style={{ flex: 1, fontSize: 11, wordBreak: 'break-all', color: 'var(--text-1)' }}>
              {createdAgent.token}
            </span>
            <button onClick={() => copy(createdAgent.token)} className="btn btn-ghost btn-icon btn-sm">
              {copied ? <Check size={13} style={{ color: 'var(--ok)' }} /> : <Copy size={13} />}
            </button>
          </div>

          <p style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>Option A — Docker (recommended):</p>
          <div className="console" style={{ padding: '10px 12px', marginBottom: 12, fontSize: 11 }}>
            <div>docker run --rm \</div>
            <div style={{ paddingLeft: 16 }}>-e SCANR_SERVER={window.location.origin} \</div>
            <div style={{ paddingLeft: 16 }}>-e SCANR_TOKEN={createdAgent.token} \</div>
            <div style={{ paddingLeft: 16 }}>--network host \</div>
            <div style={{ paddingLeft: 16 }}>{'<your-scanr-worker-image>'} \</div>
            <div style={{ paddingLeft: 16 }}>python -m scanr.agent.full_runner</div>
          </div>

          <p style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-1)', marginBottom: 4 }}>Option B — Lightweight script:</p>
          <div className="console" style={{ padding: '10px 12px', fontSize: 11 }}>
            <div><span style={{ color: 'var(--text-3)' }}># install dependency</span></div>
            <div>pip install httpx</div>
            <div style={{ marginTop: 6 }}><span style={{ color: 'var(--text-3)' }}># download agent</span></div>
            <div>curl {window.location.origin}/api/v1/agent/script -o scanr_agent.py</div>
            <div style={{ marginTop: 6 }}><span style={{ color: 'var(--text-3)' }}># run</span></div>
            <div>python scanr_agent.py --server {window.location.origin} --token {createdAgent.token}</div>
          </div>

          <button onClick={() => setCreatedAgent(null)} style={{ marginTop: 10, fontSize: 11, color: 'var(--ok)', background: 'none', border: 'none', cursor: 'pointer', textDecoration: 'underline' }}>
            Dismiss
          </button>
        </div>
      )}

      {/* Create form */}
      {showCreate && (
        <div className="panel" style={{ marginBottom: 24, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>Register Agent</div>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Agent name (e.g. Office-Network-Agent)"
            className="input"
            style={{ marginBottom: 8 }}
          />
          <input
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            className="input"
            style={{ marginBottom: 10 }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => createMut.mutate()} disabled={!form.name || createMut.isPending} className="btn btn-primary btn-sm">
              {createMut.isPending ? 'Registering…' : 'Register'}
            </button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      {/* Card grid */}
      {isLoading ? (
        <div className="dimmer" style={{ fontSize: 13, padding: '20px 0' }}>Loading…</div>
      ) : agents.length === 0 ? (
        <div className="panel" style={{ padding: 40 }}>
          <EmptyState
            icon={<Bot size={28} />}
            message="No agents registered"
            action={<span style={{ fontSize: 11, color: 'var(--text-3)' }}>Register an agent to scan internal networks</span>}
          />
        </div>
      ) : (
        <>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 14 }}>
          {activeAgents.map(a => {
            const online = isOnline(a.last_seen_at)
            return (
              <div key={a.id} className="panel" style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* Card header */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                      {online
                        ? <span className="live-dot" style={{ width: 7, height: 7, flexShrink: 0, boxShadow: 'none' }} />
                        : <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--text-3)', flexShrink: 0, display: 'inline-block' }} />
                      }
                      <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.name}
                      </span>
                    </div>
                    {a.description && (
                      <div className="dimmer" style={{ fontSize: 11, marginTop: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {a.description}
                      </div>
                    )}
                  </div>
                  <button
                    onClick={() => deleteMut.mutate(a.id)}
                    className="btn btn-ghost btn-icon btn-sm"
                    title="Remove agent"
                    style={{ color: 'var(--sev-high)', flexShrink: 0 }}
                  >
                    <Trash2 size={13} />
                  </button>
                </div>

                {/* Stats row */}
                <div style={{ display: 'flex', gap: 0, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                  {[
                    { label: 'Status', value: online ? 'Online' : (a.last_seen_at ? 'Offline' : 'Never'), color: online ? 'var(--ok)' : 'var(--text-3)' },
                    { label: 'IP', value: a.ip_address || '—', mono: true },
                    { label: 'Version', value: a.agent_version || '—', mono: true },
                  ].map((stat, i) => (
                    <div key={i} style={{ flex: 1, textAlign: 'center', borderRight: i < 2 ? '1px solid var(--border)' : 'none', padding: '0 8px' }}>
                      <div style={{ fontSize: 10, color: 'var(--text-3)', marginBottom: 2 }}>{stat.label}</div>
                      <div className={stat.mono ? 'mono' : ''} style={{ fontSize: 12, fontWeight: 600, color: stat.color ?? 'var(--text-1)' }}>
                        {stat.value}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Footer */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="mono dimmer" style={{ fontSize: 10 }}>{a.prefix}…</span>
                  <span className="dimmer" style={{ fontSize: 10 }}>
                    {a.last_seen_at ? relTime(a.last_seen_at) : 'never connected'}
                  </span>
                </div>
              </div>
            )
          })}
        </div>

        {showDisabled && disabledAgents.length > 0 && (
          <>
            <div style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 600, marginTop: 12, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Disabled agents ({disabledAgents.length})
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 10, opacity: 0.6 }}>
              {disabledAgents.map(a => (
                <div key={a.id} className="panel" style={{ padding: '10px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span style={{ fontSize: 13, color: 'var(--text-1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.name}</span>
                  <button
                    onClick={() => enableMut.mutate(a.id)}
                    className="btn btn-ghost btn-sm"
                    title="Re-enable agent"
                    style={{ flexShrink: 0 }}
                  >
                    <RotateCcw size={12} /> Re-enable
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
        </>
      )}
    </div>
  )
}
