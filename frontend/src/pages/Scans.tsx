import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Play, StopCircle, Trash2, Terminal, GitCompare, Search, Activity, X, AlertCircle } from 'lucide-react'
import { scansApi, type ScanCreate } from '@/api/scans'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { credentialsApi } from '@/api/credentials'
import { ProfileEditor, ALL_CATEGORIES, PORT_RANGES, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import ScanDelta from './ScanDelta'
import { StatusPill, CHML, SeverityBar, Meter, relTime, fmtDuration } from '@/components/ui'

interface Props {
  onOpenScan?: (id: string) => void
}

const PAGE_SIZE = 50

type StatusFilter = 'all' | 'running' | 'completed' | 'pending' | 'failed'

export default function Scans({ onOpenScan }: Props) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [deltaScan, setDeltaScan] = useState<{ id: string; name: string } | null>(null)
  const [page, setPage] = useState(0)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [search, setSearch] = useState('')

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    refetchInterval: 5000,
  })

  const [mutError, setMutError] = useState<string | null>(null)

  const createMut = useMutation({
    mutationFn: (body: ScanCreate) => scansApi.create(body),
    onSuccess: (scan) => {
      setShowForm(false)
      scansApi.launch(scan.id).finally(() => qc.invalidateQueries({ queryKey: ['scans'] }))
    },
    onError: (e: Error) => setMutError(e.message || 'Failed to create scan'),
  })
  const launchMut = useMutation({
    mutationFn: (id: string) => scansApi.launch(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: (e: Error) => setMutError(e.message || 'Failed to launch scan'),
  })
  const cancelMut = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: (e: Error) => setMutError(e.message || 'Failed to cancel scan'),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: (e: Error) => setMutError(e.message || 'Failed to delete scan'),
  })

  const counts: Record<StatusFilter, number> = {
    all: scans.length,
    running: scans.filter(s => s.status === 'running').length,
    completed: scans.filter(s => s.status === 'completed').length,
    pending: scans.filter(s => s.status === 'pending').length,
    failed: scans.filter(s => s.status === 'failed').length,
  }

  const filtered = scans
    .filter(s => statusFilter === 'all' || s.status === statusFilter)
    .filter(s => !search || s.name.toLowerCase().includes(search.toLowerCase()))

  return (
    <div style={{ padding: 20, maxWidth: 1480, margin: '0 auto' }}>
      {deltaScan && (
        <ScanDelta scanId={deltaScan.id} scanName={deltaScan.name} onClose={() => setDeltaScan(null)} />
      )}

      {mutError && (
        <div style={{ marginBottom: 12, padding: '8px 12px', background: 'var(--sev-critical-bg)', border: '1px solid var(--sev-critical)', borderRadius: 6, color: 'var(--sev-critical)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertCircle size={13} /> {mutError}
          <button className="btn btn-ghost btn-icon" style={{ marginLeft: 'auto', color: 'inherit' }} onClick={() => setMutError(null)}><X size={12} /></button>
        </div>
      )}

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>Scans</h1>
          <div className="mono dim" style={{ fontSize: 11, marginTop: 2 }}>
            {scans.length} total · last updated {relTime(new Date().toISOString())}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn btn-primary" onClick={() => setShowForm(true)}>
            <Plus size={12} /> New Scan
          </button>
        </div>
      </div>

      {/* Status filter tabs + search */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        {(['all', 'running', 'completed', 'pending', 'failed'] as StatusFilter[]).map(f => (
          <button
            key={f}
            onClick={() => setStatusFilter(f)}
            style={{
              padding: '5px 10px', borderRadius: 6, fontSize: 11.5, textTransform: 'capitalize',
              background: statusFilter === f ? 'var(--bg-3)' : 'transparent',
              color: statusFilter === f ? 'var(--text-0)' : 'var(--text-2)',
              border: '1px solid ' + (statusFilter === f ? 'var(--border-strong)' : 'transparent'),
              cursor: 'pointer',
            }}
          >
            {f} <span className="mono dim" style={{ marginLeft: 4 }}>{counts[f]}</span>
          </button>
        ))}
        <div style={{ flex: 1 }} />
        <div className="search" style={{ width: 260 }}>
          <Search size={13} color="var(--text-3)" />
          <input
            placeholder="Search by name, target…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* New scan modal */}
      {showForm && (
        <div style={{
          position: 'fixed', inset: 0, background: 'oklch(0.06 0.01 255 / 0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, padding: 20,
        }}
          onClick={() => setShowForm(false)}
        >
          <div className="panel" style={{ width: 640, maxHeight: '92vh', overflow: 'auto' }}
            onClick={e => e.stopPropagation()}>
            <ScanForm
              onSubmit={b => createMut.mutate(b)}
              onCancel={() => setShowForm(false)}
              loading={createMut.isPending}
            />
          </div>
        </div>
      )}

      {/* Table */}
      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th>Name</th>
              <th>Targets</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Hosts</th>
              <th>Findings (C/H/M/L)</th>
              <th>Severity</th>
              <th>Duration</th>
              <th>When</th>
              <th style={{ width: 110 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(s => (
              <tr key={s.id} onClick={() => onOpenScan?.(s.id)}>
                <td style={{ color: 'var(--text-3)', textAlign: 'center' }}>
                  {s.status === 'running'
                    ? <span className="live-dot" style={{ width: 6, height: 6, display: 'inline-block', margin: '0 auto' }} />
                    : <Activity size={13} />
                  }
                </td>
                <td>
                  <div style={{ fontWeight: 500 }}>{s.name}</div>
                  <div className="mono dim" style={{ fontSize: 10.5 }}>{s.id.slice(0, 8)}</div>
                  {s.status === 'running' && (
                    <div style={{ width: 80, marginTop: 4 }}>
                      <Meter value={s.progress ?? 0.5} color="var(--accent-2)" />
                    </div>
                  )}
                </td>
                <td className="mono dim" style={{ fontSize: 11.5, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {s.targets?.length
                    ? <>{s.targets[0]}{s.targets.length > 1 && <span style={{ color: 'var(--text-3)' }}> +{s.targets.length - 1}</span>}</>
                    : <span className="dimmer">—</span>
                  }
                </td>
                <td className="mono dim" style={{ fontSize: 11.5 }}>{s.profile}</td>
                <td><StatusPill status={s.status} /></td>
                <td className="mono">
                  <span style={{ color: 'var(--text-0)' }}>{s.hosts_up ?? 0}</span>
                  <span className="dim">/{s.hosts_total ?? 0}</span>
                </td>
                <td>
                  <CHML c={s.findings_critical} h={s.findings_high} m={s.findings_medium} l={s.findings_low} />
                </td>
                <td style={{ width: 110 }}>
                  <SeverityBar c={s.findings_critical} h={s.findings_high} m={s.findings_medium} l={s.findings_low} i={s.findings_info} />
                </td>
                <td className="mono dim" style={{ fontSize: 11.5 }}>{fmtDuration(s.duration_s)}</td>
                <td className="mono dim" style={{ fontSize: 11.5 }}>{relTime(s.created_at)}</td>
                <td onClick={e => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 2 }}>
                    <button className="btn btn-ghost btn-icon" title="Open console" onClick={() => onOpenScan?.(s.id)}>
                      <Terminal size={13} />
                    </button>
                    {s.status === 'pending' && (
                      <button className="btn btn-ghost btn-icon" title="Launch" onClick={() => launchMut.mutate(s.id)}>
                        <Play size={11} style={{ color: 'var(--ok)' }} />
                      </button>
                    )}
                    {s.status === 'running' && (
                      <button className="btn btn-ghost btn-icon" title="Cancel" onClick={() => cancelMut.mutate(s.id)}>
                        <StopCircle size={10} style={{ color: 'var(--sev-high)' }} />
                      </button>
                    )}
                    {(s.status === 'completed' || s.status === 'failed') && (
                      <button className="btn btn-ghost btn-icon" title="Compare" onClick={() => setDeltaScan({ id: s.id, name: s.name })}>
                        <GitCompare size={13} />
                      </button>
                    )}
                    <button
                      className="btn btn-ghost btn-icon"
                      title="Delete"
                      onClick={() => { if (confirm('Delete this scan?')) deleteMut.mutate(s.id) }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={11} style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  <Activity size={24} style={{ margin: '0 auto 8px', color: 'var(--text-3)' }} />
                  <div>No scans yet. Create your first scan to get started.</div>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {(page > 0 || scans.length === PAGE_SIZE) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12, justifyContent: 'flex-end' }}>
          <button className="btn btn-sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
            Previous
          </button>
          <span className="mono dim" style={{ fontSize: 11.5 }}>Page {page + 1}</span>
          <button className="btn btn-sm" onClick={() => setPage(p => p + 1)} disabled={scans.length < PAGE_SIZE}>
            Next
          </button>
        </div>
      )}
    </div>
  )
}

function ScanForm({ onSubmit, onCancel, loading }: {
  onSubmit: (b: ScanCreate) => void; onCancel: () => void; loading: boolean
}) {
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState<ScanTemplate | null>(null)
  const [profileConfig, setProfileConfig] = useState<ProfileConfig>({
    port_range: 'top-10000',
    categories: ALL_CATEGORIES.map(x => x.id),
  })

  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: templatesApi.list })
  const { data: credentials = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const systemTemplates = templates.filter(t => t.is_system)

  function applyTemplate(t: ScanTemplate) {
    setSelectedTemplate(t)
    setProfileConfig(jsonToConfig(t.profile_json))
    if (!name) setName(t.name)
  }

  function handleSubmit() {
    if (loading) return
    const pj = configToJson(profileConfig)
    onSubmit({
      name,
      targets: targets.split('\n').map(t => t.trim()).filter(Boolean),
      profile: 'custom',
      profile_json: JSON.stringify(pj),
      credential_id: credentialId || undefined,
    })
  }

  const tplIcons: Record<string, string> = {
    'Quick Scan': '⚡', 'Full Scan': '◎', 'Web Audit': '🌐', 'Internal Network Audit': '🏢',
  }

  return (
    <>
      <div className="panel-head">
        <span style={{ fontSize: 13, fontWeight: 600 }}>New Scan</span>
        <button className="btn btn-ghost btn-icon" style={{ marginLeft: 'auto' }} onClick={onCancel}>
          <X size={14} />
        </button>
      </div>
      <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Template picker */}
        {systemTemplates.length > 0 && (
          <div>
            <div className="label">Start from template</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: 8 }}>
              {systemTemplates.map(t => {
                const active = selectedTemplate?.id === t.id
                return (
                  <button key={t.id} onClick={() => applyTemplate(t)} style={{
                    padding: 12, borderRadius: 8, textAlign: 'left', cursor: 'pointer',
                    background: active ? 'var(--accent-soft)' : 'var(--bg-0)',
                    border: '1px solid ' + (active ? 'var(--accent)' : 'var(--border)'),
                    display: 'flex', alignItems: 'flex-start', gap: 10,
                  }}>
                    <span style={{
                      width: 28, height: 28, borderRadius: 6, background: 'var(--bg-2)',
                      color: active ? 'var(--accent)' : 'var(--text-1)',
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, fontSize: 14,
                    }}>
                      {tplIcons[t.name] ?? '◎'}
                    </span>
                    <div>
                      <div style={{ fontSize: 12.5, fontWeight: 600 }}>{t.name}</div>
                      <div className="mono dim" style={{ fontSize: 10.5, marginTop: 2 }}>{t.description ?? ''}</div>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>
        )}

        {/* Name */}
        <div>
          <div className="label">Scan name</div>
          <input className="input" value={name} onChange={e => setName(e.target.value)} placeholder="Internal Network Q2 2026" />
        </div>

        {/* Targets */}
        <div>
          <div className="label">
            Targets <span style={{ color: 'var(--text-3)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
              — one per line · IP, CIDR, hostname, range
            </span>
          </div>
          <textarea
            className="textarea"
            rows={3}
            value={targets}
            onChange={e => setTargets(e.target.value)}
            placeholder={'192.168.1.0/24\n10.0.0.1-10.0.0.50\nexample.com'}
          />
        </div>

        {/* Credential */}
        {credentials.length > 0 && (
          <div>
            <div className="label">Credential <span style={{ color: 'var(--text-3)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>(optional)</span></div>
            <select className="select-field" value={credentialId} onChange={e => setCredentialId(e.target.value)}>
              <option value="">None</option>
              {credentials.map(c => (
                <option key={c.id} value={c.id}>{c.name} ({c.type}{c.username ? ` — ${c.username}` : ''})</option>
              ))}
            </select>
          </div>
        )}

        {/* Port range */}
        <div>
          <div className="label">Port Range</div>
          {selectedTemplate ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px', background: 'var(--accent-soft)', border: '1px solid oklch(0.78 0.14 200 / 0.3)', borderRadius: 'var(--radius)', fontSize: 11.5 }}>
              <span className="mono" style={{ color: 'var(--accent)', flex: 1 }}>
                {PORT_RANGES.find(r => r.value === profileConfig.port_range)?.label ?? profileConfig.port_range}
              </span>
              <span style={{ fontSize: 10.5, color: 'var(--accent-dim)' }}>set by {selectedTemplate.name}</span>
              <button style={{ fontSize: 11, color: 'var(--text-2)', cursor: 'pointer', background: 'none', border: 'none' }}
                onClick={() => setSelectedTemplate(null)}>unlock</button>
            </div>
          ) : (
            <select className="select-field" value={profileConfig.port_range}
              onChange={e => setProfileConfig(c => ({ ...c, port_range: e.target.value }))}>
              {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
            </select>
          )}
        </div>

        {/* Plugin categories */}
        <div>
          <div className="label">Plugin categories</div>
          <div style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 12 }}>
            <ProfileEditor config={profileConfig} onChange={setProfileConfig} hidePortRange />
          </div>
        </div>

        {/* Legal notice */}
        <div style={{ background: 'var(--bg-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 10, fontSize: 11.5, color: 'var(--text-2)', display: 'flex', gap: 8 }}>
          <AlertCircle size={13} style={{ color: 'var(--sev-medium)', marginTop: 1, flexShrink: 0 }} />
          <div>
            <strong style={{ color: 'var(--text-1)' }}>Legal notice.</strong> Only scan networks and systems you own or have explicit written permission to test.
          </div>
        </div>
      </div>
      <div style={{ padding: '12px 18px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
        <button className="btn" onClick={onCancel}>Cancel</button>
        <button
          className="btn btn-primary"
          disabled={loading || !name || !targets.trim()}
          onClick={handleSubmit}
        >
          <Play size={11} /> {loading ? 'Creating…' : 'Create & Launch'}
        </button>
      </div>
    </>
  )
}
