import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Play, StopCircle, Trash2, Terminal, GitCompare } from 'lucide-react'
import { scansApi, type ScanCreate } from '@/api/scans'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { credentialsApi } from '@/api/credentials'
import { ProfileEditor, ALL_CATEGORIES, PORT_RANGES, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import ScanDelta from './ScanDelta'

interface Props {
  onOpenScan?: (id: string) => void
}

const PAGE_SIZE = 50

export default function Scans({ onOpenScan }: Props) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [deltaScan, setDeltaScan] = useState<{ id: string; name: string } | null>(null)
  const [page, setPage] = useState(0)

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    refetchInterval: 5000,
  })

  const createMut = useMutation({
    mutationFn: (body: ScanCreate) => scansApi.create(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); setShowForm(false) },
  })
  const launchMut = useMutation({
    mutationFn: (id: string) => scansApi.launch(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
  const cancelMut = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  return (
    <div style={{ padding: '24px 28px' }}>
      {deltaScan && (
        <ScanDelta scanId={deltaScan.id} scanName={deltaScan.name} onClose={() => setDeltaScan(null)} />
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Scans</h1>
        <button onClick={() => setShowForm(!showForm)} className="btn btn-primary btn-sm">
          <Plus size={14} /> New Scan
        </button>
      </div>

      {showForm && (
        <ScanForm
          onSubmit={b => createMut.mutate(b)}
          onCancel={() => setShowForm(false)}
          loading={createMut.isPending}
        />
      )}

      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              {['Name', 'Profile', 'Status', 'Hosts', 'C/H/M/L', 'Actions'].map(h => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.map(s => (
              <tr key={s.id} onClick={() => onOpenScan?.(s.id)} style={{ cursor: 'pointer' }}>
                <td style={{ fontWeight: 500, color: 'var(--text-0)' }}>{s.name}</td>
                <td className="dimmer" style={{ fontSize: 12 }}>{s.profile}</td>
                <td><StatusBadge status={s.status} /></td>
                <td style={{ color: 'var(--text-2)', fontSize: 13 }}>{s.hosts_up}/{s.hosts_total}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  <span style={{ color: 'var(--sev-critical)' }}>{s.findings_critical}</span>
                  <span className="dimmer"> / </span>
                  <span style={{ color: 'var(--sev-high)' }}>{s.findings_high}</span>
                  <span className="dimmer"> / </span>
                  <span style={{ color: 'var(--sev-medium)' }}>{s.findings_medium}</span>
                  <span className="dimmer"> / </span>
                  <span style={{ color: 'var(--sev-low)' }}>{s.findings_low}</span>
                </td>
                <td onClick={e => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button onClick={() => onOpenScan?.(s.id)} className="btn btn-ghost btn-icon btn-sm" title="Open console">
                      <Terminal size={13} />
                    </button>
                    {s.status === 'pending' && (
                      <button onClick={() => launchMut.mutate(s.id)} className="btn btn-ghost btn-icon btn-sm" title="Launch" style={{ color: 'var(--ok)' }}>
                        <Play size={13} />
                      </button>
                    )}
                    {s.status === 'running' && (
                      <button onClick={() => cancelMut.mutate(s.id)} className="btn btn-ghost btn-icon btn-sm" title="Cancel" style={{ color: 'var(--sev-high)' }}>
                        <StopCircle size={13} />
                      </button>
                    )}
                    {(s.status === 'completed' || s.status === 'failed') && (
                      <button
                        onClick={() => setDeltaScan({ id: s.id, name: s.name })}
                        className="btn btn-ghost btn-icon btn-sm"
                        title="Compare with baseline"
                      >
                        <GitCompare size={13} />
                      </button>
                    )}
                    <button
                      onClick={() => { if (confirm('Delete scan?')) deleteMut.mutate(s.id) }}
                      className="btn btn-ghost btn-icon btn-sm"
                      title="Delete"
                      style={{ color: 'var(--sev-high)' }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr>
                <td colSpan={6} style={{ padding: '32px 16px', textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>
                  No scans yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {(page > 0 || scans.length === PAGE_SIZE) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16, justifyContent: 'flex-end' }}>
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="btn btn-ghost btn-sm">
            Previous
          </button>
          <span className="dimmer" style={{ fontSize: 12 }}>Page {page + 1}</span>
          <button onClick={() => setPage(p => p + 1)} disabled={scans.length < PAGE_SIZE} className="btn btn-ghost btn-sm">
            Next
          </button>
        </div>
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const cls: Record<string, string> = {
    running:   'pill-running',
    completed: 'pill-completed',
    failed:    'pill-failed',
    pending:   'pill-pending',
    cancelled: 'pill-cancelled',
  }
  return <span className={`pill ${cls[status] ?? 'pill-cancelled'}`}>{status}</span>
}

// ── Scan creation form ──────────────────────────────────────────────────────

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
    onSubmit({
      name,
      targets: targets.split('\n').map(t => t.trim()).filter(Boolean),
      profile: 'custom',
      profile_json: JSON.stringify(configToJson(profileConfig)),
      credential_id: credentialId || undefined,
    })
  }

  return (
    <div className="panel" style={{ padding: 20, marginBottom: 20 }}>
      <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--text-0)', marginBottom: 16 }}>New Scan</div>

      {/* Quick-start templates */}
      {systemTemplates.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div className="label" style={{ marginBottom: 8 }}>Start from a template</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 8 }}>
            {systemTemplates.map(t => {
              const active = selectedTemplate?.id === t.id
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => applyTemplate(t)}
                  style={{
                    padding: '10px 12px', borderRadius: 6, border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                    background: active ? 'var(--accent-soft)' : 'var(--bg-2)',
                    cursor: 'pointer', textAlign: 'left',
                    boxShadow: active ? '0 0 0 1px var(--accent)' : 'none',
                  }}
                >
                  <div style={{ fontSize: 12, fontWeight: 600, color: active ? 'var(--accent)' : 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {t.name}
                  </div>
                  {t.profile_json && (
                    <div className="mono dimmer" style={{ fontSize: 10, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {PORT_RANGES.find(r => r.value === (t.profile_json as any).port_range)?.label.split(' —')[0]
                        ?? (t.profile_json as any).port_range}
                    </div>
                  )}
                </button>
              )
            })}
          </div>
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div>
          <label className="label">Scan Name</label>
          <input value={name} onChange={e => setName(e.target.value)} className="input" placeholder="Internal Network Q4" />
        </div>

        <div>
          <label className="label">Targets <span className="dimmer" style={{ fontWeight: 400 }}>(one per line: IP, CIDR, hostname, range)</span></label>
          <textarea
            value={targets}
            onChange={e => setTargets(e.target.value)}
            rows={3}
            className="textarea"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
            placeholder={"192.168.1.0/24\n10.0.0.1-10.0.0.50\nexample.com"}
          />
        </div>

        {credentials.length > 0 && (
          <div>
            <label className="label">Credential <span className="dimmer" style={{ fontWeight: 400 }}>(optional)</span></label>
            <select value={credentialId} onChange={e => setCredentialId(e.target.value)} className="select-field">
              <option value="">None</option>
              {credentials.map(c => (
                <option key={c.id} value={c.id}>{c.name} ({c.type}{c.username ? ` — ${c.username}` : ''})</option>
              ))}
            </select>
          </div>
        )}

        <div>
          <label className="label">Port Range</label>
          {selectedTemplate ? (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px',
              background: 'var(--accent-soft)', border: '1px solid oklch(0.78 0.14 200 / 0.3)',
              borderRadius: 6, fontSize: 12,
            }}>
              <span className="mono" style={{ flex: 1, color: 'var(--accent)', fontSize: 11 }}>
                {PORT_RANGES.find(r => r.value === profileConfig.port_range)?.label ?? profileConfig.port_range}
              </span>
              <span className="dimmer" style={{ fontSize: 10, flexShrink: 0 }}>set by {selectedTemplate.name}</span>
              <button type="button" onClick={() => setSelectedTemplate(null)} className="btn btn-ghost btn-sm" style={{ fontSize: 10, padding: '2px 6px' }}>
                unlock
              </button>
            </div>
          ) : (
            <select
              value={PORT_RANGES.find(r => r.value === profileConfig.port_range) ? profileConfig.port_range : '__custom__'}
              onChange={e => { if (e.target.value !== '__custom__') setProfileConfig(c => ({ ...c, port_range: e.target.value })) }}
              className="select-field"
            >
              {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
              {!PORT_RANGES.find(r => r.value === profileConfig.port_range) && (
                <option value="__custom__" disabled>Custom: {profileConfig.port_range}</option>
              )}
            </select>
          )}
        </div>

        <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 14 }}>
          <div className="label" style={{ marginBottom: 10 }}>Plugin Categories</div>
          <ProfileEditor config={profileConfig} onChange={setProfileConfig} hidePortRange />
        </div>
      </div>

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button onClick={handleSubmit} disabled={loading || !name || !targets.trim()} className="btn btn-primary btn-sm">
          {loading ? 'Creating…' : 'Create Scan'}
        </button>
        <button onClick={onCancel} className="btn btn-ghost btn-sm">Cancel</button>
      </div>
    </div>
  )
}
