import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Server, Search, X, Plus, AlertTriangle } from 'lucide-react'
import { assetsApi, type AssetItem } from '@/api/assets'
import type { Finding } from '@/api/findings'
import { SevTag, CHML, relTime } from '@/components/ui'

function VprBadge({ score }: { score: number | null }) {
  if (score == null) return <span className="dimmer" style={{ fontSize: 11 }}>—</span>
  const color = score >= 8 ? 'var(--sev-critical)' : score >= 5 ? 'var(--sev-high)' : 'var(--sev-medium)'
  return (
    <span className="mono" style={{ fontSize: 11, fontWeight: 700, color, background: `${color}20`, padding: '1px 5px', borderRadius: 3 }}>
      {score.toFixed(1)}
    </span>
  )
}

function TagChips({ tags, onAdd, onRemove }: { ip?: string; tags: string[]; onAdd: (t: string) => void; onRemove: (t: string) => void }) {
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState('')
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
      {tags.map(t => (
        <span key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 10, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 6px', borderRadius: 999, fontWeight: 600 }}>
          {t}
          <button onClick={() => onRemove(t)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0, lineHeight: 1 }}><X size={9} /></button>
        </span>
      ))}
      {adding ? (
        <input
          autoFocus
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && draft.trim()) { onAdd(draft.trim()); setDraft(''); setAdding(false) }
            if (e.key === 'Escape') { setAdding(false); setDraft('') }
          }}
          onBlur={() => { if (!draft.trim()) setAdding(false) }}
          style={{ width: 80, fontSize: 10, padding: '2px 6px', borderRadius: 999, border: '1px solid var(--accent)', background: 'var(--bg-0)', color: 'var(--text-0)' }}
          placeholder="tag…"
        />
      ) : (
        <button onClick={() => setAdding(true)} style={{ background: 'none', border: '1px dashed var(--border)', cursor: 'pointer', color: 'var(--text-3)', padding: '2px 5px', borderRadius: 999, fontSize: 10 }}>
          <Plus size={9} />
        </button>
      )}
    </div>
  )
}

function FindingRow({ f }: { f: Finding }) {
  const sev = f.severity as 'critical' | 'high' | 'medium' | 'low' | 'info'
  return (
    <tr>
      <td><SevTag severity={sev} /></td>
      <td style={{ fontSize: 12, color: 'var(--text-0)', maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>
      <td className="mono dimmer" style={{ fontSize: 11 }}>{f.port_number ? `${f.port_number}/${f.protocol}` : '—'}</td>
      <td><VprBadge score={f.vpr_score} /></td>
      <td className="mono dimmer" style={{ fontSize: 11 }}>{f.cvss_score?.toFixed(1) ?? '—'}</td>
      <td><span className={`pill pill-${f.remediation_status === 'resolved' ? 'completed' : f.false_positive ? 'cancelled' : 'pending'}`} style={{ fontSize: 10 }}>{f.false_positive ? 'FP' : f.remediation_status}</span></td>
    </tr>
  )
}

export default function Assets() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<AssetItem | null>(null)

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['assets', search],
    queryFn: () => assetsApi.list({ search: search || undefined, limit: 200 }),
  })

  const { data: tagMap = {} } = useQuery({
    queryKey: ['host-tags-all'],
    queryFn: assetsApi.allTags,
  })

  const { data: selectedFindings = [] } = useQuery({
    queryKey: ['asset-findings', selected?.ip],
    queryFn: () => assetsApi.findings(selected!.ip),
    enabled: !!selected,
  })

  const addTagMut = useMutation({
    mutationFn: ({ ip, tag }: { ip: string; tag: string }) => assetsApi.addTag(ip, tag),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-tags-all'] }),
  })
  const removeTagMut = useMutation({
    mutationFn: ({ ip, tag }: { ip: string; tag: string }) => assetsApi.removeTag(ip, tag),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-tags-all'] }),
  })

  return (
    <div className="page-pad" style={{ maxWidth: 1480, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Server size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Assets</h1>
            <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>All discovered hosts across all scans, aggregated by IP</p>
          </div>
        </div>
        <div className="search" style={{ width: 260 }}>
          <Search size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP or hostname…" style={{ minWidth: 0 }} />
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 180px)', minHeight: 0 }}>
        {/* Asset table */}
        <div className="panel" style={{ flex: selected ? '0 0 60%' : '1', overflow: 'auto', minWidth: 0 }}>
          {isLoading ? (
            <div className="dimmer" style={{ padding: 24, fontSize: 13 }}>Loading…</div>
          ) : assets.length === 0 ? (
            <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-3)' }}>
              <Server size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
              <p style={{ fontSize: 13 }}>No assets discovered yet. Run a scan first.</p>
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hostname</th>
                  <th>OS</th>
                  <th>Scans</th>
                  <th>Findings (C/H/M/L)</th>
                  <th>Risk</th>
                  <th>Last seen</th>
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {assets.map(a => {
                  const tags = tagMap[a.ip] ?? []
                  const isSelected = selected?.ip === a.ip
                  return (
                    <tr key={a.ip} onClick={() => setSelected(isSelected ? null : a)}
                      className={isSelected ? 'selected' : ''}>
                      <td className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)' }}>{a.ip}</td>
                      <td className="mono dimmer" style={{ fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.hostname ?? '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.os_name ?? '—'}</td>
                      <td style={{ fontSize: 11 }}>{a.scan_count}</td>
                      <td><CHML c={a.findings_critical} h={a.findings_high} m={a.findings_medium} l={a.findings_low} /></td>
                      <td>
                        {a.risk_score > 0 ? (
                          <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: a.risk_score >= 80 ? 'var(--sev-critical)' : a.risk_score >= 30 ? 'var(--sev-high)' : 'var(--sev-medium)' }}>
                            {a.risk_score}
                          </span>
                        ) : <span className="dimmer" style={{ fontSize: 11 }}>0</span>}
                      </td>
                      <td className="dimmer" style={{ fontSize: 11 }}>{a.last_seen_at ? relTime(a.last_seen_at) : '—'}</td>
                      <td>
                        <TagChips ip={a.ip} tags={tags}
                          onAdd={tag => addTagMut.mutate({ ip: a.ip, tag })}
                          onRemove={tag => removeTagMut.mutate({ ip: a.ip, tag })}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Findings panel for selected asset */}
        {selected && (
          <div className="panel" style={{ flex: '0 0 38%', display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
            <div className="panel-head" style={{ gap: 10 }}>
              <AlertTriangle size={13} style={{ color: 'var(--accent)' }} />
              <span className="panel-title">{selected.ip} — All Findings</span>
              <span className="dimmer" style={{ fontSize: 11, marginLeft: 'auto' }}>{selectedFindings.length} total</span>
              <button onClick={() => setSelected(null)} className="btn btn-ghost btn-icon btn-sm"><X size={13} /></button>
            </div>
            <div style={{ flex: 1, overflow: 'auto' }}>
              {selectedFindings.length === 0 ? (
                <div className="dimmer" style={{ padding: 24, fontSize: 12, textAlign: 'center' }}>No findings for this host</div>
              ) : (
                <table className="tbl">
                  <thead><tr><th>Sev</th><th>Title</th><th>Port</th><th>VPR</th><th>CVSS</th><th>Status</th></tr></thead>
                  <tbody>{selectedFindings.map(f => <FindingRow key={f.id} f={f} />)}</tbody>
                </table>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
