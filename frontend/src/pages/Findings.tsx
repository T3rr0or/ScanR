import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, X, ExternalLink, Download, Search } from 'lucide-react'
import { findingsApi, type Finding } from '@/api/findings'
import { scansApi } from '@/api/scans'
import { SevTag, EmptyState } from '@/components/ui'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const SEV_LABELS: Record<string, string> = { '': 'All', critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

function safeParse(s: string | null | undefined): string[] {
  if (!s) return []
  try { return JSON.parse(s) } catch { return [] }
}

export default function Findings() {
  const [severity, setSeverity] = useState('')
  const [scanId, setScanId] = useState('')
  const [triage, setTriage] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const qc = useQueryClient()

  const { data: scans = [] } = useQuery({ queryKey: ['scans', 0], queryFn: () => scansApi.list({ limit: 200 }) })

  const params: Record<string, string> = {}
  if (severity) params.severity = severity
  if (scanId) params.scan_id = scanId

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', severity, scanId],
    queryFn: () => findingsApi.list(Object.keys(params).length ? params : undefined),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { false_positive?: boolean; analyst_notes?: string; remediation_status?: string } }) =>
      findingsApi.update(id, body),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      if (selected?.id === updated.id) setSelected(updated)
    },
  })

  const triaged = triage === 'fp'
    ? findings.filter(f => f.false_positive)
    : triage === 'accepted'
      ? findings.filter(f => !f.false_positive && f.remediation_status === 'accepted_risk')
      : triage === 'open'
        ? findings.filter(f => !f.false_positive && f.remediation_status !== 'accepted_risk')
        : findings

  const filtered = search
    ? triaged.filter(f => f.title.toLowerCase().includes(search.toLowerCase()) || (f.host_ip ?? '').includes(search) || f.plugin_id.includes(search) || safeParse(f.cve_ids).some(id => id.toLowerCase().includes(search.toLowerCase())))
    : triaged

  const counts = {
    all: findings.length,
    open: findings.filter(f => !f.false_positive && f.remediation_status !== 'accepted_risk').length,
    fp: findings.filter(f => f.false_positive).length,
    accepted: findings.filter(f => !f.false_positive && f.remediation_status === 'accepted_risk').length,
  }

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden', flexDirection: 'column' }}>
      {/* Page header */}
      <div style={{ padding: '16px 20px 12px', borderBottom: '1px solid var(--border)', background: 'var(--bg-1)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div>
            <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>Findings</h1>
            <div className="mono dim" style={{ fontSize: 11, marginTop: 2 }}>{findings.length} findings across all scans</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm"><Download size={11} /> Export CSV</button>
          </div>
        </div>

        {/* Severity chips */}
        <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
          {SEVERITIES.map(s => {
            const n = s === '' ? findings.length : findings.filter(f => f.severity === s).length
            const active = severity === s
            return (
              <button key={s} onClick={() => setSeverity(s)} style={{
                padding: '5px 10px', borderRadius: 6, fontSize: 11, textTransform: 'capitalize',
                background: active ? 'var(--bg-3)' : 'transparent',
                color: active ? 'var(--text-0)' : 'var(--text-2)',
                border: '1px solid ' + (active ? 'var(--border-strong)' : 'transparent'),
                display: 'inline-flex', alignItems: 'center', gap: 5, cursor: 'pointer',
              }}>
                {s && <span className="sev-bar" style={{ background: `var(--sev-${s})`, height: 10 }} />}
                {SEV_LABELS[s]} <span className="mono dimmer" style={{ marginLeft: 2 }}>{n}</span>
              </button>
            )
          })}
          <div style={{ width: 1, height: 16, background: 'var(--border)', margin: '0 4px' }} />
          {([['', 'All', counts.all], ['open', 'Open', counts.open], ['fp', 'FP', counts.fp], ['accepted', 'Accepted', counts.accepted]] as const).map(([v, label, count]) => {
            const active = triage === v
            return (
              <button key={v} onClick={() => setTriage(v)} style={{
                padding: '5px 10px', borderRadius: 6, fontSize: 11,
                background: active ? 'var(--bg-3)' : 'transparent',
                color: active ? 'var(--text-0)' : 'var(--text-2)',
                border: '1px solid ' + (active ? 'var(--border-strong)' : 'transparent'),
                display: 'inline-flex', alignItems: 'center', gap: 4, cursor: 'pointer',
              }}>
                {label} <span className="mono dimmer" style={{ fontSize: 10 }}>{count}</span>
              </button>
            )
          })}
          <div style={{ flex: 1 }} />
          <div className="search" style={{ width: 260 }}>
            <Search size={13} color="var(--text-3)" />
            <input placeholder="Title, host, CVE, plugin…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <select value={scanId} onChange={e => setScanId(e.target.value)} className="select-field" style={{ fontSize: 12, width: 'auto' }}>
            <option value="">All scans</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </div>
      </div>

      {/* Content */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Main table */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 4 }}></th>
                <th>Severity</th>
                <th>Title</th>
                <th>Host</th>
                <th>Port</th>
                <th>Plugin</th>
                <th>CVSS</th>
                <th>CVE</th>
                <th>Scan</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr
                  key={f.id}
                  onClick={() => setSelected(f)}
                  className={selected?.id === f.id ? 'selected' : ''}
                  style={{
                    opacity: f.false_positive ? 0.45 : 1,
                  }}
                >
                  <td style={{ padding: 0 }}>
                    <span className={`sev-bar ${f.severity}`} style={{ height: 34, width: 3, display: 'block' }} />
                  </td>
                  <td><SevTag severity={f.severity} /></td>
                  <td style={{ maxWidth: 300 }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-0)', fontWeight: 500 }}>
                      {f.title}
                    </div>
                  </td>
                  <td className="mono" style={{ color: 'var(--accent)', fontSize: 11 }}>{f.host_ip ?? '—'}</td>
                  <td className="mono dimmer">{f.port_number ? `${f.port_number}/${f.protocol ?? 'tcp'}` : '—'}</td>
                  <td className="mono dimmer" style={{ fontSize: 11 }}>{f.plugin_id}</td>
                  <td className="mono" style={{ color: f.cvss_score != null && f.cvss_score >= 9 ? 'var(--sev-critical)' : f.cvss_score != null && f.cvss_score >= 7 ? 'var(--sev-high)' : 'var(--text-2)', fontWeight: 600 }}>
                    {f.cvss_score?.toFixed(1) ?? '—'}
                  </td>
                  <td>
                    {(() => {
                      const ids = safeParse(f.cve_ids)
                      return ids.length > 0
                        ? <span className="mono" style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'oklch(0.68 0.21 27 / 0.12)', color: 'var(--sev-high)', border: '1px solid oklch(0.68 0.21 27 / 0.25)', whiteSpace: 'nowrap' }}>{ids[0]}</span>
                        : <span className="dimmer">—</span>
                    })()}
                  </td>
                  <td className="mono dim" style={{ fontSize: 10.5 }}>{f.scan_id?.slice(0, 8) ?? '—'}</td>
                  <td>
                    {f.false_positive
                      ? <span className="pill pill-cancelled" style={{ fontSize: 10 }}>FP</span>
                      : f.remediation_status === 'accepted_risk'
                        ? <span className="pill" style={{ fontSize: 10, background: 'var(--bg-3)', color: 'var(--text-2)' }}>accepted</span>
                        : <span className="pill pill-pending" style={{ fontSize: 10 }}>open</span>
                    }
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <EmptyState icon={<AlertTriangle size={28} />} message="No findings match the current filters" />
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Finding drawer */}
      {selected && (
        <FindingDrawer
          finding={selected}
          onClose={() => setSelected(null)}
          onUpdate={(body) => updateMut.mutate({ id: selected.id, body })}
          isPending={updateMut.isPending}
        />
      )}
      </div>
    </div>
  )
}

function FindingDrawer({ finding: f, onClose, onUpdate, isPending }: {
  finding: Finding
  onClose: () => void
  onUpdate: (body: { false_positive?: boolean; analyst_notes?: string; remediation_status?: string }) => void
  isPending: boolean
}) {
  const cveIds = safeParse(f.cve_ids)
  const mitreTags = safeParse(f.mitre_tags)
  const complianceTags = safeParse(f.compliance_tags)
  const refs = safeParse(f.references)

  return (
    <div style={{
      width: 420, flexShrink: 0, borderLeft: '1px solid var(--border)',
      background: 'var(--bg-1)', display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 6 }}>
          <SevTag severity={f.severity} />
          <button onClick={onClose} className="btn btn-ghost btn-icon btn-sm" style={{ marginLeft: 'auto' }}>
            <X size={14} />
          </button>
        </div>
        <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text-0)', lineHeight: 1.4 }}>{f.title}</div>
        <div style={{ display: 'flex', gap: 16, marginTop: 10 }}>
          {f.cvss_score != null && (
            <div>
              <div className="panel-title" style={{ fontSize: 9.5 }}>CVSS</div>
              <div className="mono" style={{
                fontSize: 15, fontWeight: 700, marginTop: 2,
                color: f.cvss_score >= 9 ? 'var(--sev-critical)' : f.cvss_score >= 7 ? 'var(--sev-high)' : f.cvss_score >= 4 ? 'var(--sev-medium)' : 'var(--sev-low)',
              }}>
                {f.cvss_score.toFixed(1)}
              </div>
            </div>
          )}
          <div>
            <div className="panel-title" style={{ fontSize: 9.5 }}>Host</div>
            <div className="mono" style={{ fontSize: 12, color: 'var(--accent)', marginTop: 2 }}>{f.host_ip ?? '—'}</div>
          </div>
          <div>
            <div className="panel-title" style={{ fontSize: 9.5 }}>Port</div>
            <div className="mono" style={{ fontSize: 12, marginTop: 2 }}>{f.port_number ? `${f.port_number}/${f.protocol ?? 'tcp'}` : '—'}</div>
          </div>
          <div>
            <div className="panel-title" style={{ fontSize: 9.5 }}>Plugin</div>
            <div className="mono" style={{ fontSize: 11, marginTop: 2 }}>{f.plugin_id}</div>
          </div>
        </div>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflow: 'auto', padding: '14px 16px' }}>
        {f.description && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>Description</div>
            <p style={{ fontSize: 12, color: 'var(--text-1)', lineHeight: 1.6 }}>{f.description}</p>
          </section>
        )}

        {f.evidence && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>Evidence</div>
            <pre className="console" style={{ padding: '10px 12px', fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
              {f.evidence}
            </pre>
          </section>
        )}

        {f.remediation && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>Remediation</div>
            <div style={{
              background: 'oklch(0.22 0.05 145 / 0.4)', borderLeft: '3px solid var(--ok)',
              padding: '10px 12px', borderRadius: 4, fontSize: 12, color: 'var(--text-1)', lineHeight: 1.6,
            }}>
              {f.remediation}
            </div>
          </section>
        )}

        {cveIds.length > 0 && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>CVE IDs</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {cveIds.map(id => (
                <span key={id} className="mono" style={{ fontSize: 11, color: 'var(--sev-high)', background: 'oklch(0.45 0.18 30 / 0.12)', padding: '2px 6px', borderRadius: 4 }}>{id}</span>
              ))}
            </div>
          </section>
        )}

        {mitreTags.length > 0 && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>MITRE ATT&CK</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {mitreTags.map(t => (
                <span key={t} className="mono" style={{ fontSize: 11, color: 'var(--sev-medium)', background: 'oklch(0.55 0.15 60 / 0.12)', padding: '2px 6px', borderRadius: 4 }}>{t}</span>
              ))}
            </div>
          </section>
        )}

        {complianceTags.length > 0 && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>Compliance</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {complianceTags.map(t => (
                <span key={t} className="mono" style={{ fontSize: 11, color: 'var(--accent)', background: 'var(--accent-soft)', padding: '2px 6px', borderRadius: 4 }}>{t}</span>
              ))}
            </div>
          </section>
        )}

        {refs.length > 0 && (
          <section style={{ marginBottom: 14 }}>
            <div className="panel-title" style={{ marginBottom: 6 }}>References</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {refs.map(url => (
                <a key={url} href={url} target="_blank" rel="noreferrer"
                  style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--accent)', textDecoration: 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  <ExternalLink size={11} style={{ flexShrink: 0 }} />
                  {url}
                </a>
              ))}
            </div>
          </section>
        )}

        <section style={{ marginBottom: 14 }}>
          <div className="panel-title" style={{ marginBottom: 6 }}>Analyst Notes</div>
          <textarea
            key={f.id}
            defaultValue={f.analyst_notes ?? ''}
            onBlur={e => onUpdate({ analyst_notes: e.target.value })}
            placeholder="Add notes…"
            className="textarea"
            style={{ fontSize: 12, minHeight: 72 }}
          />
        </section>
      </div>

      {/* Triage actions */}
      <div style={{ padding: '12px 16px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8, flexShrink: 0 }}>
        <button
          onClick={() => onUpdate({ false_positive: !f.false_positive })}
          disabled={isPending}
          className={`btn btn-sm ${f.false_positive ? 'btn-primary' : 'btn-ghost'}`}
          style={{ flex: 1 }}
        >
          {f.false_positive ? 'Unmark FP' : 'False Positive'}
        </button>
        <button
          onClick={() => onUpdate({ remediation_status: f.remediation_status === 'accepted_risk' ? 'open' : 'accepted_risk' })}
          disabled={isPending || !!f.false_positive}
          className={`btn btn-sm ${f.remediation_status === 'accepted_risk' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ flex: 1 }}
        >
          {f.remediation_status === 'accepted_risk' ? 'Reopen' : 'Accept Risk'}
        </button>
      </div>
    </div>
  )
}
