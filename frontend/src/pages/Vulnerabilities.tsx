import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Search, X, Users } from 'lucide-react'
import { vulnerabilitiesApi, type VulnerabilityItem } from '@/api/vulnerabilities'
import { SevTag, relTime } from '@/components/ui'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

function VprBadge({ score }: { score: number | null }) {
  if (score == null) return <span className="dimmer" style={{ fontSize: 11 }}>—</span>
  const color = score >= 8 ? 'var(--sev-critical)' : score >= 5 ? 'var(--sev-high)' : 'var(--sev-medium)'
  return <span className="mono" style={{ fontSize: 11, fontWeight: 700, color, background: `${color}20`, padding: '1px 5px', borderRadius: 3 }}>{score.toFixed(1)}</span>
}

function statusColor(s: string) {
  if (s === 'resolved') return 'var(--ok)'
  if (s === 'accepted_risk') return 'var(--sev-medium)'
  return 'var(--text-3)'
}

export default function Vulnerabilities() {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('')
  const [selected, setSelected] = useState<VulnerabilityItem | null>(null)

  const { data: vulns = [], isLoading } = useQuery({
    queryKey: ['vulnerabilities', search, severity],
    queryFn: () => vulnerabilitiesApi.list({ search: search || undefined, severity: severity || undefined, limit: 300 }),
  })

  const { data: hosts = [] } = useQuery({
    queryKey: ['vuln-hosts', selected?.plugin_id],
    queryFn: () => vulnerabilitiesApi.hosts(selected!.plugin_id),
    enabled: !!selected,
  })

  return (
    <div className="page-pad" style={{ maxWidth: 1480, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldAlert size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Vulnerabilities</h1>
            <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>All findings grouped by vulnerability type across all scans</p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select value={severity} onChange={e => setSeverity(e.target.value)} className="select-field" style={{ width: 'auto' }}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
          </select>
          <div className="search" style={{ width: 220 }}>
            <Search size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search plugin or title…" style={{ minWidth: 0 }} />
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 16, height: 'calc(100vh - 180px)', minHeight: 0 }}>
        {/* Vuln table */}
        <div className="panel" style={{ flex: selected ? '0 0 58%' : '1', overflow: 'auto' }}>
          {isLoading ? (
            <div className="dimmer" style={{ padding: 24, fontSize: 13 }}>Loading…</div>
          ) : vulns.length === 0 ? (
            <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-3)' }}>
              <ShieldAlert size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
              <p style={{ fontSize: 13 }}>No vulnerabilities found.</p>
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Vulnerability</th>
                  <th style={{ textAlign: 'center' }}>Hosts</th>
                  <th style={{ textAlign: 'center' }}>Open</th>
                  <th>Max VPR</th>
                  <th>Max CVSS</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {vulns.map(v => {
                  const isSelected = selected?.plugin_id === v.plugin_id
                  return (
                    <tr key={v.plugin_id} onClick={() => setSelected(isSelected ? null : v)} className={isSelected ? 'selected' : ''}>
                      <td><SevTag severity={v.severity as any} /></td>
                      <td style={{ maxWidth: 300 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v.title}</div>
                        <div className="mono dimmer" style={{ fontSize: 10, marginTop: 2 }}>{v.plugin_id}</div>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
                          <Users size={11} style={{ opacity: 0.6 }} />{v.host_count}
                        </span>
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <span style={{ fontSize: 12, color: v.open_count > 0 ? 'var(--sev-high)' : 'var(--ok)' }}>{v.open_count}</span>
                      </td>
                      <td><VprBadge score={v.max_vpr} /></td>
                      <td className="mono dimmer" style={{ fontSize: 11 }}>{v.max_cvss?.toFixed(1) ?? '—'}</td>
                      <td className="dimmer" style={{ fontSize: 11 }}>{v.first_seen_at ? relTime(v.first_seen_at) : '—'}</td>
                      <td className="dimmer" style={{ fontSize: 11 }}>{v.last_seen_at ? relTime(v.last_seen_at) : '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Affected hosts panel */}
        {selected && (
          <div className="panel" style={{ flex: '0 0 40%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div className="panel-head" style={{ gap: 8 }}>
              <ShieldAlert size={13} style={{ color: 'var(--accent)' }} />
              <span className="panel-title" style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selected.title}</span>
              <button onClick={() => setSelected(null)} className="btn btn-ghost btn-icon btn-sm"><X size={13} /></button>
            </div>
            <div style={{ padding: '8px 14px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)' }}>
              <span>{hosts.length} host(s) affected</span>
              <span style={{ color: 'var(--sev-high)' }}>{hosts.filter(h => !h.false_positive && h.remediation_status === 'open').length} open</span>
              <span style={{ color: 'var(--ok)' }}>{hosts.filter(h => h.remediation_status === 'resolved').length} resolved</span>
            </div>
            <div style={{ flex: 1, overflow: 'auto' }}>
              <table className="tbl">
                <thead><tr><th>IP</th><th>Port</th><th>Scan</th><th>Status</th></tr></thead>
                <tbody>
                  {hosts.map(h => (
                    <tr key={h.finding_id}>
                      <td className="mono" style={{ fontSize: 12, color: 'var(--accent)' }}>{h.ip}</td>
                      <td className="mono dimmer" style={{ fontSize: 11 }}>{h.port_number ?? '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.scan_name}</td>
                      <td>
                        <span style={{ fontSize: 10, fontWeight: 600, color: statusColor(h.remediation_status) }}>
                          {h.false_positive ? 'FP' : h.remediation_status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
