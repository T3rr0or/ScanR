import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, Search, X, Users } from 'lucide-react'
import { vulnerabilitiesApi, type VulnerabilityItem } from '@/api/vulnerabilities'
import { findingsApi } from '@/api/findings'
import { SevTag, relTime } from '@/components/ui'
import FindingDetailPanel from '@/components/FindingDetailPanel'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']
const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

type VulnSortKey = 'severity' | 'title' | 'hosts' | 'open' | 'vpr' | 'cvss' | 'first_seen' | 'last_seen'


function VTh({ label, sortKey, active, dir, onSort, style }: { label: string; sortKey: VulnSortKey; active: VulnSortKey; dir: 'asc' | 'desc'; onSort: (k: VulnSortKey) => void; style?: React.CSSProperties }) {
  const isActive = active === sortKey
  return (
    <th onClick={() => onSort(sortKey)} style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap', color: isActive ? 'var(--accent)' : undefined, ...style }}>
      {label}<span style={{ marginLeft: 4, opacity: isActive ? 1 : 0.25, fontSize: 9 }}>{isActive ? (dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
    </th>
  )
}

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
  const [detailFindingId, setDetailFindingId] = useState<string | null>(null)
  const [vKey, setVKey] = useState<VulnSortKey>('open')
  const [vDir, setVDir] = useState<'asc' | 'desc'>('desc')

  function vToggle(k: VulnSortKey) {
    if (vKey === k) {
      setVDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setVKey(k)
      setVDir(k === 'title' ? 'asc' : 'desc')
    }
  }

  const { data: detailFinding = null } = useQuery({
    queryKey: ['finding', detailFindingId],
    queryFn: () => findingsApi.get(detailFindingId!),
    enabled: !!detailFindingId,
  })

  const { data: rawVulns = [], isLoading } = useQuery({
    queryKey: ['vulnerabilities', search, severity],
    queryFn: () => vulnerabilitiesApi.list({ search: search || undefined, severity: severity || undefined, limit: 300 }),
  })

  const vulns = useMemo(() => {
    const m = vDir === 'asc' ? 1 : -1
    return [...rawVulns].sort((a, b) => {
      switch (vKey) {
        case 'severity':   return m * ((SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99))
        case 'title':      return m * a.title.localeCompare(b.title)
        case 'hosts':      return m * (a.host_count - b.host_count)
        case 'open':       return m * (a.open_count - b.open_count)
        case 'vpr':        return m * ((a.max_vpr ?? -1) - (b.max_vpr ?? -1))
        case 'cvss':       return m * ((a.max_cvss ?? -1) - (b.max_cvss ?? -1))
        case 'first_seen': return m * ((a.first_seen_at ?? '').localeCompare(b.first_seen_at ?? ''))
        case 'last_seen':  return m * ((a.last_seen_at ?? '').localeCompare(b.last_seen_at ?? ''))
        default: return 0
      }
    })
  }, [rawVulns, vKey, vDir])

  const { data: hosts = [] } = useQuery({
    queryKey: ['vuln-hosts', selected?.plugin_id],
    queryFn: () => vulnerabilitiesApi.hosts(selected!.plugin_id),
    enabled: !!selected,
  })

  return (
    <>
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
                  <VTh label="Severity" sortKey="severity" active={vKey} dir={vDir} onSort={vToggle} />
                  <VTh label="Vulnerability" sortKey="title" active={vKey} dir={vDir} onSort={vToggle} />
                  <VTh label="Hosts" sortKey="hosts" active={vKey} dir={vDir} onSort={vToggle} style={{ textAlign: 'center' }} />
                  <VTh label="Open" sortKey="open" active={vKey} dir={vDir} onSort={vToggle} style={{ textAlign: 'center' }} />
                  <VTh label="Max VPR" sortKey="vpr" active={vKey} dir={vDir} onSort={vToggle} />
                  <VTh label="Max CVSS" sortKey="cvss" active={vKey} dir={vDir} onSort={vToggle} />
                  <VTh label="First seen" sortKey="first_seen" active={vKey} dir={vDir} onSort={vToggle} />
                  <VTh label="Last seen" sortKey="last_seen" active={vKey} dir={vDir} onSort={vToggle} />
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
                    <tr key={h.finding_id} onClick={() => setDetailFindingId(h.finding_id)} style={{ cursor: 'pointer' }} title="Click to view finding details">
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

    <FindingDetailPanel finding={detailFinding} onClose={() => setDetailFindingId(null)} />
    </>
  )
}
