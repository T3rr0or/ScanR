/**
 * HostDetail — full-screen modal showing host details: ports + findings.
 */
import { useState } from 'react'
import { X, Globe, Cpu, Hash, Monitor, AlertTriangle } from 'lucide-react'
import type { HostRead } from '@/api/hosts'
import type { Finding } from '@/api/findings'
import { StatusPill, SevTag } from '@/components/ui'
import FindingDetailPanel from '@/components/FindingDetailPanel'
import SortableTh from '@/components/SortableTh'
import { useSortableFindings } from '@/hooks/useSortableFindings'

interface Props {
  host: HostRead
  scanId: string
  findings?: Finding[]
  onClose: () => void
}

export default function HostDetail({ host, findings = [], onClose }: Props) {
  const [tab, setTab] = useState<'ports' | 'findings'>('ports')
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null)
  const openPorts = (host.ports ?? []).filter(p => p.state === 'open')
  const { sorted: sortedFindings, sortKey, sortDir, toggleSort } = useSortableFindings(findings)

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 50,
          background: 'oklch(0.05 0.01 255 / 0.75)',
          animation: 'fadeIn 0.18s ease',
        }}
      />

      {/* Centered full-screen modal */}
      <div
        style={{
          position: 'fixed', inset: 0, zIndex: 51,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: 24, pointerEvents: 'none',
        }}
      >
        <div
          onClick={e => e.stopPropagation()}
          style={{
            width: '100%', maxWidth: 1100,
            maxHeight: 'calc(100vh - 48px)',
            background: 'var(--bg-1)',
            border: '1px solid var(--border)',
            borderRadius: 12,
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden',
            boxShadow: '0 24px 80px #0012',
            pointerEvents: 'auto',
            animation: 'slideUp 0.22s cubic-bezier(0.32, 0.72, 0, 1)',
          }}
        >
          {/* Header */}
          <div style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border)',
            flexShrink: 0,
            display: 'flex', alignItems: 'flex-start', gap: 14,
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span className="mono" style={{ fontSize: 22, fontWeight: 700, color: 'var(--accent)', letterSpacing: '-0.01em' }}>
                  {host.ip}
                </span>
                <StatusPill status={host.status === 'up' ? 'completed' : 'cancelled'} />
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px 20px' }}>
                {host.hostname && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Globe size={11} style={{ color: 'var(--text-3)' }} />
                    <span style={{ fontSize: 12, color: 'var(--text-1)' }}>{host.hostname}</span>
                  </div>
                )}
                {host.os_name && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Cpu size={11} style={{ color: 'var(--text-3)' }} />
                    <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
                      {host.os_name}
                      {host.os_accuracy != null && <span style={{ color: 'var(--text-3)', marginLeft: 5 }}>({host.os_accuracy}%)</span>}
                    </span>
                  </div>
                )}
                {host.mac_address && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <Hash size={11} style={{ color: 'var(--text-3)' }} />
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>{host.mac_address}</span>
                  </div>
                )}
              </div>
            </div>
            <button className="btn btn-ghost btn-icon" onClick={onClose}><X size={15} /></button>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 2, padding: '8px 20px 0', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
            <TabBtn active={tab === 'ports'} onClick={() => setTab('ports')}
              icon={<Monitor size={12} />} label="Open Ports" count={openPorts.length} />
            <TabBtn active={tab === 'findings'} onClick={() => setTab('findings')}
              icon={<AlertTriangle size={12} />} label="Findings" count={findings.length} />
          </div>

          {/* Body */}
          <div style={{ flex: 1, overflow: 'auto' }}>
            {tab === 'ports' && (
              openPorts.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontSize: 12.5 }}>No open ports discovered</div>
              ) : (
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>State</th>
                      <th>Service</th>
                      <th>Version</th>
                      <th>Banner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {openPorts.map((p, idx) => (
                      <tr key={idx} style={{ cursor: 'default' }}>
                        <td className="mono" style={{ fontWeight: 600, color: 'var(--accent)', fontSize: 13 }}>{p.number}</td>
                        <td className="mono dim" style={{ fontSize: 11 }}>{p.protocol}</td>
                        <td>
                          <span className="mono" style={{ fontSize: 11, fontWeight: 600, color: 'var(--ok)' }}>{p.state}</span>
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-1)' }}>{p.service ?? <span className="dimmer">—</span>}</td>
                        <td className="mono dim" style={{ fontSize: 11 }}>{p.version ?? <span className="dimmer">—</span>}</td>
                        <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', fontSize: 11 }}>
                          {p.banner ? <span className="mono dim" title={p.banner}>{p.banner}</span> : <span className="dimmer">—</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}

            {tab === 'findings' && (
              findings.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-3)', fontSize: 12.5 }}>No findings for this host</div>
              ) : (
                <table className="tbl">
                  <thead>
                    <tr>
                      <SortableTh label="Sev" sortKey="severity" active={sortKey} dir={sortDir} onSort={toggleSort} />
                      <SortableTh label="Title" sortKey="title" active={sortKey} dir={sortDir} onSort={toggleSort} />
                      <SortableTh label="Port" sortKey="port" active={sortKey} dir={sortDir} onSort={toggleSort} />
                      <SortableTh label="VPR" sortKey="vpr" active={sortKey} dir={sortDir} onSort={toggleSort} />
                      <SortableTh label="CVSS" sortKey="cvss" active={sortKey} dir={sortDir} onSort={toggleSort} />
                      <SortableTh label="Status" sortKey="status" active={sortKey} dir={sortDir} onSort={toggleSort} />
                    </tr>
                  </thead>
                  <tbody>
                    {sortedFindings.map(f => (
                      <tr key={f.id} onClick={() => setDetailFinding(f)} style={{ cursor: 'pointer' }} title="Click for details">
                        <td><SevTag severity={f.severity as any} /></td>
                        <td style={{ fontSize: 12, color: 'var(--text-0)' }}>{f.title}</td>
                        <td className="mono dimmer" style={{ fontSize: 11 }}>{f.port_number ? `${f.port_number}/${f.protocol}` : '—'}</td>
                        <td>
                          {f.vpr_score != null ? (
                            <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: f.vpr_score >= 8 ? 'var(--sev-critical)' : f.vpr_score >= 5 ? 'var(--sev-high)' : 'var(--sev-medium)', background: `${f.vpr_score >= 8 ? 'var(--sev-critical)' : 'var(--sev-medium)'}20`, padding: '1px 5px', borderRadius: 3 }}>{f.vpr_score.toFixed(1)}</span>
                          ) : <span className="dimmer" style={{ fontSize: 11 }}>—</span>}
                        </td>
                        <td className="mono dimmer" style={{ fontSize: 11 }}>{f.cvss_score?.toFixed(1) ?? '—'}</td>
                        <td><span className={`pill pill-${f.remediation_status === 'resolved' ? 'completed' : f.false_positive ? 'cancelled' : 'pending'}`} style={{ fontSize: 10 }}>{f.false_positive ? 'FP' : f.remediation_status}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            )}
          </div>
        </div>
      </div>

      <FindingDetailPanel finding={detailFinding} onClose={() => setDetailFinding(null)} />

      <style>{`
        @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(16px) scale(0.98) } to { opacity: 1; transform: translateY(0) scale(1) } }
      `}</style>
    </>
  )
}

function TabBtn({ active, onClick, icon, label, count }: {
  active: boolean; onClick: () => void; icon: React.ReactNode; label: string; count: number
}) {
  return (
    <button
      onClick={onClick}
      className={`tab ${active ? 'active' : ''}`}
      style={{ marginBottom: -1 }}
    >
      {icon}{label}
      <span className="count">{count}</span>
    </button>
  )
}
