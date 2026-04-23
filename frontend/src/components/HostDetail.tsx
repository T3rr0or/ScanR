/**
 * HostDetail — slide-over panel showing full host details.
 * Opened when a row is clicked in the Hosts tab of ScanDetail.
 */
import { X, Monitor, Globe, Cpu, Hash } from 'lucide-react'
import type { HostRead } from '@/api/hosts'
import { StatusPill } from '@/components/ui'

interface Props {
  host: HostRead
  scanId: string
  onClose: () => void
}

export default function HostDetail({ host, onClose }: Props) {
  const openPorts = (host.ports ?? []).filter(p => p.state === 'open')

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 40,
          background: 'oklch(0.05 0.01 255 / 0.5)',
        }}
      />

      {/* Slide-over panel */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          right: 0,
          bottom: 0,
          width: 580,
          background: 'var(--bg-1)',
          borderLeft: '1px solid var(--border)',
          zIndex: 41,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          background: 'var(--bg-1)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                <span
                  className="mono"
                  style={{ fontSize: 20, fontWeight: 700, color: 'var(--accent)', letterSpacing: '-0.01em' }}
                >
                  {host.ip}
                </span>
                <StatusPill status={host.status === 'up' ? 'completed' : 'cancelled'} />
              </div>
              {host.hostname && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <Globe size={12} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
                  <span style={{ fontSize: 12.5, color: 'var(--text-1)' }}>{host.hostname}</span>
                </div>
              )}
              {host.os_name && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <Cpu size={12} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: 'var(--text-2)' }}>
                    {host.os_name}
                    {host.os_accuracy != null && (
                      <span style={{ color: 'var(--text-3)', marginLeft: 6 }}>({host.os_accuracy}%)</span>
                    )}
                  </span>
                </div>
              )}
              {host.mac_address && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Hash size={12} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>{host.mac_address}</span>
                </div>
              )}
            </div>
            <button className="btn btn-ghost btn-icon" onClick={onClose}>
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {/* Open ports section */}
          <div style={{ marginBottom: 6, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Monitor size={13} style={{ color: 'var(--text-2)' }} />
            <span className="panel-title">Open Ports</span>
            {openPorts.length > 0 && (
              <span className="mono" style={{
                fontSize: 10.5, padding: '1px 6px',
                background: 'var(--bg-2)', borderRadius: 999, color: 'var(--text-1)',
              }}>
                {openPorts.length}
              </span>
            )}
          </div>

          {openPorts.length === 0 ? (
            <div style={{
              textAlign: 'center', padding: '40px 20px',
              color: 'var(--text-3)', fontSize: 12.5,
            }}>
              No open ports discovered
            </div>
          ) : (
            <div className="panel" style={{ overflow: 'hidden' }}>
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
                      <td className="mono" style={{ fontWeight: 600, color: 'var(--accent)', fontSize: 12 }}>
                        {p.number}
                      </td>
                      <td className="mono dim" style={{ fontSize: 11 }}>{p.protocol}</td>
                      <td>
                        <span className="mono" style={{
                          fontSize: 10.5, fontWeight: 600,
                          color: p.state === 'open' ? 'var(--ok)'
                            : p.state === 'closed' ? 'var(--sev-high)'
                            : 'var(--text-3)',
                        }}>
                          {p.state}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-1)' }}>
                        {p.service ?? <span className="dimmer">—</span>}
                      </td>
                      <td className="mono dim" style={{ fontSize: 11 }}>
                        {p.version ?? <span className="dimmer">—</span>}
                      </td>
                      <td style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', fontSize: 11 }}>
                        {p.banner
                          ? <span className="mono dim" title={p.banner}>{p.banner}</span>
                          : <span className="dimmer">—</span>
                        }
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* All ports (non-open) */}
          {(() => {
            const others = (host.ports ?? []).filter(p => p.state !== 'open')
            if (others.length === 0) return null
            return (
              <div style={{ marginTop: 20 }}>
                <div style={{ marginBottom: 6 }}>
                  <span className="panel-title">Closed / Filtered Ports</span>
                  <span className="mono" style={{
                    fontSize: 10.5, padding: '1px 6px', marginLeft: 8,
                    background: 'var(--bg-2)', borderRadius: 999, color: 'var(--text-3)',
                  }}>
                    {others.length}
                  </span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {others.map((p, idx) => (
                    <span key={idx} className="mono" style={{
                      fontSize: 10.5, padding: '2px 8px',
                      background: 'var(--bg-2)', border: '1px solid var(--border)',
                      borderRadius: 4, color: 'var(--text-3)',
                    }}>
                      {p.number}/{p.protocol}
                    </span>
                  ))}
                </div>
              </div>
            )
          })()}
        </div>
      </div>
    </>
  )
}
