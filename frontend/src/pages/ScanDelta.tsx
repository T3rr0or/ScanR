/**
 * ScanDelta — compare two scans side-by-side.
 * Shows new/resolved/persisting findings, new/removed hosts, port changes.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { X, ArrowRight, TrendingUp, TrendingDown, Minus, Server, Unlock, Globe } from 'lucide-react'
import { scansApi } from '@/api/scans'
import SeverityBadge from '@/components/SeverityBadge'

interface Props {
  scanId: string
  scanName: string
  onClose: () => void
}

type DeltaTab = 'new' | 'resolved' | 'persisting' | 'subdomains' | 'hosts' | 'ports'

export default function ScanDelta({ scanId, scanName, onClose }: Props) {
  const [baselineId, setBaselineId] = useState<string>('')
  const [tab, setTab] = useState<DeltaTab>('new')

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', 0],
    queryFn: () => scansApi.list({ limit: 200, offset: 0 }),
  })
  const candidates = scans.filter(
    s => s.id !== scanId && (s.status === 'completed' || s.status === 'failed')
  )

  const { data: delta, isLoading, error } = useQuery({
    queryKey: ['delta', scanId, baselineId],
    queryFn: () => scansApi.delta(scanId, baselineId),
    enabled: !!baselineId,
  })
  const { data: latestDelta, isLoading: latestLoading, error: latestError } = useQuery({
    queryKey: ['delta-latest', scanId],
    queryFn: () => scansApi.latestDelta(scanId),
    enabled: !baselineId,
    retry: false,
  })

  const activeDelta = baselineId ? delta : latestDelta
  const loading = baselineId ? isLoading : latestLoading
  const loadError = baselineId ? error : latestError
  const baselineName = baselineId
    ? candidates.find(s => s.id === baselineId)?.name ?? ''
    : latestDelta?.baseline_scan?.name ?? ''

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex' }}>
      {/* Backdrop */}
      <div
        style={{ flex: 1, background: 'oklch(0.05 0.01 255 / 0.55)' }}
        onClick={onClose}
      />

      {/* Slide-over panel */}
      <div
        style={{
          width: '100%',
          maxWidth: 900,
          background: 'var(--bg-1)',
          borderLeft: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          boxShadow: 'var(--shadow-2)',
        }}
      >
        {/* Header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            padding: '14px 20px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-2)',
            flexShrink: 0,
          }}
        >
          <div style={{ flex: 1, minWidth: 0 }}>
            <h2 style={{ fontWeight: 600, color: 'var(--text-0)', fontSize: 15, margin: 0 }}>
              Scan Comparison
            </h2>
            <div
              style={{
                fontSize: 12,
                color: 'var(--text-3)',
                display: 'flex',
                alignItems: 'center',
                gap: 6,
                marginTop: 2,
                flexWrap: 'wrap',
              }}
            >
              <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>{scanName}</span>
              {baselineName && (
                <>
                  <ArrowRight size={13} />
                  <span>{baselineName} (baseline)</span>
                </>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="btn btn-ghost btn-icon"
            title="Close"
          >
            <X size={16} />
          </button>
        </div>

        {/* Baseline selector */}
        <div
          style={{
            padding: '12px 20px',
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-1)',
            flexShrink: 0,
          }}
        >
          <label className="label">Compare against baseline scan</label>
          <select
            value={baselineId}
            onChange={e => setBaselineId(e.target.value)}
            className="select-field"
          >
            <option value="">— select a baseline —</option>
            {candidates.map(s => (
              <option key={s.id} value={s.id}>
                {s.name} ({new Date(s.created_at).toLocaleDateString()}) — {s.hosts_up} hosts
              </option>
            ))}
          </select>
          {!baselineId && latestDelta?.baseline_scan && (
            <p style={{ marginTop: 6, fontSize: 11, color: 'var(--text-3)' }}>
              Automatically comparing against latest matching scan: <strong>{latestDelta.baseline_scan.name}</strong>
            </p>
          )}
          {candidates.length === 0 && (
            <p style={{ marginTop: 6, fontSize: 11, color: 'var(--text-3)' }}>
              No other completed scans available to compare against.
            </p>
          )}
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
          {!baselineId && !latestDelta && !loadError && (
            <div
              style={{
                flex: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-3)',
                fontSize: 13,
              }}
            >
              {latestLoading ? 'Looking for latest matching baseline...' : 'Select a baseline scan above to see the delta'}
            </div>
          )}

          {loading && (
            <div
              style={{
                flex: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--text-3)',
                fontSize: 13,
              }}
            >
              Loading comparison…
            </div>
          )}

          {loadError && !activeDelta && (
            <div
              style={{
                flex: 1,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--sev-high)',
                fontSize: 13,
              }}
            >
              No previous matching scan found yet.
            </div>
          )}

          {activeDelta && (
            <>
              {/* Summary cards */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))',
                  gap: 10,
                  padding: '14px 20px',
                  borderBottom: '1px solid var(--border)',
                  flexShrink: 0,
                }}
              >
                <SummaryCard
                  label="New Findings"
                  value={activeDelta.summary.new_findings}
                  valueColor={activeDelta.summary.new_findings > 0 ? 'var(--sev-critical)' : 'var(--text-1)'}
                  bgColor={activeDelta.summary.new_findings > 0 ? 'oklch(0.70 0.22 352 / 0.08)' : 'var(--bg-2)'}
                  borderColor={activeDelta.summary.new_findings > 0 ? 'oklch(0.70 0.22 352 / 0.3)' : 'var(--border)'}
                  icon={<TrendingUp size={14} />}
                  onClick={() => setTab('new')}
                  active={tab === 'new'}
                />
                <SummaryCard
                  label="Resolved"
                  value={activeDelta.summary.resolved_findings}
                  valueColor="var(--ok)"
                  bgColor="oklch(0.75 0.15 145 / 0.08)"
                  borderColor="oklch(0.75 0.15 145 / 0.3)"
                  icon={<TrendingDown size={14} />}
                  onClick={() => setTab('resolved')}
                  active={tab === 'resolved'}
                />
                <SummaryCard
                  label="Persisting"
                  value={activeDelta.summary.persisting_findings}
                  valueColor="var(--sev-high)"
                  bgColor="oklch(0.68 0.21 27 / 0.08)"
                  borderColor="oklch(0.68 0.21 27 / 0.3)"
                  icon={<Minus size={14} />}
                  onClick={() => setTab('persisting')}
                  active={tab === 'persisting'}
                />
                <SummaryCard
                  label="New Subdomains"
                  value={activeDelta.summary.new_subdomains ?? 0}
                  valueColor="var(--accent)"
                  bgColor="var(--accent-soft)"
                  borderColor="oklch(0.78 0.14 200 / 0.3)"
                  icon={<Globe size={14} />}
                  onClick={() => setTab('subdomains')}
                  active={tab === 'subdomains'}
                />
                <SummaryCard
                  label="New Hosts"
                  value={activeDelta.summary.new_hosts}
                  valueColor="var(--accent)"
                  bgColor="var(--accent-soft)"
                  borderColor="oklch(0.78 0.14 200 / 0.3)"
                  icon={<Server size={14} />}
                  onClick={() => setTab('hosts')}
                  active={tab === 'hosts'}
                />
                <SummaryCard
                  label="Lost Hosts"
                  value={activeDelta.summary.removed_hosts}
                  valueColor="var(--text-2)"
                  bgColor="var(--bg-2)"
                  borderColor="var(--border)"
                  icon={<Server size={14} />}
                  onClick={() => setTab('hosts')}
                  active={tab === 'hosts'}
                />
                <SummaryCard
                  label="Port Changes"
                  value={activeDelta.summary.port_changes}
                  valueColor="var(--sev-medium)"
                  bgColor="oklch(0.80 0.16 70 / 0.08)"
                  borderColor="oklch(0.80 0.16 70 / 0.3)"
                  icon={<Unlock size={14} />}
                  onClick={() => setTab('ports')}
                  active={tab === 'ports'}
                />
              </div>

              {/* Tabs */}
              <div className="tabs">
                {(
                  [
                    { key: 'new' as DeltaTab, label: 'New', count: activeDelta.summary.new_findings },
                    { key: 'resolved' as DeltaTab, label: 'Resolved', count: activeDelta.summary.resolved_findings },
                    { key: 'persisting' as DeltaTab, label: 'Persisting', count: activeDelta.summary.persisting_findings },
                    { key: 'subdomains' as DeltaTab, label: 'Subdomains', count: activeDelta.summary.new_subdomains ?? 0 },
                    { key: 'hosts' as DeltaTab, label: 'Hosts', count: activeDelta.summary.new_hosts + activeDelta.summary.removed_hosts },
                    { key: 'ports' as DeltaTab, label: 'Ports', count: activeDelta.summary.port_changes },
                  ]
                ).map(t => (
                  <button
                    key={t.key}
                    className={`tab${tab === t.key ? ' active' : ''}`}
                    onClick={() => setTab(t.key)}
                  >
                    {t.label}
                    {t.count > 0 && <span className="count">{t.count}</span>}
                  </button>
                ))}
              </div>

              {/* Tab body */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
                {tab === 'new' && (
                  <FindingList
                    findings={activeDelta.new_findings}
                    label="New Findings"
                    emptyMsg="No new findings — great!"
                    badge="new"
                  />
                )}
                {tab === 'resolved' && (
                  <FindingList
                    findings={activeDelta.resolved_findings}
                    label="Resolved Findings"
                    emptyMsg="No findings resolved."
                    badge="resolved"
                  />
                )}
                {tab === 'persisting' && (
                  <FindingList
                    findings={activeDelta.persisting_findings}
                    label="Persisting Findings"
                    emptyMsg="No persisting findings."
                    badge="persisting"
                  />
                )}
                {tab === 'subdomains' && (
                  <SubdomainDelta newSubdomains={activeDelta.new_subdomains ?? []} removedSubdomains={activeDelta.removed_subdomains ?? []} />
                )}
                {tab === 'hosts' && (
                  <HostDelta newHosts={activeDelta.new_hosts} removedHosts={activeDelta.removed_hosts} />
                )}
                {tab === 'ports' && <PortChanges changes={activeDelta.port_changes} />}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

/* ── Summary card ──────────────────────────────────────────────────────────── */

function SummaryCard({
  label, value, valueColor, bgColor, borderColor, icon, onClick, active,
}: {
  label: string
  value: number
  valueColor: string
  bgColor: string
  borderColor: string
  icon: React.ReactNode
  onClick: () => void
  active: boolean
}) {
  return (
    <button
      onClick={onClick}
      style={{
        background: bgColor,
        border: `1px solid ${active ? 'var(--accent)' : borderColor}`,
        borderRadius: 'var(--radius)',
        padding: '10px 12px',
        textAlign: 'left',
        cursor: 'pointer',
        boxShadow: active ? '0 0 0 2px var(--accent-soft)' : 'none',
        transition: 'box-shadow 120ms, border-color 120ms',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 5,
          marginBottom: 4,
          color: 'var(--text-2)',
        }}
      >
        {icon}
        <span style={{ fontSize: 10.5, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
          {label}
        </span>
      </div>
      <div style={{ fontSize: 22, fontWeight: 700, color: valueColor, lineHeight: 1 }}>{value}</div>
    </button>
  )
}

/* ── Finding list ──────────────────────────────────────────────────────────── */

const BADGE_STYLES: Record<string, { color: string; bg: string; border: string }> = {
  new: {
    color: 'var(--sev-critical)',
    bg: 'oklch(0.70 0.22 352 / 0.12)',
    border: 'oklch(0.70 0.22 352 / 0.3)',
  },
  resolved: {
    color: 'var(--ok)',
    bg: 'oklch(0.75 0.15 145 / 0.12)',
    border: 'oklch(0.75 0.15 145 / 0.3)',
  },
  persisting: {
    color: 'var(--sev-high)',
    bg: 'oklch(0.68 0.21 27 / 0.12)',
    border: 'oklch(0.68 0.21 27 / 0.3)',
  },
}

function FindingList({
  findings,
  label,
  emptyMsg,
  badge,
}: {
  findings: any[]
  label: string
  emptyMsg: string
  badge: 'new' | 'resolved' | 'persisting'
}) {
  const bs = BADGE_STYLES[badge]

  if (findings.length === 0) {
    return (
      <p style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: '32px 0' }}>
        {emptyMsg}
      </p>
    )
  }

  return (
    <div>
      <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 10 }}>
        {label} ({findings.length})
      </p>
      <table className="tbl">
        <thead>
          <tr>
            {['Status', 'Severity', 'Title', 'Host', 'Port'].map(h => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              <td>
                <span
                  style={{
                    fontSize: 10,
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: 3,
                    color: bs.color,
                    background: bs.bg,
                    border: `1px solid ${bs.border}`,
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                    fontFamily: 'var(--font-mono)',
                  }}
                >
                  {badge}
                </span>
              </td>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
              <td style={{ color: 'var(--text-0)', maxWidth: 280 }}>
                <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {f.title}
                </div>
              </td>
              <td className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
                {f.host_ip || '—'}
              </td>
              <td className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
                {f.port_number ?? '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/* -- Subdomain delta --------------------------------------------------------- */

function SubdomainDelta({
  newSubdomains,
  removedSubdomains,
}: {
  newSubdomains: string[]
  removedSubdomains: string[]
}) {
  if (newSubdomains.length === 0 && removedSubdomains.length === 0) {
    return (
      <p style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: '32px 0' }}>
        No subdomain changes between scans.
      </p>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {newSubdomains.length > 0 && (
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)', marginBottom: 8 }}>
            New Subdomains ({newSubdomains.length})
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {newSubdomains.map(name => (
              <div
                key={name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  background: 'var(--accent-soft)',
                  border: '1px solid oklch(0.78 0.14 200 / 0.3)',
                  borderRadius: 'var(--radius)',
                  padding: '7px 12px',
                  fontSize: 12.5,
                }}
              >
                <Globe size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                <span className="mono" style={{ color: 'var(--accent)', fontSize: 12 }}>
                  {name}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {removedSubdomains.length > 0 && (
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>
            Removed Subdomains ({removedSubdomains.length})
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {removedSubdomains.map(name => (
              <div
                key={name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  background: 'var(--bg-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '7px 12px',
                  fontSize: 12.5,
                }}
              >
                <Globe size={14} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
                <span
                  className="mono"
                  style={{ color: 'var(--text-3)', fontSize: 12, textDecoration: 'line-through' }}
                >
                  {name}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Host delta ────────────────────────────────────────────────────────────── */

function HostDelta({
  newHosts,
  removedHosts,
}: {
  newHosts: any[]
  removedHosts: any[]
}) {
  if (newHosts.length === 0 && removedHosts.length === 0) {
    return (
      <p style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: '32px 0' }}>
        No host changes between scans.
      </p>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {newHosts.length > 0 && (
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)', marginBottom: 8 }}>
            New Hosts ({newHosts.length})
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {newHosts.map((h, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  background: 'var(--accent-soft)',
                  border: '1px solid oklch(0.78 0.14 200 / 0.3)',
                  borderRadius: 'var(--radius)',
                  padding: '7px 12px',
                  fontSize: 12.5,
                }}
              >
                <span className="mono" style={{ color: 'var(--accent)', fontSize: 12 }}>
                  {h.ip}
                </span>
                {h.hostname && (
                  <span style={{ color: 'var(--text-2)' }}>{h.hostname}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {removedHosts.length > 0 && (
        <div>
          <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 8 }}>
            Removed Hosts ({removedHosts.length})
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {removedHosts.map((h, i) => (
              <div
                key={i}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  background: 'var(--bg-2)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius)',
                  padding: '7px 12px',
                  fontSize: 12.5,
                }}
              >
                <span
                  className="mono"
                  style={{ color: 'var(--text-3)', fontSize: 12, textDecoration: 'line-through' }}
                >
                  {h.ip}
                </span>
                {h.hostname && (
                  <span style={{ color: 'var(--text-3)' }}>{h.hostname}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Port changes ──────────────────────────────────────────────────────────── */

function PortChanges({ changes }: { changes: any[] }) {
  if (changes.length === 0) {
    return (
      <p style={{ color: 'var(--text-3)', fontSize: 13, textAlign: 'center', padding: '32px 0' }}>
        No port changes between scans.
      </p>
    )
  }

  return (
    <div>
      <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-2)', marginBottom: 10 }}>
        Port Changes ({changes.length} hosts)
      </p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {changes.map((c, i) => (
          <div
            key={i}
            style={{
              background: 'var(--bg-2)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              padding: 12,
            }}
          >
            <div
              className="mono"
              style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-0)', marginBottom: 8 }}
            >
              {c.ip}
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {c.opened.map((p: any, j: number) => (
                <span
                  key={j}
                  className="mono"
                  style={{
                    fontSize: 11,
                    padding: '2px 8px',
                    borderRadius: 3,
                    color: 'var(--accent)',
                    background: 'var(--accent-soft)',
                    border: '1px solid oklch(0.78 0.14 200 / 0.3)',
                  }}
                >
                  +{p.port}/{p.protocol}
                </span>
              ))}
              {c.closed.map((p: any, j: number) => (
                <span
                  key={j}
                  className="mono"
                  style={{
                    fontSize: 11,
                    padding: '2px 8px',
                    borderRadius: 3,
                    color: 'var(--text-3)',
                    background: 'var(--bg-3)',
                    border: '1px solid var(--border)',
                    textDecoration: 'line-through',
                  }}
                >
                  {p.port}/{p.protocol}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
