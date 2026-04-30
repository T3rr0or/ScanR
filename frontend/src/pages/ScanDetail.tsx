/**
 * ScanDetail — full-page scan view
 * Tabs: Console | Findings | Hosts | Topology | Screenshots | Exclusions
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  X, RefreshCw, Terminal, AlertTriangle, Camera, Server, Network, Shield,
  ChevronLeft, GitCompare, StopCircle, CheckSquare, Square,
  ExternalLink, Copy, Link2,
} from 'lucide-react'
import { scansApi } from '@/api/scans'
import { findingsApi, type Finding } from '@/api/findings'
import api from '@/api/client'
import ScanConsole from '@/components/ScanConsole'
import ScreenshotGallery from '@/components/ScreenshotGallery'
import ScanDelta from '@/pages/ScanDelta'
import { useScanConsole } from '@/hooks/useScanConsole'
import ScanTimeline from '@/components/ScanTimeline'
import NetworkTopology from '@/components/NetworkTopology'
import HostDetail from '@/components/HostDetail'
import type { HostRead } from '@/api/hosts'
import {
  StatusPill, SevTag, Meter, relTime, fmtDuration,
} from '@/components/ui'

interface Props {
  scanId: string
  onBack: () => void
}

type Tab = 'console' | 'findings' | 'hosts' | 'topology' | 'screenshots' | 'exclusions' | 'chains'

interface ScannedPort {
  id: string; number: number; protocol: string; state: string
  service?: { name?: string; product?: string; version?: string; extra_info?: string }
}

interface ScannedHost {
  id: string; ip: string; hostname?: string; os_name?: string; status: string
  ports?: ScannedPort[]
}

export default function ScanDetail({ scanId, onBack }: Props) {
  const [tab, setTab] = useState<Tab>('console')
  const [highlightHostIp, setHighlightHostIp] = useState<string | null>(null)
  const [showDelta, setShowDelta] = useState(false)
  const qc = useQueryClient()

  function goToHost(ip: string) { setHighlightHostIp(ip); setTab('hosts') }

  const cancelMut = useMutation({
    mutationFn: () => scansApi.cancel(scanId),
    onSuccess: () => { refetch(); qc.invalidateQueries({ queryKey: ['scans'] }) },
  })

  const pauseMut = useMutation({
    mutationFn: () => api.post(`/scans/${scanId}/pause`),
    onSuccess: () => refetch(),
  })

  const resumeMut = useMutation({
    mutationFn: () => api.post(`/scans/${scanId}/resume`),
    onSuccess: () => refetch(),
  })

  const { data: scan, refetch } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => ['running', 'pending', 'paused'].includes(query.state.data?.status ?? '') ? 5000 : false,
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => findingsApi.list({ scan_id: scanId, limit: 500 }),
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
    enabled: ['completed', 'failed', 'running'].includes(scan?.status ?? ''),
  })

  const { data: hosts = [], isLoading: hostsLoading } = useQuery<ScannedHost[]>({
    queryKey: ['hosts', scanId],
    queryFn: () => scansApi.hosts(scanId),
    enabled: !!scan,
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
  })

  const { events, connected, scanStatus, phaseTimings } = useScanConsole(scan ? scanId : null)
  const isActive = ['running', 'pending'].includes(scan?.status ?? '')
  const isPending = scan?.status === 'pending'
  const chains = computeChains(findings)

  const totalFindings = (scan?.findings_critical ?? 0) + (scan?.findings_high ?? 0) + (scan?.findings_medium ?? 0) + (scan?.findings_low ?? 0) + (scan?.findings_info ?? 0)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, background: 'var(--bg-0)' }}>
      {showDelta && scan && (
        <ScanDelta scanId={scanId} scanName={scan.name} onClose={() => setShowDelta(false)} />
      )}
      {/* Header */}
      <div style={{ padding: '14px 20px 12px', borderBottom: '1px solid var(--border)', background: 'var(--bg-1)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <button className="btn btn-ghost btn-sm" onClick={onBack}>
            <ChevronLeft size={13} /> Back
          </button>
          <span className="mono dim" style={{ fontSize: 11 }}>{scanId.slice(0, 8)}</span>
          <div style={{ flex: 1 }} />
          {scan?.status === 'paused' && (
            <button className="btn btn-primary btn-sm" onClick={() => resumeMut.mutate()} disabled={resumeMut.isPending}>
              ▶ {resumeMut.isPending ? 'Resuming…' : 'Resume'}
            </button>
          )}
          {scan?.status === 'running' && (
            <button className="btn btn-sm" onClick={() => pauseMut.mutate()} disabled={pauseMut.isPending}>
              ⏸ {pauseMut.isPending ? 'Pausing…' : 'Pause'}
            </button>
          )}
          {isActive && (
            <button className="btn btn-danger btn-sm" onClick={() => cancelMut.mutate()} disabled={cancelMut.isPending}>
              <StopCircle size={11} /> {cancelMut.isPending ? 'Cancelling…' : 'Cancel'}
            </button>
          )}
          {!isActive && scan?.status === 'completed' && (
            <button className="btn btn-sm" onClick={() => setShowDelta(true)}><GitCompare size={12} /> Compare</button>
          )}
          <button className="btn btn-sm" onClick={() => refetch()}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>{scan?.name ?? '…'}</h1>
              {scan && <StatusPill status={scan.status} />}
            </div>
            <div className="mono dim" style={{ fontSize: 11.5 }}>
              profile: {scan?.profile}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 20, flexShrink: 0 }}>
            <DStat label="Hosts up" value={`${scan?.hosts_up ?? 0}/${scan?.hosts_total ?? 0}`} />
            <DStat label="Findings" value={totalFindings} />
            <DStat label="Duration" value={fmtDuration((scan as any)?.duration_s)} />
            <DStat label="Started" value={relTime(scan?.started_at)} />
          </div>
        </div>
        {scan?.status === 'running' && (
          <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Meter value={(scan as any)?.progress ?? 0.5} color="var(--accent-2)" />
          </div>
        )}
        {scan?.status === 'failed' && (scan as any)?.error_message && (
          <div style={{
            marginTop: 10,
            padding: '8px 12px',
            borderRadius: 6,
            background: 'oklch(0.25 0.05 20 / 0.4)',
            border: '1px solid oklch(0.5 0.15 20 / 0.4)',
            fontSize: 12,
            color: 'var(--sev-high)',
            fontFamily: 'var(--font-mono)',
          }}>
            {(scan as any).error_message}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="tabs">
        <TabBtn active={tab === 'console'} onClick={() => setTab('console')} icon={<Terminal size={12}/>} label="Console" count={events.length || undefined} liveColor={isActive ? 'var(--accent-2)' : undefined} />
        <TabBtn active={tab === 'findings'} onClick={() => setTab('findings')} icon={<AlertTriangle size={12}/>} label="Findings" count={totalFindings || undefined} />
        <TabBtn active={tab === 'hosts'} onClick={() => setTab('hosts')} icon={<Server size={12}/>} label="Hosts" count={hosts.length || undefined} />
        <TabBtn active={tab === 'topology'} onClick={() => setTab('topology')} icon={<Network size={12}/>} label="Topology" />
        <TabBtn active={tab === 'screenshots'} onClick={() => setTab('screenshots')} icon={<Camera size={12}/>} label="Screenshots" />
        {isPending && <TabBtn active={tab === 'exclusions'} onClick={() => setTab('exclusions')} icon={<Shield size={12}/>} label="Exclusions" />}
        {chains.length > 0 && <TabBtn active={tab === 'chains'} onClick={() => setTab('chains')} icon={<Link2 size={12}/>} label="Chains" count={chains.length} />}
      </div>

      {/* Content */}
      <div style={{ flex: 1, minHeight: 0, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        {tab === 'console' && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <ScanTimeline timings={phaseTimings} isRunning={isActive} />
            <div className="page-pad" style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
              <ScanConsole events={events} connected={connected} scanStatus={scanStatus} />
            </div>
          </div>
        )}
        {tab === 'findings' && (
          <FindingsTab findings={findings} scanId={scanId} onGoToHost={goToHost} />
        )}
        {tab === 'hosts' && (
          <HostsTab hosts={hosts} loading={hostsLoading} highlightIp={highlightHostIp} findings={findings} scanId={scanId} />
        )}
        {tab === 'topology' && (
          <div className="page-pad" style={{ flex: 1, minHeight: 0 }}>
            {hostsLoading
              ? <div style={{ textAlign: 'center', color: 'var(--text-3)', padding: 40 }}>Loading…</div>
              : <NetworkTopology
                  hosts={hosts}
                  findingsByHost={Object.fromEntries(hosts.map(h => [h.ip, findings.filter(f => f.host_ip === h.ip)]))}
                />
            }
          </div>
        )}
        {tab === 'screenshots' && <ScreenshotGallery scanId={scanId} />}
        {tab === 'exclusions' && <ExclusionsPanel scanId={scanId} />}
        {tab === 'chains' && <ChainsPanel chains={chains} />}
      </div>
    </div>
  )
}

function TabBtn({ active, onClick, icon, label, count, liveColor }: {
  active: boolean; onClick: () => void; icon: React.ReactNode
  label: string; count?: number; liveColor?: string
}) {
  return (
    <button className={`tab ${active ? 'active' : ''}`} onClick={onClick}>
      {liveColor
        ? <span className="live-dot" style={{ width: 5, height: 5, boxShadow: 'none', background: liveColor }} />
        : icon
      }
      {label}
      {count != null && <span className="count">{count}</span>}
    </button>
  )
}

function DStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{ textAlign: 'right' }}>
      <div className="panel-title" style={{ fontSize: 9.5 }}>{label}</div>
      <div className="mono" style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-0)', marginTop: 2 }}>{value ?? '—'}</div>
    </div>
  )
}

/* ── Findings tab ──────────────────────────────────────────── */
function FindingsTab({ findings, scanId, onGoToHost }: { findings: Finding[]; scanId: string; onGoToHost: (ip: string) => void }) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null)
  const [sevFilter, setSevFilter] = useState<string>('all')
  const [triageFilter, setTriageFilter] = useState<'all' | 'open' | 'false_positive' | 'accepted_risk'>('all')

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof findingsApi.update>[1] }) => findingsApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', scanId] }),
  })

  const bulkMut = useMutation({
    mutationFn: (data: { false_positive?: boolean; remediation_status?: string }) => findingsApi.bulkUpdate([...selected], data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings', scanId] }); setSelected(new Set()) },
  })

  const toggle = (id: string) => setSelected(prev => {
    const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next
  })

  const filtered = findings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (triageFilter === 'open') return !f.false_positive && f.remediation_status === 'open'
    if (triageFilter === 'false_positive') return f.false_positive
    if (triageFilter === 'accepted_risk') return f.remediation_status === 'accepted_risk'
    return true
  })

  const sevCounts: Record<string, number> = { all: findings.length }
  findings.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1 })

  if (findings.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 12.5 }}>
        No findings recorded
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', height: '100%', minHeight: 0 }}>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Filters */}
        <div style={{ display: 'flex', gap: 6, padding: '10px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0, flexWrap: 'wrap', alignItems: 'center', background: 'var(--bg-1)' }}>
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => {
            const n = sevCounts[s] ?? 0
            return (
              <button key={s} onClick={() => setSevFilter(s)} style={{
                padding: '4px 10px', borderRadius: 6, fontSize: 11, textTransform: 'capitalize', cursor: 'pointer',
                background: sevFilter === s ? 'var(--bg-3)' : 'transparent',
                color: sevFilter === s ? 'var(--text-0)' : 'var(--text-2)',
                border: '1px solid ' + (sevFilter === s ? 'var(--border-strong)' : 'transparent'),
                display: 'inline-flex', alignItems: 'center', gap: 5,
              }}>
                {s !== 'all' && <span className="sev-bar" style={{ background: `var(--sev-${s})`, height: 10 }} />}
                {s} <span className="mono dim" style={{ marginLeft: 2 }}>{n}</span>
              </button>
            )
          })}
          <div style={{ flex: 1 }} />
          <div style={{ display: 'flex', gap: 4 }}>
            {(['all', 'open', 'false_positive', 'accepted_risk'] as const).map(f => (
              <button key={f} onClick={() => setTriageFilter(f)} style={{
                padding: '4px 8px', borderRadius: 4, fontSize: 10.5, cursor: 'pointer',
                background: triageFilter === f ? 'var(--bg-3)' : 'transparent',
                color: triageFilter === f ? 'var(--text-0)' : 'var(--text-2)',
                border: '1px solid ' + (triageFilter === f ? 'var(--border-strong)' : 'transparent'),
              }}>
                {f === 'false_positive' ? 'False Positive' : f === 'accepted_risk' ? 'Accepted Risk' : f === 'open' ? 'Open' : 'All'}
              </button>
            ))}
          </div>
          {selected.size > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: 8, borderLeft: '1px solid var(--border)' }}>
              <span className="dim" style={{ fontSize: 11 }}>{selected.size} selected</span>
              <button className="btn btn-sm" onClick={() => bulkMut.mutate({ false_positive: true })}>Mark FP</button>
              <button className="btn btn-sm" onClick={() => bulkMut.mutate({ remediation_status: 'accepted_risk' })}>Accept Risk</button>
              <button className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}><X size={11}/></button>
            </div>
          )}
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 4 }}></th>
                <th style={{ width: 28 }}></th>
                <th>Severity</th>
                <th>Title</th>
                <th>Host</th>
                <th>Port</th>
                <th>Plugin</th>
                <th>CVSS</th>
                <th>CVE</th>
                <th>Age</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr
                  key={f.id}
                  className={detailFinding?.id === f.id ? 'selected' : ''}
                  style={{ opacity: f.false_positive ? 0.45 : 1 }}
                  onClick={() => setDetailFinding(f)}
                >
                  <td style={{ padding: 0 }}>
                    <span className={`sev-bar ${f.severity}`} style={{ height: 34, width: 3, display: 'block' }} />
                  </td>
                  <td onClick={e => e.stopPropagation()} style={{ textAlign: 'center' }}>
                    <button onClick={() => toggle(f.id)} style={{ color: 'var(--text-3)', cursor: 'pointer', background: 'none', border: 'none' }}>
                      {selected.has(f.id) ? <CheckSquare size={13} style={{ color: 'var(--accent)' }} /> : <Square size={13} />}
                    </button>
                  </td>
                  <td><SevTag severity={f.severity} /></td>
                  <td style={{ fontWeight: 500, maxWidth: 340, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {f.title}
                    {f.false_positive && <span className="mono" style={{ fontSize: 9, color: 'var(--sev-medium)', marginLeft: 6 }}>FP</span>}
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    {f.host_ip
                      ? <button onClick={() => onGoToHost(f.host_ip!)} className="mono" style={{ color: 'var(--accent)', fontSize: 11.5, background: 'none', border: 'none', cursor: 'pointer' }}>{f.host_ip}</button>
                      : <span className="dimmer">—</span>
                    }
                  </td>
                  <td className="mono dim">{f.port_number ? `${f.port_number}/${f.protocol ?? 'tcp'}` : '—'}</td>
                  <td className="mono dim" style={{ fontSize: 11 }}>{f.plugin_id}</td>
                  <td className="mono" style={{
                    fontWeight: 600,
                    color: f.cvss_score != null && f.cvss_score >= 9 ? 'var(--sev-critical)' : f.cvss_score != null && f.cvss_score >= 7 ? 'var(--sev-high)' : 'var(--text-1)',
                  }}>
                    {f.cvss_score?.toFixed(1) ?? '—'}
                  </td>
                  <td>
                    {(() => {
                      const ids = f.cve_ids ? (() => { try { return JSON.parse(f.cve_ids!) } catch { return [] } })() : []
                      return ids.length > 0
                        ? <span className="mono" style={{ fontSize: 10, padding: '1px 5px', borderRadius: 3, background: 'oklch(0.68 0.21 27 / 0.12)', color: 'var(--sev-high)', border: '1px solid oklch(0.68 0.21 27 / 0.25)', whiteSpace: 'nowrap' }}>{ids[0]}</span>
                        : <span className="dimmer">—</span>
                    })()}
                  </td>
                  <td className="mono dim" style={{ fontSize: 11 }}>{relTime(f.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail drawer */}
      {detailFinding && (
        <FindingDrawer
          finding={detailFinding}
          onClose={() => setDetailFinding(null)}
          onUpdate={(data) => updateMut.mutate({ id: detailFinding.id, data })}
        />
      )}
    </div>
  )
}

function FindingDrawer({ finding, onClose, onUpdate }: { finding: Finding; onClose: () => void; onUpdate: (d: Parameters<typeof findingsApi.update>[1]) => void }) {
  function safeParse(s?: string | null): string[] {
    if (!s) return []; try { return JSON.parse(s) } catch { return [] }
  }
  const cves = safeParse((finding as any).cve_ids)
  const mitre = safeParse((finding as any).mitre_tags)
  const comp = safeParse((finding as any).compliance_tags)
  const refs = safeParse((finding as any).references)

  return (
    <div style={{ width: 420, flexShrink: 0, background: 'var(--bg-1)', borderLeft: '1px solid var(--border)', overflow: 'auto', minHeight: 0 }}>
      {/* Sticky header */}
      <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', position: 'sticky', top: 0, background: 'var(--bg-1)', zIndex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <SevTag severity={finding.severity} />
          <span className="mono dim" style={{ fontSize: 10.5 }}>{finding.id.slice(0, 8)}</span>
          <div style={{ flex: 1 }} />
          <button className="btn btn-ghost btn-icon" onClick={onClose}><X size={14} /></button>
        </div>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 600, lineHeight: 1.35 }}>{finding.title}</h2>
        <div style={{ display: 'flex', gap: 16, marginTop: 10 }}>
          {finding.cvss_score != null && (
            <div>
              <div className="panel-title" style={{ fontSize: 9.5 }}>CVSS</div>
              <div className="mono" style={{
                fontSize: 15, fontWeight: 700, marginTop: 2,
                color: finding.cvss_score >= 9 ? 'var(--sev-critical)' : finding.cvss_score >= 7 ? 'var(--sev-high)' : finding.cvss_score >= 4 ? 'var(--sev-medium)' : 'var(--sev-low)',
              }}>
                {finding.cvss_score.toFixed(1)}
              </div>
            </div>
          )}
          <MiniField label="Host" value={finding.host_ip ?? '—'} mono accent />
          <MiniField label="Port" value={finding.port_number ? `${finding.port_number}/${finding.protocol ?? 'tcp'}` : '—'} mono />
          <MiniField label="Plugin" value={finding.plugin_id} mono small />
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 16 }}>
        <DrawerSection title="Description">
          <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-1)', lineHeight: 1.55 }}>{finding.description}</p>
        </DrawerSection>

        {finding.evidence && (
          <DrawerSection title="Evidence">
            <EvidenceBlock evidence={finding.evidence} />
          </DrawerSection>
        )}

        {finding.remediation && (
          <DrawerSection title="Remediation">
            <div style={{
              padding: 10, fontSize: 12, lineHeight: 1.5, color: 'var(--text-1)',
              background: 'oklch(0.75 0.15 145 / 0.08)',
              border: '1px solid oklch(0.75 0.15 145 / 0.25)',
              borderLeft: '3px solid var(--ok)', borderRadius: 4,
            }}>
              {finding.remediation}
            </div>
          </DrawerSection>
        )}

        {cves.length > 0 && (
          <DrawerSection title="CVE IDs">
            <TagRow items={cves} color="var(--sev-high)" />
          </DrawerSection>
        )}

        {mitre.length > 0 && (
          <DrawerSection title="MITRE ATT&CK">
            <TagRow items={mitre} color="var(--accent-2)" />
          </DrawerSection>
        )}

        {comp.length > 0 && (
          <DrawerSection title="Compliance">
            <TagRow items={comp} color="var(--accent)" />
          </DrawerSection>
        )}

        {refs.length > 0 && (
          <DrawerSection title="References">
            {refs.map((u: string) => (
              <a key={u} href={u} target="_blank" rel="noreferrer" style={{
                display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5,
                color: 'var(--accent)', padding: '4px 0', textDecoration: 'none',
              }}>
                <ExternalLink size={11} /> {u}
              </a>
            ))}
          </DrawerSection>
        )}

        <div style={{ display: 'flex', gap: 6, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
          <button
            className="btn btn-sm"
            onClick={() => onUpdate({ false_positive: !finding.false_positive })}
          >
            {finding.false_positive ? 'Unmark FP' : 'Mark False Positive'}
          </button>
          <button
            className="btn btn-sm"
            onClick={() => onUpdate({ remediation_status: finding.remediation_status === 'accepted_risk' ? 'open' : 'accepted_risk' })}
          >
            {finding.remediation_status === 'accepted_risk' ? 'Reopen' : 'Accept Risk'}
          </button>
          <button className="btn btn-ghost btn-icon btn-sm" style={{ marginLeft: 'auto' }} title="Copy ID"
            onClick={() => navigator.clipboard.writeText(finding.id)}>
            <Copy size={11} />
          </button>
        </div>
      </div>
    </div>
  )
}

function EvidenceBlock({ evidence }: { evidence: string }) {
  const hasHttp = evidence.includes('=== REQUEST ===')
  const copy = () => navigator.clipboard.writeText(evidence)
  const preStyle: React.CSSProperties = {
    margin: 0, fontSize: 10.5, background: 'oklch(0.12 0.008 255)', color: 'var(--text-1)',
    padding: 10, borderRadius: 6, border: '1px solid var(--border)',
    whiteSpace: 'pre-wrap', overflow: 'auto', maxHeight: 220, fontFamily: 'var(--font-mono)',
  }
  if (hasHttp) {
    const [reqPart, resPart] = evidence.split('\n\n=== RESPONSE ===\n')
    const reqText = reqPart.replace('=== REQUEST ===\n', '')
    return (
      <div>
        <div style={{ display: 'flex', gap: 6, marginBottom: 4, alignItems: 'center' }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Request</span>
          <span style={{ fontSize: 10, color: 'var(--text-3)' }}>→</span>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--ok)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Response</span>
          <button onClick={copy} className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto', fontSize: 10 }}>Copy</button>
        </div>
        <pre style={preStyle}>{reqText}</pre>
        {resPart && <pre style={{ ...preStyle, marginTop: 6 }}>{resPart}</pre>}
      </div>
    )
  }
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 4 }}>
        <button onClick={copy} className="btn btn-ghost btn-sm" style={{ fontSize: 10 }}>Copy</button>
      </div>
      <pre style={preStyle}>{evidence}</pre>
    </div>
  )
}

function DrawerSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="panel-title" style={{ fontSize: 10, marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  )
}

function TagRow({ items, color }: { items: string[]; color: string }) {
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
      {items.map(i => (
        <span key={i} className="mono" style={{
          fontSize: 10.5, padding: '2px 7px', borderRadius: 3,
          background: `color-mix(in oklch, ${color} 14%, transparent)`,
          color, border: `1px solid color-mix(in oklch, ${color} 30%, transparent)`,
        }}>{i}</span>
      ))}
    </div>
  )
}

function MiniField({ label, value, mono, accent, small }: { label: string; value: string; mono?: boolean; accent?: boolean; small?: boolean }) {
  return (
    <div>
      <div className="panel-title" style={{ fontSize: 9.5 }}>{label}</div>
      <div className={mono ? 'mono' : ''} style={{ fontSize: small ? 11 : 12, color: accent ? 'var(--accent)' : 'var(--text-0)', marginTop: 2 }}>{value}</div>
    </div>
  )
}

/* ── Hosts tab ─────────────────────────────────────────────── */
function HostsTab({ hosts, loading, highlightIp, findings, scanId }: {
  hosts: ScannedHost[]
  loading: boolean
  highlightIp: string | null
  findings: Finding[]
  scanId: string
}) {
  const [selectedHost, setSelectedHost] = useState<HostRead | null>(null)

  if (loading) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 12 }}>
        Loading hosts…
      </div>
    )
  }

  const findingsPerHost = Object.fromEntries(
    hosts.map(h => [h.ip, findings.filter(f => f.host_ip === h.ip)])
  )

  // Convert ScannedHost to HostRead shape for HostDetail
  function toHostRead(h: ScannedHost): HostRead {
    return {
      id: h.id,
      ip: h.ip,
      hostname: h.hostname,
      os_name: h.os_name,
      status: h.status,
      ports: (h.ports ?? []).map(p => ({
        number: p.number,
        protocol: p.protocol,
        state: p.state,
        service: p.service?.name,
        version: [p.service?.product, p.service?.version].filter(Boolean).join(' ') || undefined,
      })),
    }
  }

  return (
    <>
      <div style={{ padding: 20 }}>
        <div className="panel" style={{ overflow: 'hidden' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 4 }}></th>
                <th>Host</th>
                <th>Hostname</th>
                <th>OS</th>
                <th>Open Ports</th>
                <th>Findings</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map(h => {
                const hf = findingsPerHost[h.ip] ?? []
                const maxSev = hf[0]?.severity ?? 'info'
                const openPorts = (h.ports ?? []).filter(p => p.state === 'open')
                const isHighlighted = h.ip === highlightIp
                return (
                  <tr
                    key={h.ip}
                    style={{ background: isHighlighted ? 'var(--accent-soft)' : undefined }}
                    onClick={() => setSelectedHost(toHostRead(h))}
                  >
                    <td style={{ padding: 0 }}>
                      <span className={`sev-bar ${maxSev}`} style={{ height: 26, width: 3, display: 'block' }} />
                    </td>
                    <td className="mono" style={{ color: 'var(--accent)', fontSize: 12 }}>{h.ip}</td>
                    <td style={{ fontSize: 12.5 }}>{h.hostname ?? <span className="dimmer">—</span>}</td>
                    <td className="dim" style={{ fontSize: 11.5 }}>{h.os_name ?? '—'}</td>
                    <td className="mono" style={{ fontSize: 11, color: 'var(--text-1)' }}>
                      {openPorts.slice(0, 6).map(p => (
                        <span key={p.number} style={{ marginRight: 6 }}>
                          {p.number}<span className="dim">/tcp</span>
                        </span>
                      ))}
                      {openPorts.length > 6 && <span className="dim">+{openPorts.length - 6}</span>}
                      {openPorts.length === 0 && <span className="dimmer">—</span>}
                    </td>
                    <td className="mono" style={{ fontSize: 12, fontWeight: 600, color: hf.length > 0 ? `var(--sev-${maxSev})` : 'var(--text-3)' }}>
                      {hf.length}
                    </td>
                    <td>{hf.length > 0 ? <SevTag severity={maxSev} /> : <span className="dimmer">—</span>}</td>
                  </tr>
                )
              })}
              {hosts.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                    No hosts discovered
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* HostDetail slide-over */}
      {selectedHost && (
        <HostDetail
          host={selectedHost}
          scanId={scanId}
          onClose={() => setSelectedHost(null)}
        />
      )}
    </>
  )
}

/* ── Exclusions panel ──────────────────────────────────────── */
/* ── Attack Chain computation ──────────────────── */
interface AttackChain {
  id: string
  title: string
  severity: 'critical' | 'high'
  steps: Finding[]
  description: string
  details: string
}

function computeChains(findings: Finding[]): AttackChain[] {
  const chains: AttackChain[] = []

  // Chain 1: SQLi + exposed DB service on same host
  const sqliF = findings.filter(f => f.plugin_id.includes('sqli'))
  const dbF = findings.filter(f => ['services.mysql_unauth', 'services.postgres_unauth', 'services.mssql_unauth'].includes(f.plugin_id))
  for (const sq of sqliF) {
    const db = dbF.find(d => d.host_ip === sq.host_ip)
    if (db) chains.push({
      id: `sqli-db-${sq.id}`,
      title: 'SQL Injection → Database Access',
      severity: 'critical',
      steps: [sq, db],
      description: 'SQLi on the web tier plus an exposed database service on the same host enables full DB exfiltration via load_file() or direct connection.',
      details: `SQLi: ${sq.title}\nDB: ${db.title}\nHost: ${sq.host_ip ?? '?'}`,
    })
  }

  // Chain 2: Unsigned SMB + Anonymous LDAP = NTLM Relay
  const smbUnsigned = findings.filter(f => f.plugin_id === 'services.smb_signing')
  const ldapAnon = findings.filter(f => f.plugin_id === 'services.ldap_anon_bind')
  if (smbUnsigned.length > 0 && ldapAnon.length > 0) {
    chains.push({
      id: 'ntlm-relay',
      title: 'NTLM Relay: Unsigned SMB + Anonymous LDAP',
      severity: 'critical',
      steps: [...smbUnsigned.slice(0, 1), ...ldapAnon.slice(0, 1)],
      description: 'Unsigned SMB allows credential capture via Responder. Unauthenticated LDAP allows relaying that credential to perform privileged AD operations (add machine, modify ACL, DCSync prep).',
      details: `${smbUnsigned.length} unsigned SMB host(s), ${ldapAnon.length} anonymous LDAP host(s)`,
    })
  }

  // Chain 3: Path traversal with SSH evidence
  const traversal = findings.filter(f => f.plugin_id === 'web.path_traversal' && (f.evidence ?? '').includes('.ssh'))
  for (const t of traversal) {
    chains.push({
      id: `path-ssh-${t.id}`,
      title: 'Path Traversal → SSH Key Exposure → Lateral Movement',
      severity: 'critical',
      steps: [t],
      description: 'Path traversal exposes .ssh/id_rsa private keys. These can be used to authenticate via SSH to other hosts without knowing passwords.',
      details: `Host: ${t.host_ip ?? '?'}\n${t.title}`,
    })
  }

  // Chain 4: SSRF to cloud metadata
  const ssrf = findings.filter(f => ['web.aws_metadata_ssrf', 'web.ssrf_detect'].includes(f.plugin_id))
  const metaDirect = findings.filter(f => f.title?.includes('Metadata Service'))
  if (ssrf.length > 0 && metaDirect.length > 0) {
    chains.push({
      id: 'ssrf-meta',
      title: 'SSRF → Cloud Metadata → IAM Credential Theft',
      severity: 'critical',
      steps: [...ssrf.slice(0, 1), ...metaDirect.slice(0, 1)],
      description: 'SSRF vulnerability can reach the cloud metadata service (accessible from within the VPC) to steal IAM/managed identity tokens.',
      details: `SSRF on ${ssrf[0].host_ip ?? '?'} + direct metadata access from scanner`,
    })
  }

  // Chain 5: Default web creds + admin access
  const defaultCreds = findings.filter(f => f.plugin_id === 'web.default_creds_web')
  const adminPaths = findings.filter(f => f.plugin_id === 'web.broken_access_control' || (f.plugin_id === 'web.dir_bruteforce' && f.title?.toLowerCase().includes('admin')))
  for (const dc of defaultCreds) {
    const admin = adminPaths.find(a => a.host_ip === dc.host_ip)
    if (admin) chains.push({
      id: `creds-admin-${dc.id}`,
      title: 'Default Credentials → Admin Interface Access',
      severity: 'critical',
      steps: [dc, admin],
      description: 'Default credentials work AND an admin/management interface was found on the same host. Full administrative compromise is straightforward.',
      details: `Host: ${dc.host_ip ?? '?'}`,
    })
  }

  return chains
}

function ChainsPanel({ chains }: { chains: AttackChain[] }) {
  const sevColor = (s: string) => s === 'critical' ? 'var(--sev-critical)' : 'var(--sev-high)'

  if (chains.length === 0) return (
    <div className="page-pad" style={{ color: 'var(--text-3)', fontSize: 13 }}>No attack chains detected in this scan.</div>
  )

  return (
    <div className="page-pad" style={{ maxWidth: 800, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Link2 size={16} style={{ color: 'var(--accent)' }} />
        <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: 'var(--text-0)' }}>Attack Chains</h2>
        <span className="dimmer" style={{ fontSize: 11 }}>{chains.length} detected</span>
      </div>
      <p style={{ margin: 0, fontSize: 12, color: 'var(--text-2)', lineHeight: 1.5 }}>
        These chains correlate multiple findings that together enable a more serious attack than any single finding alone.
      </p>
      {chains.map(c => (
        <div key={c.id} className="panel" style={{ borderLeft: `3px solid ${sevColor(c.severity)}` }}>
          <div className="panel-head" style={{ gap: 10 }}>
            <span className={`sev-tag ${c.severity}`}>{c.severity}</span>
            <span style={{ fontWeight: 600, color: 'var(--text-0)', fontSize: 13 }}>{c.title}</span>
          </div>
          <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-1)', lineHeight: 1.55 }}>{c.description}</p>
            <div>
              <div className="panel-title" style={{ marginBottom: 6 }}>Chain steps</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {c.steps.map((f, i) => (
                  <div key={f.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                    <span style={{ width: 18, height: 18, borderRadius: '50%', background: sevColor(c.severity), color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, flexShrink: 0 }}>{i + 1}</span>
                    <span className={`sev-bar ${f.severity}`} />
                    <span style={{ color: 'var(--text-0)' }}>{f.title}</span>
                    {f.host_ip && <span className="mono dimmer" style={{ fontSize: 10 }}>{f.host_ip}</span>}
                  </div>
                ))}
              </div>
            </div>
            {c.details && (
              <pre className="mono" style={{ margin: 0, fontSize: 10, color: 'var(--text-2)', background: 'var(--bg-0)', padding: '6px 10px', borderRadius: 4, border: '1px solid var(--border)', whiteSpace: 'pre-wrap' }}>
                {c.details}
              </pre>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

/* ── Exclusions panel ──────────────────────────────────────── */
function ExclusionsPanel({ scanId }: { scanId: string }) {
  const qc = useQueryClient()
  const { data: exclusions = [] } = useQuery({
    queryKey: ['exclusions', scanId],
    queryFn: () => api.get(`/scans/${scanId}/exclusions`).then(r => r.data),
  })
  const [type, setType] = useState('ip')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')

  const addMut = useMutation({
    mutationFn: () => api.post(`/scans/${scanId}/exclusions`, { type, value, reason: reason || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['exclusions', scanId] }); setValue(''); setReason('') },
  })
  const delMut = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${scanId}/exclusions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exclusions', scanId] }),
  })

  interface Exclusion { id: string; type: string; value: string; reason?: string; created_at: string }

  return (
    <div style={{ padding: 20, maxWidth: 640 }}>
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Exclusions</span>
          <span className="dim" style={{ fontSize: 11, marginLeft: 'auto' }}>
            Applied at scan time — IPs, CIDRs, ports, or hostnames to skip
          </span>
        </div>
        <div style={{ padding: 14, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', borderBottom: '1px solid var(--border)' }}>
          <div>
            <label className="label">Type</label>
            <select className="select-field" style={{ width: 100 }} value={type} onChange={e => setType(e.target.value)}>
              {['ip', 'cidr', 'port', 'host'].map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label className="label">Value</label>
            <input
              className="input mono"
              value={value}
              onChange={e => setValue(e.target.value)}
              placeholder={type === 'ip' ? '192.168.1.5' : type === 'cidr' ? '10.0.0.0/8' : type === 'port' ? '22' : 'hostname'}
              onKeyDown={e => { if (e.key === 'Enter' && value) addMut.mutate() }}
            />
          </div>
          <div style={{ flex: 2, minWidth: 160 }}>
            <label className="label">Reason (optional)</label>
            <input
              className="input"
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Why this exclusion?"
            />
          </div>
          <button
            className="btn btn-primary"
            disabled={!value || addMut.isPending}
            onClick={() => addMut.mutate()}
            style={{ marginTop: 20 }}
          >
            Add
          </button>
        </div>
        <table className="tbl">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Reason</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(exclusions as Exclusion[]).map(e => (
              <tr key={e.id} style={{ cursor: 'default' }}>
                <td><span className="pill" style={{ fontSize: 10 }}>{e.type}</span></td>
                <td className="mono">{e.value}</td>
                <td className="dim" style={{ fontSize: 11.5 }}>{e.reason ?? <span className="dimmer">—</span>}</td>
                <td>
                  <button className="btn btn-ghost btn-icon btn-sm" onClick={() => delMut.mutate(e.id)}>
                    <X size={12} />
                  </button>
                </td>
              </tr>
            ))}
            {exclusions.length === 0 && (
              <tr>
                <td colSpan={4} style={{ padding: '24px 20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  No exclusions — all targets will be scanned
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
