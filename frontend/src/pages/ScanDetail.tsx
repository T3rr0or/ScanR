/**
 * ScanDetail — full-page scan view
 * Tabs: Console | Findings | Hosts | Topology | Screenshots | Exclusions
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  X, RefreshCw, Terminal, AlertTriangle, Camera, Server, Network, Shield,
  ChevronLeft, GitCompare, StopCircle, CheckSquare, Square,
  ExternalLink, Copy,
} from 'lucide-react'
import { scansApi } from '@/api/scans'
import { findingsApi, type Finding } from '@/api/findings'
import api from '@/api/client'
import ScanConsole from '@/components/ScanConsole'
import ScreenshotGallery from '@/components/ScreenshotGallery'
import ScanDelta from '@/pages/ScanDelta'
import { useScanConsole } from '@/hooks/useScanConsole'
import NetworkTopology from '@/components/NetworkTopology'
import {
  StatusPill, SevTag, Meter, relTime, fmtDuration,
} from '@/components/ui'

interface Props {
  scanId: string
  onBack: () => void
}

type Tab = 'console' | 'findings' | 'hosts' | 'topology' | 'screenshots' | 'exclusions'

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

  const { data: scan, refetch } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => query.state.data?.status === 'running' ? 3000 : false,
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => findingsApi.list({ scan_id: scanId }),
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
    enabled: ['completed', 'failed', 'running'].includes(scan?.status ?? ''),
  })

  const { data: hosts = [], isLoading: hostsLoading } = useQuery<ScannedHost[]>({
    queryKey: ['hosts', scanId],
    queryFn: () => scansApi.hosts(scanId),
    enabled: !!scan,
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
  })

  const { events, connected, scanStatus } = useScanConsole(scan ? scanId : null)
  const isActive = ['running', 'pending'].includes(scan?.status ?? '')
  const isPending = scan?.status === 'pending'

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
      </div>

      {/* Tabs */}
      <div className="tabs">
        <TabBtn active={tab === 'console'} onClick={() => setTab('console')} icon={<Terminal size={12}/>} label="Console" count={events.length || undefined} liveColor={isActive ? 'var(--accent-2)' : undefined} />
        <TabBtn active={tab === 'findings'} onClick={() => setTab('findings')} icon={<AlertTriangle size={12}/>} label="Findings" count={findings.length || undefined} />
        <TabBtn active={tab === 'hosts'} onClick={() => setTab('hosts')} icon={<Server size={12}/>} label="Hosts" count={hosts.length || undefined} />
        <TabBtn active={tab === 'topology'} onClick={() => setTab('topology')} icon={<Network size={12}/>} label="Topology" />
        <TabBtn active={tab === 'screenshots'} onClick={() => setTab('screenshots')} icon={<Camera size={12}/>} label="Screenshots" />
        {isPending && <TabBtn active={tab === 'exclusions'} onClick={() => setTab('exclusions')} icon={<Shield size={12}/>} label="Exclusions" />}
      </div>

      {/* Content */}
      <div style={{ flex: 1, minHeight: 0, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        {tab === 'console' && (
          <div style={{ flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 12, minHeight: 0 }}>
            <ScanConsole events={events} connected={connected} scanStatus={scanStatus} />
          </div>
        )}
        {tab === 'findings' && (
          <FindingsTab findings={findings} scanId={scanId} onGoToHost={goToHost} />
        )}
        {tab === 'hosts' && (
          <HostsTab hosts={hosts} loading={hostsLoading} highlightIp={highlightHostIp} findings={findings} />
        )}
        {tab === 'topology' && (
          <div style={{ flex: 1, padding: 20, minHeight: 0 }}>
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
    mutationFn: ({ id, data }: { id: string; data: any }) => findingsApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', scanId] }),
  })

  const bulkMut = useMutation({
    mutationFn: (data: any) => findingsApi.bulkUpdate([...selected], data),
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

function FindingDrawer({ finding, onClose, onUpdate }: { finding: Finding; onClose: () => void; onUpdate: (d: any) => void }) {
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
            <pre className="mono" style={{
              margin: 0, fontSize: 11, background: 'oklch(0.12 0.008 255)', color: 'var(--text-1)',
              padding: 10, borderRadius: 6, border: '1px solid var(--border)',
              whiteSpace: 'pre-wrap', overflow: 'auto', maxHeight: 200,
            }}>{finding.evidence}</pre>
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
function HostsTab({ hosts, loading, highlightIp, findings }: {
  hosts: ScannedHost[]; loading: boolean; highlightIp: string | null; findings: Finding[]
}) {
  if (loading) {
    return <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 12 }}>Loading hosts…</div>
  }
  const findingsPerHost = Object.fromEntries(
    hosts.map(h => [h.ip, findings.filter(f => f.host_ip === h.ip)])
  )
  return (
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
                <tr key={h.ip} style={{ background: isHighlighted ? 'var(--accent-soft)' : undefined }}>
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
              <tr><td colSpan={7} style={{ padding: '40px 20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>No hosts discovered</td></tr>
            )}
          </tbody>
        </table>
      </div>
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

  const addMut = useMutation({
    mutationFn: () => api.post(`/scans/${scanId}/exclusions`, { type, value }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['exclusions', scanId] }); setValue('') },
  })
  const delMut = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${scanId}/exclusions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exclusions', scanId] }),
  })

  return (
    <div style={{ padding: 20, maxWidth: 600 }}>
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Exclusions</span>
        </div>
        <div style={{ padding: 14, display: 'flex', gap: 8 }}>
          <select className="select-field" style={{ width: 100 }} value={type} onChange={e => setType(e.target.value)}>
            {['ip', 'cidr', 'port', 'host'].map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <input className="input" style={{ flex: 1 }} value={value} onChange={e => setValue(e.target.value)}
            placeholder={type === 'ip' ? '192.168.1.5' : type === 'cidr' ? '10.0.0.0/8' : type === 'port' ? '22' : 'hostname'} />
          <button className="btn btn-primary" disabled={!value} onClick={() => addMut.mutate()}>Add</button>
        </div>
        <table className="tbl">
          <thead><tr><th>Type</th><th>Value</th><th></th></tr></thead>
          <tbody>
            {exclusions.map((e: any) => (
              <tr key={e.id}>
                <td><span className="pill" style={{ fontSize: 10 }}>{e.type}</span></td>
                <td className="mono">{e.value}</td>
                <td><button className="btn btn-ghost btn-icon" onClick={() => delMut.mutate(e.id)}><X size={12} /></button></td>
              </tr>
            ))}
            {exclusions.length === 0 && (
              <tr><td colSpan={3} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>No exclusions</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
