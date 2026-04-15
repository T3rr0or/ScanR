/**
 * ScanDetail — slide-over panel with tabs:
 *   Console     — live WebSocket log feed (always visible while running)
 *   Findings    — vulnerability findings table with triage
 *   Hosts       — discovered hosts with ports/services
 *   Screenshots — Aquatone-style screenshot gallery
 */
import { useState, useRef, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { X, RefreshCw, Terminal, AlertTriangle, Camera, Server, CheckSquare, Square, Shield, Trash2, Network } from 'lucide-react'
import { scansApi } from '@/api/scans'
import { findingsApi, type Finding } from '@/api/findings'
import api from '@/api/client'
import ScanConsole from '@/components/ScanConsole'
import ScreenshotGallery from '@/components/ScreenshotGallery'
import SeverityBadge from '@/components/SeverityBadge'
import { useScanConsole } from '@/hooks/useScanConsole'
import NetworkTopology from '@/components/NetworkTopology'

interface Props {
  scanId: string
  onBack: () => void
}

type Tab = 'console' | 'findings' | 'hosts' | 'topology' | 'screenshots' | 'exclusions'

interface PortService {
  name?: string
  product?: string
  version?: string
  extra_info?: string
}

interface ScannedPort {
  id: string
  number: number
  protocol: string
  state: string
  service?: PortService
}

interface ScannedHost {
  id: string
  ip: string
  hostname?: string
  os_name?: string
  status: string
  ports?: ScannedPort[]
}

export default function ScanDetail({ scanId, onBack }: Props) {
  const [tab, setTab] = useState<Tab>('console')
  const [highlightHostIp, setHighlightHostIp] = useState<string | null>(null)

  function goToHost(ip: string) {
    setHighlightHostIp(ip)
    setTab('hosts')
  }

  const { data: scan, refetch } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => query.state.data?.status === 'running' ? 3000 : false,
  })

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', scanId],
    queryFn: () => findingsApi.list({ scan_id: scanId }),
    // Poll during scan so findings show live
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
    enabled: scan?.status === 'completed' || scan?.status === 'failed' || scan?.status === 'running',
  })

  const { data: hosts = [], isLoading: hostsLoading } = useQuery<ScannedHost[]>({
    queryKey: ['hosts', scanId],
    queryFn: () => scansApi.hosts(scanId),
    enabled: !!scan,
    refetchInterval: scan?.status === 'running' ? 10_000 : false,
  })

  const { events, connected, scanStatus } = useScanConsole(
    scan ? scanId : null   // always connect to get history replay for completed scans
  )

  const isActive = scan?.status === 'running' || scan?.status === 'pending'
  const isPending = scan?.status === 'pending'

  return (
    <div className="h-full flex flex-col bg-gray-950 overflow-hidden">
        {/* Header */}
        <div className="flex items-center gap-3 px-6 py-4 bg-gray-900 border-b border-gray-800 flex-shrink-0">
          <button onClick={onBack} className="p-2 text-gray-500 hover:text-gray-300 rounded" title="Back to scans">
            <X size={18} />
          </button>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="text-white font-semibold text-lg truncate">{scan?.name ?? '…'}</h2>
              {scan && <StatusPill status={scan.status} />}
            </div>
            <div className="text-xs text-gray-500 mt-0.5 font-mono">{scan?.id}</div>
          </div>
          <button onClick={() => refetch()} className="p-2 text-gray-500 hover:text-gray-300 rounded" title="Refresh">
            <RefreshCw size={15} />
          </button>
        </div>

        {/* Stats bar */}
        {scan && (
          <div className="flex gap-6 px-6 py-3 bg-gray-900 border-b border-gray-800 text-sm flex-shrink-0 flex-wrap">
            <Stat label="Hosts" value={`${scan.hosts_up ?? 0}/${scan.hosts_total ?? 0}`} />
            <Stat label="Critical" value={scan.findings_critical ?? 0} color="text-red-400" />
            <Stat label="High" value={scan.findings_high ?? 0} color="text-orange-400" />
            <Stat label="Medium" value={scan.findings_medium ?? 0} color="text-yellow-400" />
            <Stat label="Low" value={scan.findings_low ?? 0} color="text-green-400" />
            <Stat label="Info" value={scan.findings_info ?? 0} color="text-blue-400" />
            {scan.started_at && (
              <Stat label="Started" value={new Date(scan.started_at).toLocaleTimeString()} />
            )}
            {scan.finished_at && (
              <Stat label="Duration" value={duration(scan.started_at ?? undefined, scan.finished_at ?? undefined)} />
            )}
          </div>
        )}

        {/* Tabs */}
        <div className="flex border-b border-gray-800 bg-gray-900 flex-shrink-0">
          <TabBtn active={tab === 'console'} onClick={() => setTab('console')} icon={<Terminal size={13} />} label="Console" badge={isActive ? '●' : undefined} badgeClass="text-emerald-400" />
          <TabBtn active={tab === 'findings'} onClick={() => setTab('findings')} icon={<AlertTriangle size={13} />} label="Findings" badge={findings.length > 0 ? String(findings.length) : undefined} />
          <TabBtn active={tab === 'hosts'} onClick={() => setTab('hosts')} icon={<Server size={13} />} label="Hosts" badge={scan ? String(scan.hosts_up) : undefined} />
          <TabBtn active={tab === 'topology'} onClick={() => setTab('topology')} icon={<Network size={13} />} label="Topology" badge={hosts.length > 0 ? String(hosts.length) : undefined} />
          <TabBtn active={tab === 'screenshots'} onClick={() => setTab('screenshots')} icon={<Camera size={13} />} label="Screenshots" />
          {isPending && <TabBtn active={tab === 'exclusions'} onClick={() => setTab('exclusions')} icon={<Shield size={13} />} label="Exclusions" />}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {tab === 'console' && (
            <div className="flex-1 p-4 min-h-0">
              <ScanConsole events={events} connected={connected} scanStatus={scanStatus} />
            </div>
          )}
          {tab === 'findings' && (
            <div className="flex-1 overflow-y-auto">
              {findings.length > 0 ? (
                <FindingsList findings={findings} scanId={scanId} onGoToHost={goToHost} />
              ) : (
                <div className="flex items-center justify-center h-32 text-gray-600 text-sm">
                  {scan?.status === 'running' ? 'Scan running — findings will appear here as discovered' : scan?.status === 'pending' ? 'Scan not started yet' : 'No findings recorded'}
                </div>
              )}
            </div>
          )}
          {tab === 'hosts' && (
            <div className="flex-1 overflow-y-auto">
              {hostsLoading
                ? <div className="flex items-center justify-center h-32 text-gray-500 text-sm">Loading hosts…</div>
                : <HostsList hosts={hosts} highlightIp={highlightHostIp} />}
            </div>
          )}
          {tab === 'topology' && (
            <div className="flex-1 p-4 min-h-0">
              {hostsLoading
                ? <div className="flex items-center justify-center h-full text-gray-500 text-sm">Loading topology…</div>
                : <NetworkTopology
                    hosts={hosts}
                    findingsByHost={Object.fromEntries(
                      hosts.map((h) => [h.ip, findings.filter(f => f.host_ip === h.ip)])
                    )}
                  />}
            </div>
          )}
          {tab === 'screenshots' && (
            <div className="flex-1 overflow-y-auto">
              <ScreenshotGallery scanId={scanId} />
            </div>
          )}
          {tab === 'exclusions' && (
            <div className="flex-1 overflow-y-auto">
              <ExclusionsPanel scanId={scanId} />
            </div>
          )}
        </div>
    </div>
  )
}

function TabBtn({ active, onClick, icon, label, badge, badgeClass = 'text-gray-400' }: {
  active: boolean; onClick: () => void; icon: React.ReactNode
  label: string; badge?: string; badgeClass?: string
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-5 py-2.5 text-sm font-medium border-b-2 transition-colors ${
        active
          ? 'border-blue-500 text-white'
          : 'border-transparent text-gray-500 hover:text-gray-300'
      }`}
    >
      {icon}
      {label}
      {badge && <span className={`ml-1 text-xs ${badgeClass}`}>{badge}</span>}
    </button>
  )
}

function Stat({ label, value, color = 'text-white' }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="text-center">
      <div className={`font-bold font-mono ${color}`}>{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  )
}

function StatusPill({ status }: { status: string }) {
  const c: Record<string, string> = {
    running:   'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
    completed: 'bg-green-500/20 text-green-400 border border-green-500/30',
    failed:    'bg-red-500/20 text-red-400 border border-red-500/30',
    pending:   'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    cancelled: 'bg-gray-700/50 text-gray-400 border border-gray-600/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${c[status] ?? c.cancelled}`}>
      {status}
    </span>
  )
}

function FindingsList({ findings, scanId, onGoToHost }: { findings: Finding[]; scanId: string; onGoToHost: (ip: string) => void }) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [filter, setFilter] = useState<'all' | 'open' | 'false_positive' | 'accepted_risk'>('all')

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof findingsApi.update>[1] }) =>
      findingsApi.update(id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings', scanId] }),
  })

  const bulkMut = useMutation({
    mutationFn: (data: { false_positive?: boolean; remediation_status?: string }) =>
      findingsApi.bulkUpdate([...selected], data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings', scanId] })
      setSelected(new Set())
    },
  })

  const toggleSelect = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const filteredFindings = findings.filter(f => {
    if (filter === 'open') return !f.false_positive && f.remediation_status === 'open'
    if (filter === 'false_positive') return f.false_positive
    if (filter === 'accepted_risk') return f.remediation_status === 'accepted_risk'
    return true
  })

  if (findings.length === 0) {
    return <div className="flex items-center justify-center h-32 text-gray-600">No findings recorded</div>
  }

  return (
    <div>
      {/* Filter + bulk action bar */}
      <div className="flex items-center gap-3 px-4 py-2 bg-gray-900 border-b border-gray-800 flex-wrap sticky top-0">
        <div className="flex gap-1">
          {(['all', 'open', 'false_positive', 'accepted_risk'] as const).map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2 py-1 text-xs rounded transition-colors ${filter === f ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}
            >
              {f === 'all' ? 'All' : f === 'false_positive' ? 'False Positive' : f === 'accepted_risk' ? 'Accepted Risk' : 'Open'}
            </button>
          ))}
        </div>

        {selected.size > 0 && (
          <div className="flex items-center gap-2 ml-2 border-l border-gray-700 pl-3">
            <span className="text-xs text-gray-400">{selected.size} selected</span>
            <button
              onClick={() => bulkMut.mutate({ false_positive: true })}
              disabled={bulkMut.isPending}
              className="text-xs px-2 py-1 bg-orange-500/20 text-orange-400 rounded hover:bg-orange-500/30"
            >
              Mark FP
            </button>
            <button
              onClick={() => bulkMut.mutate({ remediation_status: 'accepted_risk' })}
              disabled={bulkMut.isPending}
              className="text-xs px-2 py-1 bg-gray-600/50 text-gray-300 rounded hover:bg-gray-600"
            >
              Accept Risk
            </button>
            <button onClick={() => setSelected(new Set())} className="text-xs text-gray-500 hover:text-gray-300">
              Clear
            </button>
          </div>
        )}
      </div>

      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-900 border-b border-gray-800">
            <th className="px-2 py-2 w-8" />
            {['Severity', 'Title', 'Host', 'Port', 'Status'].map(h => (
              <th key={h} className="px-4 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filteredFindings.map((f, i) => (
            <tr
              key={f.id ?? i}
              className={`border-b border-gray-800 hover:bg-gray-900/50 ${f.false_positive ? 'opacity-50' : ''}`}
            >
              <td className="px-2 py-2 text-center">
                <button onClick={() => toggleSelect(f.id)} className="text-gray-600 hover:text-gray-300">
                  {selected.has(f.id) ? <CheckSquare size={14} className="text-blue-400" /> : <Square size={14} />}
                </button>
              </td>
              <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
              <td className="px-4 py-2 text-gray-200 max-w-xs">
                <div className="truncate">{f.title}</div>
                {f.false_positive && <span className="text-xs text-orange-400">FP</span>}
              </td>
              <td className="px-4 py-2 font-mono text-xs">
                {f.host_ip
                  ? <button onClick={() => onGoToHost(f.host_ip!)} className="text-blue-400 hover:text-blue-300 hover:underline">{f.host_ip}</button>
                  : <span className="text-gray-500">—</span>}
              </td>
              <td className="px-4 py-2 text-gray-400 font-mono text-xs">{f.port_number ?? '—'}</td>
              <td className="px-4 py-2">
                <select
                  value={f.remediation_status}
                  onChange={e => updateMut.mutate({ id: f.id, data: { remediation_status: e.target.value } })}
                  className="text-xs bg-gray-800 border border-gray-700 rounded px-1 py-0.5 text-gray-300"
                >
                  <option value="open">Open</option>
                  <option value="accepted_risk">Accepted</option>
                  <option value="resolved">Resolved</option>
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function HostsList({ hosts, highlightIp }: { hosts: ScannedHost[]; highlightIp?: string | null }) {
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const highlightRef = useRef<HTMLTableRowElement | null>(null)

  useEffect(() => {
    if (highlightIp && highlightRef.current) {
      highlightRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }, [highlightIp])

  if (hosts.length === 0) {
    return <div className="flex items-center justify-center h-32 text-gray-600 text-sm">No hosts discovered</div>
  }

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="bg-gray-900 border-b border-gray-800 sticky top-0">
          {['IP', 'Hostname', 'OS', 'Open Ports', 'Status'].map(h => (
            <th key={h} className="px-4 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {hosts.map(host => {
          const isHighlighted = host.ip === highlightIp
          return (
          <>
            <tr
              key={host.id}
              ref={isHighlighted ? highlightRef : null}
              className={`border-b border-gray-800 cursor-pointer transition-colors ${isHighlighted ? 'bg-blue-900/30 border-l-2 border-l-blue-500' : 'hover:bg-gray-900'}`}
              onClick={() => setExpandedId(expandedId === host.id ? null : host.id)}
            >
              <td className="px-4 py-2 font-mono text-blue-400 text-xs">{host.ip}</td>
              <td className="px-4 py-2 text-gray-400 text-xs">{host.hostname ?? '—'}</td>
              <td className="px-4 py-2 text-gray-500 text-xs truncate max-w-xs">{host.os_name ?? '—'}</td>
              <td className="px-4 py-2 text-gray-300 font-mono text-xs">
                {host.ports?.filter((p) => p.state === 'open').length ?? 0}
              </td>
              <td className="px-4 py-2">
                <span className={`text-xs px-1.5 py-0.5 rounded ${host.status === 'up' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700 text-gray-400'}`}>
                  {host.status}
                </span>
              </td>
            </tr>
            {expandedId === host.id && (host.ports?.length ?? 0) > 0 && (
              <tr key={`${host.id}-ports`} className="bg-gray-900/50 border-b border-gray-800">
                <td colSpan={5} className="px-6 py-3">
                  <div className="text-xs text-gray-500 mb-2 font-medium">Open Ports</div>
                  <div className="flex flex-wrap gap-2">
                    {(host.ports ?? [])
                      .filter((p) => p.state === 'open')
                      .map((p) => (
                        <div key={p.id} className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs">
                          <span className="text-blue-400 font-mono">{p.number}/{p.protocol}</span>
                          {p.service && (
                            <span className="text-gray-400 ml-1">
                              {[p.service.name, p.service.product, p.service.version].filter(Boolean).join(' ')}
                            </span>
                          )}
                        </div>
                      ))}
                  </div>
                </td>
              </tr>
            )}
          </>
        )})}
      </tbody>
    </table>
  )
}

function ExclusionsPanel({ scanId }: { scanId: string }) {
  const qc = useQueryClient()
  const [type, setType] = useState('ip')
  const [value, setValue] = useState('')
  const [reason, setReason] = useState('')

  interface Exclusion { id: string; type: string; value: string; reason?: string }
  const { data: exclusions = [] } = useQuery<Exclusion[]>({
    queryKey: ['exclusions', scanId],
    queryFn: () => api.get(`/scans/${scanId}/exclusions`).then(r => r.data),
  })

  const addMut = useMutation({
    mutationFn: () => api.post(`/scans/${scanId}/exclusions`, { type, value, reason: reason || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['exclusions', scanId] }); setValue(''); setReason('') },
  })
  const delMut = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${scanId}/exclusions/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exclusions', scanId] }),
  })

  return (
    <div className="p-4 space-y-4">
      <p className="text-xs text-gray-500">Exclusions are applied at scan time — IPs, CIDRs, ports, or hostnames to skip entirely.</p>

      {/* Add form */}
      <div className="flex gap-2 flex-wrap">
        <select value={type} onChange={e => setType(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300">
          <option value="ip">IP</option>
          <option value="cidr">CIDR</option>
          <option value="port">Port</option>
          <option value="host">Hostname</option>
        </select>
        <input value={value} onChange={e => setValue(e.target.value)}
          placeholder={type === 'ip' ? '192.168.1.5' : type === 'cidr' ? '10.0.0.0/8' : type === 'port' ? '22' : 'evil.corp'}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 font-mono w-44"
        />
        <input value={reason} onChange={e => setReason(e.target.value)}
          placeholder="Reason (optional)"
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-300 flex-1 min-w-32"
        />
        <button
          onClick={() => addMut.mutate()}
          disabled={!value || addMut.isPending}
          className="px-3 py-1.5 bg-blue-600 text-white text-xs rounded hover:bg-blue-700 disabled:opacity-50"
        >
          Add
        </button>
      </div>

      {/* Exclusion list */}
      {exclusions.length === 0 ? (
        <p className="text-gray-600 text-xs text-center py-4">No exclusions — all targets will be scanned</p>
      ) : (
        <div className="space-y-1">
          {exclusions.map((e) => (
            <div key={e.id} className="flex items-center gap-3 bg-gray-800/50 border border-gray-700 rounded px-3 py-2">
              <span className="text-xs bg-gray-700 text-gray-300 rounded px-1.5 py-0.5">{e.type}</span>
              <span className="text-xs font-mono text-gray-200 flex-1">{e.value}</span>
              {e.reason && <span className="text-xs text-gray-500 truncate max-w-48">{e.reason}</span>}
              <button onClick={() => delMut.mutate(e.id)} className="text-gray-600 hover:text-red-400 ml-2">
                <Trash2 size={12} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function duration(start?: string, end?: string) {
  if (!start || !end) return '—'
  const s = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}
