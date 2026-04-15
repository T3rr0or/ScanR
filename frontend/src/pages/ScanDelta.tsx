/**
 * ScanDelta — compare two scans side-by-side.
 * Shows new/resolved/persisting findings, new/removed hosts, port changes.
 */
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { X, ArrowRight, TrendingUp, TrendingDown, Minus, Server, Unlock } from 'lucide-react'
import { scansApi } from '@/api/scans'
import SeverityBadge from '@/components/SeverityBadge'

interface Props {
  scanId: string
  scanName: string
  onClose: () => void
}

export default function ScanDelta({ scanId, scanName, onClose }: Props) {
  const [baselineId, setBaselineId] = useState<string>('')
  const [tab, setTab] = useState<'new' | 'resolved' | 'persisting' | 'hosts' | 'ports'>('new')

  const { data: scans = [] } = useQuery({ queryKey: ['scans'], queryFn: scansApi.list })
  const candidates = scans.filter(s =>
    s.id !== scanId && (s.status === 'completed' || s.status === 'failed')
  )

  const { data: delta, isLoading, error } = useQuery({
    queryKey: ['delta', scanId, baselineId],
    queryFn: () => scansApi.delta(scanId, baselineId),
    enabled: !!baselineId,
  })

  const baselineName = candidates.find(s => s.id === baselineId)?.name ?? ''

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/40" onClick={onClose} />
      <div className="w-full max-w-5xl bg-white border-l border-gray-200 flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 bg-gray-50 flex-shrink-0">
          <div className="flex-1 min-w-0">
            <h2 className="font-semibold text-gray-900 text-lg">Scan Comparison</h2>
            <div className="text-sm text-gray-500 flex items-center gap-2 mt-0.5 flex-wrap">
              <span className="font-medium text-gray-700">{scanName}</span>
              {baselineName && <>
                <ArrowRight size={14} />
                <span className="text-gray-500">{baselineName} (baseline)</span>
              </>}
            </div>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-600 rounded">
            <X size={18} />
          </button>
        </div>

        {/* Baseline selector */}
        <div className="px-6 py-4 border-b border-gray-200 bg-white flex-shrink-0">
          <label className="block text-xs font-medium text-gray-600 mb-1.5">Compare against baseline scan</label>
          <select
            value={baselineId}
            onChange={e => setBaselineId(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
          >
            <option value="">— select a baseline —</option>
            {candidates.map(s => (
              <option key={s.id} value={s.id}>
                {s.name} ({new Date(s.created_at).toLocaleDateString()}) — {s.hosts_up} hosts
              </option>
            ))}
          </select>
          {candidates.length === 0 && (
            <p className="mt-1 text-xs text-gray-400">No other completed scans available to compare against.</p>
          )}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {!baselineId && (
            <div className="flex-1 flex items-center justify-center text-gray-400 text-sm">
              Select a baseline scan above to see the delta
            </div>
          )}
          {baselineId && isLoading && (
            <div className="flex-1 flex items-center justify-center text-gray-400 text-sm">Loading comparison…</div>
          )}
          {baselineId && error && (
            <div className="flex-1 flex items-center justify-center text-red-500 text-sm">Failed to load delta</div>
          )}
          {delta && (
            <>
              {/* Summary cards */}
              <div className="grid grid-cols-2 md:grid-cols-6 gap-3 px-6 py-4 border-b border-gray-200 flex-shrink-0">
                <SummaryCard label="New Findings" value={delta.summary.new_findings} color="text-red-600 bg-red-50" icon={<TrendingUp size={16} />} onClick={() => setTab('new')} active={tab === 'new'} />
                <SummaryCard label="Resolved" value={delta.summary.resolved_findings} color="text-green-600 bg-green-50" icon={<TrendingDown size={16} />} onClick={() => setTab('resolved')} active={tab === 'resolved'} />
                <SummaryCard label="Persisting" value={delta.summary.persisting_findings} color="text-orange-600 bg-orange-50" icon={<Minus size={16} />} onClick={() => setTab('persisting')} active={tab === 'persisting'} />
                <SummaryCard label="New Hosts" value={delta.summary.new_hosts} color="text-blue-600 bg-blue-50" icon={<Server size={16} />} onClick={() => setTab('hosts')} active={tab === 'hosts'} />
                <SummaryCard label="Lost Hosts" value={delta.summary.removed_hosts} color="text-gray-600 bg-gray-100" icon={<Server size={16} />} onClick={() => setTab('hosts')} active={tab === 'hosts'} />
                <SummaryCard label="Port Changes" value={delta.summary.port_changes} color="text-purple-600 bg-purple-50" icon={<Unlock size={16} />} onClick={() => setTab('ports')} active={tab === 'ports'} />
              </div>

              {/* Tab body */}
              <div className="flex-1 overflow-y-auto px-6 py-4">
                {tab === 'new' && <FindingList findings={delta.new_findings} label="New Findings" emptyMsg="No new findings — great!" badge="new" />}
                {tab === 'resolved' && <FindingList findings={delta.resolved_findings} label="Resolved Findings" emptyMsg="No findings resolved." badge="resolved" />}
                {tab === 'persisting' && <FindingList findings={delta.persisting_findings} label="Persisting Findings" emptyMsg="No persisting findings." badge="persisting" />}
                {tab === 'hosts' && <HostDelta newHosts={delta.new_hosts} removedHosts={delta.removed_hosts} />}
                {tab === 'ports' && <PortChanges changes={delta.port_changes} />}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

function SummaryCard({ label, value, color, icon, onClick, active }: {
  label: string; value: number; color: string; icon: React.ReactNode
  onClick: () => void; active: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-lg p-3 text-left transition-all border-2 ${active ? 'border-blue-400 ring-1 ring-blue-200' : 'border-transparent'} ${color}`}
    >
      <div className="flex items-center gap-1.5 mb-1 opacity-70">{icon}<span className="text-xs font-medium">{label}</span></div>
      <div className="text-2xl font-bold">{value}</div>
    </button>
  )
}

function FindingList({ findings, label, emptyMsg, badge }: {
  findings: any[]; label: string; emptyMsg: string; badge: 'new' | 'resolved' | 'persisting'
}) {
  const badgeStyle = {
    new: 'bg-red-100 text-red-700',
    resolved: 'bg-green-100 text-green-700',
    persisting: 'bg-orange-100 text-orange-700',
  }[badge]

  if (findings.length === 0) {
    return <p className="text-gray-400 text-sm text-center py-8">{emptyMsg}</p>
  }
  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-700 mb-3">{label} ({findings.length})</h3>
      <table className="w-full text-sm border-collapse">
        <thead>
          <tr className="bg-gray-50 border-b border-gray-200">
            {['', 'Severity', 'Title', 'Host', 'Port'].map(h => (
              <th key={h} className="px-3 py-2 text-left text-xs font-medium text-gray-500">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i} className="border-b border-gray-100 hover:bg-gray-50">
              <td className="px-3 py-2">
                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${badgeStyle}`}>{badge}</span>
              </td>
              <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
              <td className="px-3 py-2 text-gray-800 max-w-xs"><div className="truncate">{f.title}</div></td>
              <td className="px-3 py-2 text-gray-500 font-mono text-xs">{f.host_ip || '—'}</td>
              <td className="px-3 py-2 text-gray-500 font-mono text-xs">{f.port_number ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function HostDelta({ newHosts, removedHosts }: { newHosts: any[]; removedHosts: any[] }) {
  return (
    <div className="space-y-6">
      {newHosts.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-blue-700 mb-2">New Hosts ({newHosts.length})</h3>
          <div className="space-y-1">
            {newHosts.map((h, i) => (
              <div key={i} className="flex items-center gap-3 bg-blue-50 border border-blue-200 rounded px-3 py-2 text-sm">
                <span className="font-mono text-blue-700">{h.ip}</span>
                {h.hostname && <span className="text-gray-500">{h.hostname}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
      {removedHosts.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-600 mb-2">Removed Hosts ({removedHosts.length})</h3>
          <div className="space-y-1">
            {removedHosts.map((h, i) => (
              <div key={i} className="flex items-center gap-3 bg-gray-100 border border-gray-200 rounded px-3 py-2 text-sm">
                <span className="font-mono text-gray-500 line-through">{h.ip}</span>
                {h.hostname && <span className="text-gray-400">{h.hostname}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
      {newHosts.length === 0 && removedHosts.length === 0 && (
        <p className="text-gray-400 text-sm text-center py-8">No host changes between scans.</p>
      )}
    </div>
  )
}

function PortChanges({ changes }: { changes: any[] }) {
  if (changes.length === 0) {
    return <p className="text-gray-400 text-sm text-center py-8">No port changes between scans.</p>
  }
  return (
    <div>
      <h3 className="text-sm font-semibold text-gray-700 mb-3">Port Changes ({changes.length} hosts)</h3>
      <div className="space-y-3">
        {changes.map((c, i) => (
          <div key={i} className="border border-gray-200 rounded-lg p-3">
            <div className="font-mono text-sm font-semibold text-gray-800 mb-2">{c.ip}</div>
            <div className="flex flex-wrap gap-2">
              {c.opened.map((p: any, j: number) => (
                <span key={j} className="bg-blue-100 text-blue-700 text-xs font-mono px-2 py-0.5 rounded">
                  +{p.port}/{p.protocol}
                </span>
              ))}
              {c.closed.map((p: any, j: number) => (
                <span key={j} className="bg-gray-200 text-gray-600 text-xs font-mono px-2 py-0.5 rounded line-through">
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
