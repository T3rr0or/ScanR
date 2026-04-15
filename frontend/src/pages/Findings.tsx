import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsApi, type Finding } from '@/api/findings'
import { scansApi } from '@/api/scans'
import SeverityBadge from '@/components/SeverityBadge'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

export default function Findings() {
  const [severity, setSeverity] = useState('')
  const [scanId, setScanId] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const qc = useQueryClient()

  const { data: scans = [] } = useQuery({ queryKey: ['scans'], queryFn: scansApi.list })

  const params: Record<string, string> = {}
  if (severity) params.severity = severity
  if (scanId) params.scan_id = scanId

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', severity, scanId],
    queryFn: () => findingsApi.list(Object.keys(params).length ? params : undefined),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: { false_positive?: boolean; analyst_notes?: string } }) =>
      findingsApi.update(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })

  return (
    <div className="p-8 flex gap-6">
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-4 gap-3 flex-wrap">
          <h1 className="text-2xl font-bold">Findings</h1>
          <div className="flex gap-2 flex-wrap">
            <select value={scanId} onChange={e => setScanId(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm">
              <option value="">All scans</option>
              {scans.map(s => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
            <select value={severity} onChange={e => setSeverity(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-1.5 text-sm">
              {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All severities'}</option>)}
            </select>
          </div>
        </div>
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                {['Severity', 'Title', 'Host', 'Plugin', 'Port', 'CVSS', 'FP'].map(h =>
                  <th key={h} className="px-4 py-3 text-left font-medium text-gray-600">{h}</th>
                )}
              </tr>
            </thead>
            <tbody>
              {findings.map(f => (
                <tr key={f.id} onClick={() => setSelected(f)}
                  className={`border-b border-gray-100 cursor-pointer hover:bg-gray-50 ${f.false_positive ? 'opacity-40' : ''}`}>
                  <td className="px-4 py-2"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-2 font-medium max-w-xs truncate">{f.title}</td>
                  <td className="px-4 py-2 text-gray-500 font-mono text-xs">{f.host_ip ?? '—'}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs">{f.plugin_id}</td>
                  <td className="px-4 py-2 text-gray-500">{f.port_number ? `${f.port_number}/${f.protocol}` : '—'}</td>
                  <td className="px-4 py-2">{f.cvss_score?.toFixed(1) ?? '—'}</td>
                  <td className="px-4 py-2">{f.false_positive ? '✓' : ''}</td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No findings</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selected && (
        <div className="w-96 flex-shrink-0 bg-white border border-gray-200 rounded-xl p-5 overflow-auto max-h-screen">
          <div className="flex items-center gap-2 mb-3">
            <SeverityBadge severity={selected.severity} />
            <button onClick={() => setSelected(null)} className="ml-auto text-gray-400 hover:text-gray-600 text-lg">×</button>
          </div>
          <h2 className="font-semibold text-base mb-2">{selected.title}</h2>
          {selected.cvss_score && <p className="text-sm text-gray-500 mb-3">CVSS: {selected.cvss_score.toFixed(1)}</p>}
          {selected.description && <><p className="text-xs font-semibold text-gray-500 uppercase mb-1">Description</p>
            <p className="text-sm text-gray-700 mb-3">{selected.description}</p></>}
          {selected.evidence && <><p className="text-xs font-semibold text-gray-500 uppercase mb-1">Evidence</p>
            <pre className="bg-gray-900 text-gray-100 rounded p-3 text-xs overflow-auto mb-3 whitespace-pre-wrap">{selected.evidence}</pre></>}
          {selected.remediation && <><p className="text-xs font-semibold text-gray-500 uppercase mb-1">Remediation</p>
            <div className="bg-green-50 border-l-4 border-green-500 px-3 py-2 text-sm text-green-800 mb-3">{selected.remediation}</div></>}
          <div className="flex gap-2 mt-4">
            <button
              onClick={() => updateMut.mutate({ id: selected.id, body: { false_positive: !selected.false_positive } })}
              className={`px-3 py-1 rounded text-xs font-medium border ${selected.false_positive ? 'border-gray-300 text-gray-600' : 'border-orange-300 text-orange-600'}`}
            >
              {selected.false_positive ? 'Unmark FP' : 'Mark False Positive'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
