import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { reportsApi } from '@/api/reports'
import { scansApi } from '@/api/scans'

const FORMATS = ['html', 'pdf', 'json', 'csv']

export default function Reports() {
  const qc = useQueryClient()
  const { data: reports = [] } = useQuery({ queryKey: ['reports'], queryFn: () => reportsApi.list(), refetchInterval: 5000 })
  const { data: scans = [] } = useQuery({ queryKey: ['scans', 0], queryFn: () => scansApi.list({ limit: 200 }) })
  const scanMap = Object.fromEntries(scans.map(s => [s.id, s.name]))

  const [scanId, setScanId] = useState('')
  const [format, setFormat] = useState('html')

  const createMut = useMutation({
    mutationFn: () => reportsApi.create(scanId, format),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['reports'] }),
  })

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Reports</h1>

      <div className="bg-white border border-gray-200 rounded-xl p-5 mb-6">
        <h2 className="font-semibold mb-3">Generate Report</h2>
        <div className="flex gap-3 flex-wrap">
          <select value={scanId} onChange={e => setScanId(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm flex-1 min-w-48">
            <option value="">Select scan...</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.name} ({s.status})</option>)}
          </select>
          <select value={format} onChange={e => setFormat(e.target.value)}
            className="border border-gray-300 rounded-lg px-3 py-2 text-sm">
            {FORMATS.map(f => <option key={f} value={f}>{f.toUpperCase()}</option>)}
          </select>
          <button
            onClick={() => createMut.mutate()}
            disabled={!scanId || createMut.isPending}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium"
          >
            {createMut.isPending ? 'Generating...' : 'Generate'}
          </button>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              {['ID', 'Scan', 'Format', 'Status', 'Created', 'Download'].map(h =>
                <th key={h} className="px-4 py-3 text-left font-medium text-gray-600">{h}</th>
              )}
            </tr>
          </thead>
          <tbody>
            {reports.map(r => (
              <tr key={r.id} className="border-b border-gray-100 hover:bg-gray-50">
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{r.id.slice(0, 8)}</td>
                <td className="px-4 py-3 text-gray-700">{scanMap[r.scan_id] ?? r.scan_id.slice(0, 8)}</td>
                <td className="px-4 py-3 font-medium uppercase">{r.format}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${r.status === 'completed' ? 'bg-green-100 text-green-700' : r.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>
                    {r.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">{new Date(r.created_at).toLocaleString()}</td>
                <td className="px-4 py-3">
                  {r.status === 'completed' && (
                    <button
                      onClick={() => reportsApi.download(r)}
                      className="flex items-center gap-1 text-blue-600 hover:text-blue-700 text-xs font-medium"
                    >
                      <Download size={13} /> Download
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {reports.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No reports yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
