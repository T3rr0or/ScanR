import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, FileText } from 'lucide-react'
import { reportsApi } from '@/api/reports'
import { scansApi } from '@/api/scans'
import { StatusPill, relTime, EmptyState } from '@/components/ui'

const FORMATS = ['html', 'pdf', 'json', 'csv', 'sarif']

export default function Reports() {
  const qc = useQueryClient()
  const { data: reports = [] } = useQuery({ queryKey: ['reports'], queryFn: () => reportsApi.list(), refetchInterval: 5000 })
  const { data: scans = [] } = useQuery({ queryKey: ['scans', 0], queryFn: () => scansApi.list({ limit: 200 }) })
  const scanMap = Object.fromEntries(scans.map(s => [s.id, s.name]))

  const [scanId, setScanId] = useState('')
  const [format, setFormat] = useState('html')

  const [mutErr, setMutErr] = useState<string | null>(null)
  const createMut = useMutation({
    mutationFn: () => reportsApi.create(scanId, format),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['reports'] }); setMutErr(null) },
    onError: (e: unknown) => setMutErr(e instanceof Error ? e.message : String(e)),
  })

  return (
    <div className="page-pad">
      {mutErr && <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '6px 10px', borderRadius: 4, fontSize: 12, marginBottom: 12 }}>{mutErr}</div>}
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
        <FileText size={18} style={{ color: 'var(--accent)' }} />
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Reports</h1>
      </div>

      {/* Side-by-side layout — stacks vertically on narrow screens */}
      <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start', flexWrap: 'wrap' }}>
        {/* Report list — left, grows */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="panel" style={{ overflow: 'hidden' }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Scan</th>
                  <th>Format</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.id}>
                    <td className="mono dimmer" style={{ fontSize: 11 }}>{r.id.slice(0, 8)}</td>
                    <td style={{ color: 'var(--text-0)', fontWeight: 500 }}>{scanMap[r.scan_id] ?? r.scan_id.slice(0, 8)}</td>
                    <td className="mono" style={{ fontSize: 11, textTransform: 'uppercase', color: 'var(--accent)' }}>{r.format}</td>
                    <td><StatusPill status={r.status} /></td>
                    <td className="dimmer" style={{ fontSize: 11 }}>{relTime(r.created_at)}</td>
                    <td style={{ textAlign: 'right' }}>
                      {r.status === 'completed' && (
                        <button
                          onClick={() => reportsApi.download(r)}
                          className="btn btn-ghost btn-sm"
                          style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
                        >
                          <Download size={12} /> Download
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
                {reports.length === 0 && (
                  <EmptyState icon={<FileText size={28} />} message="No reports yet" />
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Generate panel — right, fixed width */}
        <div className="panel" style={{ width: 'clamp(240px, 35vw, 280px)', flexShrink: 0 }}>
          <div className="panel-head">
            <span className="panel-title">Generate Report</span>
          </div>
          <div style={{ padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label className="label">Scan</label>
              <select value={scanId} onChange={e => setScanId(e.target.value)} className="select-field">
                <option value="">Select scan…</option>
                {scans.map(s => <option key={s.id} value={s.id}>{s.name} ({s.status})</option>)}
              </select>
            </div>
            <div>
              <label className="label">Format</label>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {FORMATS.map(f => (
                  <button
                    key={f}
                    onClick={() => setFormat(f)}
                    className={`btn btn-sm ${format === f ? 'btn-primary' : 'btn-ghost'}`}
                    style={{ fontSize: 11, textTransform: 'uppercase' }}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <button
              onClick={() => createMut.mutate()}
              disabled={!scanId || createMut.isPending}
              className="btn btn-primary btn-sm"
              style={{ marginTop: 4 }}
            >
              {createMut.isPending ? 'Generating…' : 'Generate'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
