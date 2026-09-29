import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { reportsApi } from '@/api/reports'
import { scansApi } from '@/api/scans'
import { StatusPill, relTime } from '@/components/ui'
import './OperatorPages.css'

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
    <div className="page-pad operator-page reports-page">
      <header className="operator-head">
        <div className="operator-heading">
          <h1>Reports <span>{reports.length} generated</span></h1>
        </div>
      </header>

      {mutErr && <div className="operator-error" role="alert">{mutErr}</div>}

      <section className="report-generator" aria-label="Generate report">
        <label className="report-field">
          <span>Scan</span>
          <select value={scanId} onChange={e => setScanId(e.target.value)} className="select-field">
            <option value="">Select scan</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.name} ({s.status})</option>)}
          </select>
        </label>
        <div className="report-field">
          <span>Format</span>
          <div className="report-formats" role="group" aria-label="Report format">
            {FORMATS.map(f => (
              <button key={f} type="button" onClick={() => setFormat(f)} className={format === f ? 'is-active' : ''} aria-pressed={format === f}>{f.toUpperCase()}</button>
            ))}
          </div>
        </div>
        <button type="button" onClick={() => createMut.mutate()} disabled={!scanId || createMut.isPending} className="operator-primary">
          {createMut.isPending ? 'Generating…' : 'Generate report'}
        </button>
      </section>

      <section className="report-register" aria-label="Generated reports">
        <div className="report-register-heading"><h2>Generated reports</h2><span>{reports.length} reports</span></div>
        <div className="operator-table-panel">
          {reports.length === 0 ? (
            <div className="operator-empty"><strong>No reports yet.</strong><span>Select a scan and format to generate one.</span></div>
          ) : (
            <table className="tbl">
              <thead><tr><th>ID</th><th>Scan</th><th>Format</th><th>Status</th><th>Created</th><th>Action</th></tr></thead>
              <tbody>
                {reports.map(r => (
                  <tr key={r.id}>
                    <td className="mono dimmer" style={{ fontSize: 11 }}>{r.id.slice(0, 8)}</td>
                    <td style={{ color: 'var(--text-0)', fontWeight: 600 }}>{scanMap[r.scan_id] ?? r.scan_id.slice(0, 8)}</td>
                    <td style={{ fontSize: 12, textTransform: 'uppercase', color: 'var(--text-1)' }}>{r.format}</td>
                    <td><StatusPill status={r.status} /></td>
                    <td className="dimmer" style={{ fontSize: 11 }}>{relTime(r.created_at)}</td>
                    <td>{r.status === 'completed' && <button type="button" onClick={() => reportsApi.download(r)} className="operator-text-action"><Download size={12} /> Download</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>
    </div>
  )
}
