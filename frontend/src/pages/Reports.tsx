import { useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Download, Trash2, Upload } from 'lucide-react'
import { reportsApi, reportTemplatesApi } from '@/api/reports'
import { scansApi } from '@/api/scans'
import { StatusPill, relTime } from '@/components/ui'
import { useAuthStore } from '@/store/auth'
import { parseJwtRole } from '@/utils/jwt'
import { apiErrorMessage } from '@/utils/apiError'
import './OperatorPages.css'

const FORMATS: { id: string; label: string }[] = [
  { id: 'docx', label: 'WORD' }, { id: 'pdf', label: 'PDF' }, { id: 'html', label: 'HTML' },
  { id: 'json', label: 'JSON' }, { id: 'csv', label: 'CSV' }, { id: 'sarif', label: 'SARIF' },
]

function TemplateManager({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [name, setName] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showHelp, setShowHelp] = useState(false)
  const { data: templates = [] } = useQuery({ queryKey: ['report-templates'], queryFn: reportTemplatesApi.list })
  const { data: placeholders } = useQuery({ queryKey: ['report-placeholders'], queryFn: reportTemplatesApi.placeholders, enabled: showHelp })
  const upload = useMutation({
    mutationFn: () => reportTemplatesApi.upload(file!, name, ''),
    onSuccess: () => { setName(''); setFile(null); setError(null); qc.invalidateQueries({ queryKey: ['report-templates'] }) },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })
  const remove = useMutation({ mutationFn: reportTemplatesApi.remove, onSuccess: () => qc.invalidateQueries({ queryKey: ['report-templates'] }) })

  return (
    <section className="report-register" aria-label="Word templates">
      <div className="report-register-heading"><h2>Word templates</h2><span>{templates.length + 1} available</span></div>
      <p className="report-help">
        Word reports use the built-in template unless you choose your own. Download the default, add your logo, fonts and
        standard text in Word, and upload it as your house style. Placeholders such as <span className="mono">{'{{ report.client }}'}</span> are
        filled in when a report is generated. <button type="button" className="operator-text-action" onClick={() => setShowHelp(v => !v)}>{showHelp ? 'Hide' : 'Show'} placeholders</button>
      </p>
      {showHelp && placeholders && (
        <table className="tbl report-placeholders"><tbody>{Object.entries(placeholders).map(([k, v]) => <tr key={k}><td className="mono">{k}</td><td>{v}</td></tr>)}</tbody></table>
      )}
      <div className="operator-table-panel">
        <table className="tbl">
          <thead><tr><th>Template</th><th>Uploaded by</th><th>Added</th><th /></tr></thead>
          <tbody>
            <tr>
              <td style={{ color: 'var(--text-0)', fontWeight: 600 }}>ScanR default</td><td className="dimmer">built in</td><td className="dimmer">–</td>
              <td><button type="button" className="operator-text-action" onClick={() => reportTemplatesApi.downloadDefault()}><Download size={12} /> Download</button></td>
            </tr>
            {templates.map(t => (
              <tr key={t.id}>
                <td style={{ color: 'var(--text-0)', fontWeight: 600 }}>{t.name}</td>
                <td className="dimmer">{t.uploaded_by ?? '–'}</td>
                <td className="dimmer" style={{ fontSize: 11 }}>{relTime(t.created_at)}</td>
                <td style={{ whiteSpace: 'nowrap' }}>
                  <button type="button" className="operator-text-action" onClick={() => reportTemplatesApi.download(t)}><Download size={12} /> Download</button>
                  {isAdmin && <button type="button" className="operator-text-action" style={{ color: 'var(--sev-high)', marginLeft: 14 }} onClick={() => { if (confirm(`Delete template "${t.name}"?`)) remove.mutate(t.id) }}><Trash2 size={12} /> Delete</button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {isAdmin && (
        <div className="report-upload">
          <input className="input" placeholder="Template name, e.g. ACME house style" value={name} onChange={e => setName(e.target.value)} maxLength={255} />
          <button type="button" className="btn btn-sm" onClick={() => fileRef.current?.click()}><Upload size={13} /> {file ? file.name : 'Choose .docx'}</button>
          <input ref={fileRef} type="file" hidden accept=".docx,application/vnd.openxmlformats-officedocument.wordprocessingml.document" onChange={e => setFile(e.target.files?.[0] ?? null)} />
          <button type="button" className="operator-primary" disabled={!file || !name.trim() || upload.isPending} onClick={() => upload.mutate()}>{upload.isPending ? 'Checking…' : 'Upload template'}</button>
          {error && <div className="operator-error" role="alert">{error}</div>}
        </div>
      )}
    </section>
  )
}

export default function Reports() {
  const qc = useQueryClient()
  const isAdmin = parseJwtRole(useAuthStore(s => s.token)) === 'admin'
  const { data: reports = [] } = useQuery({ queryKey: ['reports'], queryFn: () => reportsApi.list(), refetchInterval: 5000 })
  const { data: scans = [] } = useQuery({ queryKey: ['scans', 0], queryFn: () => scansApi.list({ limit: 200 }) })
  const { data: templates = [] } = useQuery({ queryKey: ['report-templates'], queryFn: reportTemplatesApi.list })
  const scanMap = Object.fromEntries(scans.map(s => [s.id, s.name]))

  const [scanId, setScanId] = useState('')
  const [format, setFormat] = useState('docx')
  const [docx, setDocx] = useState({ template_id: '', title: '', client: '', author: '', classification: 'Confidential', include_info: false })

  const [mutErr, setMutErr] = useState<string | null>(null)
  const createMut = useMutation({
    mutationFn: () => reportsApi.create(scanId, format, {
      ...(docx.template_id ? { template_id: docx.template_id } : {}),
      title: docx.title, client: docx.client, author: docx.author, classification: docx.classification, include_info: docx.include_info,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['reports'] }); setMutErr(null) },
    onError: (e: unknown) => setMutErr(apiErrorMessage(e)),
  })
  const set = (key: 'title' | 'client' | 'author' | 'classification' | 'template_id') => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setDocx(d => ({ ...d, [key]: e.target.value }))

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
              <button key={f.id} type="button" onClick={() => setFormat(f.id)} className={format === f.id ? 'is-active' : ''} aria-pressed={format === f.id}>{f.label}</button>
            ))}
          </div>
        </div>
        <button type="button" onClick={() => createMut.mutate()} disabled={!scanId || createMut.isPending} className="operator-primary">
          {createMut.isPending ? 'Generating…' : 'Generate report'}
        </button>
      </section>

      {format === 'docx' && (
        <section className="report-docx-options" aria-label="Word report options">
          <label className="report-field"><span>Template</span>
            <select className="select-field" value={docx.template_id} onChange={set('template_id')}>
              <option value="">ScanR default</option>
              {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          </label>
          <label className="report-field"><span>Report title</span><input className="input" value={docx.title} onChange={set('title')} placeholder="Security assessment: <scan name>" /></label>
          <label className="report-field"><span>Client</span><input className="input" value={docx.client} onChange={set('client')} placeholder="ACME B.V." /></label>
          <label className="report-field"><span>Author</span><input className="input" value={docx.author} onChange={set('author')} placeholder="Your name or company" /></label>
          <label className="report-field"><span>Classification</span><input className="input" value={docx.classification} onChange={set('classification')} /></label>
          <label className="report-check"><input type="checkbox" checked={docx.include_info} onChange={e => setDocx(d => ({ ...d, include_info: e.target.checked }))} /> Include informational findings</label>
        </section>
      )}

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
                    <td style={{ fontSize: 12, textTransform: 'uppercase', color: 'var(--text-1)' }}>{r.format === 'docx' ? 'Word' : r.format}</td>
                    <td><StatusPill status={r.status} />{r.status === 'failed' && r.error_message && <div className="dimmer" style={{ fontSize: 10, marginTop: 2 }} title={r.error_message}>{r.error_message.slice(0, 80)}</div>}</td>
                    <td className="dimmer" style={{ fontSize: 11 }}>{relTime(r.created_at)}</td>
                    <td>{r.status === 'completed' && <button type="button" onClick={() => reportsApi.download(r)} className="operator-text-action"><Download size={12} /> Download</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <TemplateManager isAdmin={isAdmin} />
    </div>
  )
}
