import { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Plus, Search, Upload } from 'lucide-react'
import { libraryApi, type LibraryEntry, type LibraryEntryInput, type Severity } from '@/api/library'
import { SevTag } from '@/components/ui'
import { useAuthStore } from '@/store/auth'
import { parseJwtRole } from '@/utils/jwt'
import { apiErrorMessage } from '@/utils/apiError'
import './OperatorPages.css'
import './Library.css'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const EMPTY: LibraryEntryInput = {
  title: '', severity: 'medium', cvss_score: null, cvss_vector: null, description: '', impact: null,
  remediation: null, references: [], cve_ids: [], tags: [], plugin_ids: [], title_match: null,
}
const lines = (v: string) => v.split('\n').map(s => s.trim()).filter(Boolean)
const words = (v: string) => v.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)

function Editor({ entry, onClose }: { entry: LibraryEntry | null; onClose: () => void }) {
  const qc = useQueryClient()
  const start = entry ?? EMPTY
  const [form, setForm] = useState({
    ...start,
    cvss_score: start.cvss_score?.toString() ?? '',
    references: start.references.join('\n'),
    cve_ids: start.cve_ids.join(', '),
    tags: start.tags.join(', '),
    plugin_ids: start.plugin_ids.join(', '),
  })
  const [error, setError] = useState<string | null>(null)
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [key]: e.target.value }))
  const save = useMutation({
    mutationFn: () => {
      const body: LibraryEntryInput = {
        title: form.title, severity: form.severity as Severity,
        cvss_score: form.cvss_score === '' ? null : Number(form.cvss_score), cvss_vector: form.cvss_vector || null,
        description: form.description, impact: form.impact || null, remediation: form.remediation || null,
        references: lines(form.references), cve_ids: words(form.cve_ids), tags: words(form.tags),
        plugin_ids: words(form.plugin_ids), title_match: form.title_match || null,
      }
      return entry ? libraryApi.update(entry.id, body) : libraryApi.create(body)
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['library'] }); onClose() },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })
  const remove = useMutation({
    mutationFn: () => libraryApi.remove(entry!.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['library'] }); onClose() },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })

  return (
    <div className="library-editor panel">
      <h2>{entry ? 'Edit entry' : 'New library entry'}</h2>
      {error && <div className="library-error" role="alert">{error}</div>}
      <label>Title<input className="input" value={form.title} onChange={set('title')} maxLength={512} /></label>
      <div className="library-row">
        <label>Severity
          <select className="select-field" value={form.severity} onChange={set('severity')}>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label>CVSS<input className="input" type="number" min={0} max={10} step={0.1} value={form.cvss_score} onChange={set('cvss_score')} /></label>
        <label style={{ flex: 3 }}>CVSS vector<input className="input" value={form.cvss_vector ?? ''} onChange={set('cvss_vector')} placeholder="CVSS:3.1/AV:N/AC:L/…" /></label>
      </div>
      <label>Description<textarea className="input" rows={4} value={form.description} onChange={set('description')} /></label>
      <label>Impact<textarea className="input" rows={3} value={form.impact ?? ''} onChange={set('impact')} placeholder="What an attacker can achieve, in business terms" /></label>
      <label>Remediation<textarea className="input" rows={3} value={form.remediation ?? ''} onChange={set('remediation')} /></label>
      <label>References (one per line)<textarea className="input mono" rows={2} value={form.references} onChange={set('references')} /></label>
      <div className="library-row">
        <label>CVEs<input className="input" value={form.cve_ids} onChange={set('cve_ids')} placeholder="CVE-2021-44228, …" /></label>
        <label>Tags<input className="input" value={form.tags} onChange={set('tags')} placeholder="web, internal, …" /></label>
      </div>
      <fieldset className="library-mapping">
        <legend>Apply automatically to scanner findings (optional)</legend>
        <div className="library-row">
          <label style={{ flex: 2 }}>Plugin ids<input className="input mono" value={form.plugin_ids} onChange={set('plugin_ids')} placeholder="services.smb_signing, nessus.57608" /></label>
          <label>Only if the title contains<input className="input" value={form.title_match ?? ''} onChange={set('title_match')} /></label>
        </div>
        <p>New findings from these plugins (ScanR's own or imported, e.g. <span className="mono">nessus.&lt;pluginID&gt;</span>, <span className="mono">nuclei.&lt;template-id&gt;</span>) get this wording automatically. Their title is kept.</p>
      </fieldset>
      <div className="library-actions">
        {entry && <button type="button" className="btn btn-ghost btn-sm library-delete" onClick={() => { if (confirm(`Delete "${entry.title}"? Findings that used it keep their text.`)) remove.mutate() }}>Delete</button>}
        <span style={{ flex: 1 }} />
        <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
        <button type="button" className="btn btn-primary btn-sm" disabled={!form.title.trim() || !form.description.trim() || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : 'Save'}</button>
      </div>
    </div>
  )
}

export default function Library() {
  const qc = useQueryClient()
  const canEdit = parseJwtRole(useAuthStore(s => s.token)) !== 'viewer'
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [editing, setEditing] = useState<LibraryEntry | 'new' | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const { data: entries = [], isLoading } = useQuery({
    queryKey: ['library', q, severity],
    queryFn: () => libraryApi.list({ ...(q ? { q } : {}), ...(severity ? { severity } : {}) }),
    placeholderData: prev => prev,
  })

  const exportAll = async () => {
    const data = await libraryApi.exportAll()
    const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'scanr-finding-library.json'
    a.click()
    URL.revokeObjectURL(url)
  }
  const importFile = async (file: File) => {
    try {
      const parsed = JSON.parse(await file.text())
      const result = await libraryApi.importAll(parsed.entries ?? parsed, confirm('Overwrite entries that already exist with the same title? (Cancel keeps yours)'))
      setMessage(`Imported: ${result.added} added, ${result.updated} updated, ${result.skipped} skipped.`)
      qc.invalidateQueries({ queryKey: ['library'] })
    } catch (e) {
      setMessage(`Import failed: ${e instanceof SyntaxError ? 'not a JSON file' : apiErrorMessage(e)}`)
    }
  }

  return (
    <div className="page-pad operator-page library-page">
      <div className="operator-head">
        <div className="operator-heading"><h1>Finding library <span>{entries.length} entries</span></h1></div>
        <div className="operator-controls">
          <select value={severity} onChange={e => setSeverity(e.target.value)} className="select-field" style={{ width: 'auto' }} aria-label="Filter by severity">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <div className="search operator-search">
            <Search size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
            <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search title, text or tags" aria-label="Search the library" />
          </div>
          <button className="btn btn-sm" onClick={exportAll}><Download size={13} /> Export</button>
          {canEdit && <button className="btn btn-sm" onClick={() => fileRef.current?.click()}><Upload size={13} /> Import</button>}
          {canEdit && <button className="btn btn-primary btn-sm" onClick={() => setEditing('new')}><Plus size={13} /> New entry</button>}
          <input ref={fileRef} type="file" accept=".json,application/json" hidden onChange={e => { const f = e.target.files?.[0]; if (f) importFile(f); e.target.value = '' }} />
        </div>
      </div>
      <p className="library-intro">Reviewed write-ups your team reuses. Use them when adding a finding or editing one, and map them to scanner plugins so new findings get the same wording automatically.</p>
      {message && <div className="library-message" role="status">{message}</div>}
      <div className="library-layout">
        <div className="panel operator-table-panel">
          <table className="tbl">
            <thead><tr><th>Severity</th><th>Title</th><th>Tags</th><th>Auto-applies to</th><th>Used</th></tr></thead>
            <tbody>
              {entries.map(e => (
                <tr key={e.id} onClick={() => canEdit && setEditing(e)} className={editing !== 'new' && editing?.id === e.id ? 'is-selected' : ''}>
                  <td><SevTag severity={e.severity} /></td>
                  <td className="library-title">{e.title}</td>
                  <td className="dimmer" style={{ fontSize: 11 }}>{e.tags.join(', ') || '–'}</td>
                  <td className="mono dimmer" style={{ fontSize: 11 }}>{e.plugin_ids.length ? `${e.plugin_ids.join(', ')}${e.title_match ? ` ("${e.title_match}")` : ''}` : '–'}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{e.usage_count}</td>
                </tr>
              ))}
              {!isLoading && entries.length === 0 && <tr><td colSpan={5} className="dimmer" style={{ padding: 32, textAlign: 'center' }}>No library entries match.</td></tr>}
            </tbody>
          </table>
        </div>
        {editing && <Editor key={editing === 'new' ? 'new' : editing.id} entry={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />}
      </div>
    </div>
  )
}
