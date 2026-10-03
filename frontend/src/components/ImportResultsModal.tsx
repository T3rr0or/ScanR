import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, X } from 'lucide-react'
import { importsApi, type ImportFormat, type ImportSummary } from '@/api/scans'
import { apiErrorMessage } from '@/utils/apiError'

const FORMATS: { id: ImportFormat; label: string; hint: string }[] = [
  { id: 'auto', label: 'Detect automatically', hint: '' },
  { id: 'nessus', label: 'Nessus', hint: '.nessus export (v2)' },
  { id: 'nmap', label: 'Nmap', hint: 'XML output: nmap -oX' },
  { id: 'nuclei', label: 'Nuclei', hint: 'JSON lines: nuclei -jsonl -o' },
  { id: 'burp', label: 'Burp Suite', hint: 'Report → XML (issues)' },
  { id: 'zap', label: 'OWASP ZAP', hint: 'Traditional JSON report' },
]
const MAX_BYTES = 50 * 1024 * 1024

/** Import another tool's results, either as a new scan or into `scanId`. */
export default function ImportResultsModal({ scanId, onClose, onImported }: {
  scanId?: string
  onClose: () => void
  onImported?: (summary: ImportSummary) => void
}) {
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [name, setName] = useState('')
  const [format, setFormat] = useState<ImportFormat>('auto')
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<ImportSummary | null>(null)

  const mut = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('Choose a file')
      if (file.size > MAX_BYTES) throw new Error('File is larger than 50 MB')
      const report = await file.text()
      return scanId
        ? importsApi.intoScan(scanId, { report, format })
        : importsApi.asNewScan({ name: name || file.name, report, format })
    },
    onSuccess: summary => {
      setDone(summary)
      setError(null)
      qc.invalidateQueries({ queryKey: ['scans'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['scan'] })
    },
    onError: (e: unknown) => setError(e instanceof Error && !('isAxiosError' in e) ? e.message : apiErrorMessage(e)),
  })

  return (
    <div className="operator-modal import-modal" role="dialog" aria-modal="true" aria-labelledby="import-title" onClick={onClose}>
      <div className="import-modal-card" onClick={e => e.stopPropagation()}>
        <header>
          <h2 id="import-title">{scanId ? 'Import results into this scan' : 'Import results'}</h2>
          <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close" onClick={onClose}><X size={14} /></button>
        </header>
        {done ? (
          <div className="import-done">
            <p>Imported from <strong>{done.source}</strong>:</p>
            <ul>
              <li>{done.findings_added} findings{done.duplicates_skipped ? ` (${done.duplicates_skipped} already present, skipped)` : ''}</li>
              <li>{done.hosts_added} new hosts, {done.ports_added} open ports</li>
            </ul>
            <p className="dimmer">Findings are ranked by fix-first priority like ScanR's own.</p>
            <div className="import-actions">
              <button type="button" className="btn btn-primary btn-sm" onClick={() => { onImported?.(done); onClose() }}>{scanId ? 'Done' : 'Open scan'}</button>
            </div>
          </div>
        ) : (
          <form onSubmit={e => { e.preventDefault(); mut.mutate() }}>
            <p className="dimmer">Bring in results from Nessus, Nmap, Nuclei, Burp Suite or OWASP ZAP. Hosts, open ports and findings are added; importing the same file twice adds nothing new.</p>
            <label className="import-drop">
              <Upload size={16} />
              <span>{file ? `${file.name} (${(file.size / 1024).toFixed(0)} KB)` : 'Choose a report file'}</span>
              <input type="file" accept=".nessus,.xml,.json,.jsonl,.txt" onChange={e => { const f = e.target.files?.[0] ?? null; setFile(f); setDone(null); setError(null) }} />
            </label>
            {!scanId && (
              <label className="import-field">Scan name
                <input className="input" value={name} placeholder={file?.name ?? 'e.g. Nessus internal, October'} onChange={e => setName(e.target.value)} maxLength={255} />
              </label>
            )}
            <label className="import-field">Format
              <select className="select-field" value={format} onChange={e => setFormat(e.target.value as ImportFormat)}>
                {FORMATS.map(f => <option key={f.id} value={f.id}>{f.label}{f.hint ? ` — ${f.hint}` : ''}</option>)}
              </select>
            </label>
            {error && <p className="import-error" role="alert">{error}</p>}
            <div className="import-actions">
              <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn btn-primary btn-sm" disabled={!file || mut.isPending}>{mut.isPending ? 'Importing…' : 'Import'}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
