import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { findingsApi } from '@/api/findings'
import type { LibraryEntry } from '@/api/library'
import LibraryPicker from '@/components/LibraryPicker'
import { apiErrorMessage } from '@/utils/apiError'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

/** Add a manually found issue to a scan, starting from a library entry or blank. */
export default function AddFindingModal({ scanId, hosts, onClose }: { scanId: string; hosts: string[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [entry, setEntry] = useState<LibraryEntry | null>(null)
  const [form, setForm] = useState({ title: '', severity: 'medium', description: '', impact: '', remediation: '', evidence: '', host: hosts[0] ?? '', port: '', cvss: '' })
  const [error, setError] = useState<string | null>(null)
  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm(f => ({ ...f, [key]: e.target.value }))

  const pick = (picked: LibraryEntry) => {
    setEntry(picked)
    setForm(f => ({
      ...f, title: picked.title, severity: picked.severity, description: picked.description,
      impact: picked.impact ?? '', remediation: picked.remediation ?? '', cvss: picked.cvss_score?.toString() ?? '',
    }))
  }

  const create = useMutation({
    mutationFn: () => findingsApi.createManual(scanId, {
      ...(entry ? { template_id: entry.id } : {}),
      title: form.title, severity: form.severity, description: form.description,
      ...(form.impact ? { impact: form.impact } : {}),
      ...(form.remediation ? { remediation: form.remediation } : {}),
      ...(form.evidence ? { evidence: form.evidence } : {}),
      ...(form.host ? { host: form.host.trim() } : {}),
      ...(form.port ? { port_number: Number(form.port) } : {}),
      ...(form.cvss ? { cvss_score: Number(form.cvss) } : {}),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['scan', scanId] })
      qc.invalidateQueries({ queryKey: ['library'] })
      onClose()
    },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })

  return (
    <div className="operator-modal import-modal" role="dialog" aria-modal="true" aria-labelledby="add-finding-title" onClick={onClose}>
      <div className="import-modal-card add-finding-card" onClick={e => e.stopPropagation()}>
        <header>
          <h2 id="add-finding-title">Add finding</h2>
          <button type="button" className="btn btn-ghost btn-icon btn-sm" aria-label="Close" onClick={onClose}><X size={14} /></button>
        </header>
        <div className="add-finding-grid">
          <div>
            <p className="dimmer">Start from the finding library, or write it from scratch.</p>
            <LibraryPicker onPick={pick} selectedId={entry?.id} />
          </div>
          <form className="finding-editor" onSubmit={e => { e.preventDefault(); create.mutate() }}>
            {error && <div className="finding-editor-error" role="alert">{error}</div>}
            <label>Title<input className="input" value={form.title} onChange={set('title')} required maxLength={512} /></label>
            <div className="finding-editor-row">
              <label>Severity
                <select className="select-field" value={form.severity} onChange={set('severity')}>{SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}</select>
              </label>
              <label>CVSS<input className="input" type="number" min={0} max={10} step={0.1} value={form.cvss} onChange={set('cvss')} /></label>
            </div>
            <div className="finding-editor-row">
              <label style={{ flex: 2 }}>Host (IP or name)
                <input className="input mono" list="add-finding-hosts" value={form.host} onChange={set('host')} />
                <datalist id="add-finding-hosts">{hosts.map(h => <option key={h} value={h} />)}</datalist>
              </label>
              <label>Port<input className="input mono" type="number" min={0} max={65535} value={form.port} onChange={set('port')} /></label>
            </div>
            <label>Description<textarea className="input" rows={4} value={form.description} onChange={set('description')} required /></label>
            <label>Impact<textarea className="input" rows={2} value={form.impact} onChange={set('impact')} /></label>
            <label>Remediation<textarea className="input" rows={2} value={form.remediation} onChange={set('remediation')} /></label>
            <label>Evidence (what you observed on this host)<textarea className="input mono" rows={4} value={form.evidence} onChange={set('evidence')} /></label>
            <div className="finding-editor-actions">
              <span style={{ flex: 1 }} />
              <button type="button" className="btn btn-ghost btn-sm" onClick={onClose}>Cancel</button>
              <button type="submit" className="btn btn-primary btn-sm" disabled={create.isPending || !form.title.trim() || !form.description.trim()}>{create.isPending ? 'Adding…' : 'Add finding'}</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
