import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsApi, type Finding } from '@/api/findings'
import type { LibraryEntry } from '@/api/library'
import LibraryPicker from '@/components/LibraryPicker'
import { apiErrorMessage } from '@/utils/apiError'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

function refsOf(raw: string | null): string {
  if (!raw) return ''
  try { return (JSON.parse(raw) as string[]).join('\n') } catch { return '' }
}

/** Edit a finding's report wording, or replace it with a library entry. */
export default function FindingEditor({ finding, onDone }: { finding: Finding; onDone: () => void }) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState({
    severity: finding.severity,
    cvss_score: finding.cvss_score?.toString() ?? '',
    cvss_vector: finding.cvss_vector ?? '',
    description: finding.description ?? '',
    impact: finding.impact ?? '',
    remediation: finding.remediation ?? '',
    evidence: finding.evidence ?? '',
    references: refsOf(finding.references),
  })
  const [picking, setPicking] = useState(false)
  const [useSeverity, setUseSeverity] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const set = (key: keyof typeof draft) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setDraft(d => ({ ...d, [key]: e.target.value }))
  const refresh = () => { qc.invalidateQueries({ queryKey: ['findings'] }); qc.invalidateQueries({ queryKey: ['library'] }) }

  const save = useMutation({
    mutationFn: () => findingsApi.update(finding.id, {
      severity: draft.severity,
      ...(draft.cvss_score !== '' ? { cvss_score: Number(draft.cvss_score) } : {}),
      cvss_vector: draft.cvss_vector,
      description: draft.description,
      impact: draft.impact,
      remediation: draft.remediation,
      evidence: draft.evidence,
      references: draft.references.split('\n'),
    }),
    onSuccess: () => { refresh(); onDone() },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })
  const apply = useMutation({
    mutationFn: (entry: LibraryEntry) => findingsApi.applyTemplate(finding.id, entry.id, useSeverity),
    onSuccess: () => { refresh(); onDone() },
    onError: (e: unknown) => setError(apiErrorMessage(e)),
  })

  return (
    <div className="finding-editor">
      {error && <div className="finding-editor-error" role="alert">{error}</div>}
      {picking ? (
        <>
          <div className="finding-editor-note">Replace the description, impact, remediation and references with a reviewed library entry. The title stays; the current description moves into the evidence.</div>
          <label className="finding-editor-check"><input type="checkbox" checked={useSeverity} onChange={e => setUseSeverity(e.target.checked)} /> Also use the entry's severity</label>
          <LibraryPicker onPick={entry => apply.mutate(entry)} />
          <div className="finding-editor-actions"><button type="button" className="btn btn-ghost btn-sm" onClick={() => setPicking(false)}>Back</button></div>
        </>
      ) : (
        <>
          <div className="finding-editor-row">
            <label>Severity
              <select className="select-field" value={draft.severity} onChange={set('severity')}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
            <label>CVSS
              <input className="input" type="number" min={0} max={10} step={0.1} value={draft.cvss_score} onChange={set('cvss_score')} />
            </label>
            <label style={{ flex: 2 }}>CVSS vector
              <input className="input" value={draft.cvss_vector} onChange={set('cvss_vector')} placeholder="CVSS:3.1/AV:N/…" />
            </label>
          </div>
          <label>Description<textarea className="input" rows={4} value={draft.description} onChange={set('description')} /></label>
          <label>Impact<textarea className="input" rows={3} value={draft.impact} onChange={set('impact')} placeholder="What an attacker can achieve, in business terms" /></label>
          <label>Remediation<textarea className="input" rows={3} value={draft.remediation} onChange={set('remediation')} /></label>
          <label>Evidence<textarea className="input mono" rows={5} value={draft.evidence} onChange={set('evidence')} /></label>
          <label>References (one per line)<textarea className="input mono" rows={2} value={draft.references} onChange={set('references')} /></label>
          <div className="finding-editor-actions">
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setPicking(true)}>Use library entry…</button>
            <span style={{ flex: 1 }} />
            <button type="button" className="btn btn-ghost btn-sm" onClick={onDone}>Cancel</button>
            <button type="button" className="btn btn-primary btn-sm" onClick={() => save.mutate()} disabled={save.isPending || !draft.description.trim()}>{save.isPending ? 'Saving…' : 'Save'}</button>
          </div>
        </>
      )}
    </div>
  )
}
