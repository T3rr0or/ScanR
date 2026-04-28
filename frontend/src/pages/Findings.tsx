import { useState, useEffect, useRef, type CSSProperties } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsApi, type Finding } from '@/api/findings'
import { scansApi } from '@/api/scans'
import { SevTag, relTime, EmptyState } from '@/components/ui'

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info']

type TriageFilter = 'all' | 'open' | 'false_positive' | 'accepted_risk' | 'resolved'

function safeParse(s: string | null): string[] {
  if (!s) return []
  try { return JSON.parse(s) } catch { return [] }
}

function statusPillClass(status: string, fp: boolean): string {
  if (fp) return 'pill pill-cancelled'
  switch (status) {
    case 'resolved':      return 'pill pill-completed'
    case 'accepted_risk': return 'pill pill-pending'
    default:              return 'pill'
  }
}

function statusLabel(f: Finding): string {
  if (f.false_positive) return 'false positive'
  switch (f.remediation_status) {
    case 'resolved':      return 'resolved'
    case 'accepted_risk': return 'accepted risk'
    default:              return 'open'
  }
}

/* ─── Compliance tag chips ─────────────────────── */
function ComplianceTags({ raw }: { raw: string | null }) {
  const tags = safeParse(raw)
  if (!tags.length) return <span style={{ color: 'var(--text-3)' }}>—</span>
  const chipStyle: CSSProperties = {
    fontSize: 10,
    background: 'var(--bg-3)',
    color: 'var(--text-2)',
    padding: '1px 4px',
    borderRadius: 3,
    fontFamily: 'var(--font-mono)',
  }
  return (
    <span style={{ display: 'inline-flex', gap: 3, alignItems: 'center', flexWrap: 'wrap' }}>
      {tags.slice(0, 2).map(t => <span key={t} style={chipStyle}>{t}</span>)}
      {tags.length > 2 && <span style={{ ...chipStyle, color: 'var(--text-3)' }}>+{tags.length - 2}</span>}
    </span>
  )
}

/* ─── FindingDrawer ────────────────────────────── */
function FindingDrawer({
  finding,
  onClose,
}: {
  finding: Finding
  onClose: () => void
}) {
  const qc = useQueryClient()
  const [notes, setNotes] = useState(finding.analyst_notes ?? '')

  useEffect(() => {
    setNotes(finding.analyst_notes ?? '')
  }, [finding.id])

  const [drawerErr, setDrawerErr] = useState<string | null>(null)
  const _onErr = (e: unknown) => setDrawerErr(e instanceof Error ? e.message : String(e))

  const notesMut = useMutation({
    mutationFn: (v: string) => findingsApi.update(finding.id, { analyst_notes: v }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings'] }); setDrawerErr(null) },
    onError: _onErr,
  })

  const fpMut = useMutation({
    mutationFn: () => findingsApi.update(finding.id, { false_positive: !finding.false_positive }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings'] }); setDrawerErr(null) },
    onError: _onErr,
  })

  const cveIds = safeParse(finding.cve_ids)
  const mitreTags = safeParse(finding.mitre_tags)
  const compTags = safeParse(finding.compliance_tags)
  const refs = safeParse(finding.references)

  return (
    <div
      className="panel"
      style={{
        width: 380,
        flexShrink: 0,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        maxHeight: '100%',
      }}
    >
      {drawerErr && <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '6px 10px', fontSize: 12 }}>{drawerErr}</div>}
      {/* Header */}
      <div
        style={{
          padding: '12px 14px',
          borderBottom: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 8,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <SevTag severity={finding.severity} />
            <span className={statusPillClass(finding.remediation_status, finding.false_positive)}>
              {statusLabel(finding)}
            </span>
          </div>
          <div
            style={{
              fontSize: 13,
              fontWeight: 600,
              color: 'var(--text-0)',
              lineHeight: 1.35,
              wordBreak: 'break-word',
              whiteSpace: 'normal',
            }}
          >
            {finding.title}
          </div>
        </div>
        <button className="btn btn-icon btn-ghost" onClick={onClose} style={{ flexShrink: 0, marginTop: 2 }}>
          ×
        </button>
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflow: 'auto', padding: '14px' }}>

        {/* Meta row */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '8px 12px',
            marginBottom: 16,
            fontSize: 11.5,
          }}
        >
          {finding.host_ip && (
            <>
              <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>Host</span>
              <span className="mono" style={{ color: 'var(--text-1)', fontSize: 11 }}>{finding.host_ip}</span>
            </>
          )}
          {finding.port_number != null && (
            <>
              <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>Port</span>
              <span className="mono" style={{ color: 'var(--text-1)', fontSize: 11 }}>{finding.port_number}/{finding.protocol}</span>
            </>
          )}
          {finding.cvss_score != null && (
            <>
              <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>CVSS</span>
              <span className="mono" style={{ color: 'var(--text-1)', fontSize: 11 }}>{finding.cvss_score.toFixed(1)}</span>
            </>
          )}
          {finding.plugin_id && (
            <>
              <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>Plugin</span>
              <span className="mono" style={{ color: 'var(--text-1)', fontSize: 11 }}>{finding.plugin_id}</span>
            </>
          )}
          <>
            <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>First Seen</span>
            <span style={{ color: 'var(--text-1)', fontSize: 11 }}>{relTime(finding.created_at)}</span>
          </>
          <>
            <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>Status</span>
            <span className={statusPillClass(finding.remediation_status, finding.false_positive)} style={{ alignSelf: 'center' }}>
              {statusLabel(finding)}
            </span>
          </>
          {finding.triaged_by && (
            <>
              <span style={{ color: 'var(--text-3)', fontWeight: 600, textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.06em' }}>Triaged By</span>
              <span style={{ color: 'var(--text-1)', fontSize: 11 }}>{finding.triaged_by}</span>
            </>
          )}
        </div>

        {/* Description */}
        {finding.description && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">Description</div>
            <p style={{ fontSize: 12.5, color: 'var(--text-1)', lineHeight: 1.6, whiteSpace: 'pre-wrap', margin: 0 }}>
              {finding.description}
            </p>
          </div>
        )}

        {/* Evidence */}
        {finding.evidence && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">Evidence</div>
            <pre
              className="mono"
              style={{
                background: 'oklch(0.12 0.008 255)',
                color: 'var(--text-1)',
                borderRadius: 6,
                padding: '10px 12px',
                fontSize: 11,
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                margin: 0,
              }}
            >
              {finding.evidence}
            </pre>
          </div>
        )}

        {/* Remediation */}
        {finding.remediation && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">Remediation</div>
            <div
              style={{
                background: 'oklch(0.75 0.15 145 / 0.08)',
                borderLeft: '3px solid var(--ok)',
                padding: '8px 12px',
                borderRadius: '0 4px 4px 0',
                fontSize: 12.5,
                color: 'var(--text-1)',
                lineHeight: 1.55,
              }}
            >
              {finding.remediation}
            </div>
          </div>
        )}

        {/* CVE IDs */}
        {cveIds.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">CVE IDs</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {cveIds.map(id => (
                <span
                  key={id}
                  className="mono"
                  style={{
                    fontSize: 11,
                    color: 'var(--sev-high)',
                    background: 'oklch(0.68 0.21 27 / 0.10)',
                    border: '1px solid oklch(0.68 0.21 27 / 0.25)',
                    padding: '1px 6px',
                    borderRadius: 3,
                  }}
                >
                  {id}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* MITRE ATT&CK */}
        {mitreTags.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">MITRE ATT&amp;CK</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {mitreTags.map(t => (
                <span
                  key={t}
                  className="mono"
                  style={{
                    fontSize: 11,
                    color: 'var(--sev-medium)',
                    background: 'oklch(0.80 0.16 70 / 0.10)',
                    border: '1px solid oklch(0.80 0.16 70 / 0.25)',
                    padding: '1px 6px',
                    borderRadius: 3,
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Compliance Tags */}
        {compTags.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">Compliance</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {compTags.map(t => (
                <span
                  key={t}
                  className="mono"
                  style={{
                    fontSize: 11,
                    color: 'var(--accent)',
                    background: 'var(--accent-soft)',
                    border: '1px solid oklch(0.78 0.14 200 / 0.25)',
                    padding: '1px 6px',
                    borderRadius: 3,
                  }}
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* References */}
        {refs.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div className="label">References</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {refs.map(url => (
                <a
                  key={url}
                  href={url}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    fontSize: 11.5,
                    color: 'var(--accent)',
                    textDecoration: 'none',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                    display: 'block',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                  onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}
                >
                  {url}
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Analyst Notes */}
        <div style={{ marginBottom: 14 }}>
          <div className="label">Analyst Notes</div>
          <textarea
            className="textarea"
            value={notes}
            onChange={e => setNotes(e.target.value)}
            onBlur={() => {
              if (notes !== (finding.analyst_notes ?? '')) notesMut.mutate(notes)
            }}
            placeholder="Add analyst notes…"
            rows={4}
            style={{ width: '100%', resize: 'vertical' }}
          />
          {notesMut.isPending && (
            <span className="dimmer" style={{ fontSize: 10 }}>Saving…</span>
          )}
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => fpMut.mutate()}
            disabled={fpMut.isPending}
          >
            {finding.false_positive ? 'Unmark False Positive' : 'Mark False Positive'}
          </button>
        </div>
      </div>
    </div>
  )
}

/* ─── Main page ────────────────────────────────── */
export default function Findings() {
  const [severity, setSeverity] = useState('')
  const [scanId, setScanId] = useState('')
  const [search, setSearch] = useState('')
  const [triageStatus, setTriageStatus] = useState<TriageFilter>('all')
  const [complianceTag, setComplianceTag] = useState('')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<Finding | null>(null)
  const selectAllRef = useRef<HTMLInputElement>(null)
  const qc = useQueryClient()

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', 0],
    queryFn: () => scansApi.list({ limit: 200 }),
  })

  const apiParams: Record<string, string> = {}
  if (severity) apiParams.severity = severity
  if (scanId) apiParams.scan_id = scanId
  if (complianceTag) apiParams.compliance_tag = complianceTag

  const { data: rawFindings = [] } = useQuery({
    queryKey: ['findings', severity, scanId, complianceTag],
    queryFn: () => findingsApi.list(Object.keys(apiParams).length ? apiParams : undefined),
  })

  // Client-side filters: triage status + search
  const findings = rawFindings.filter(f => {
    // Triage filter
    if (triageStatus === 'open' && !(f.remediation_status === 'open' && !f.false_positive)) return false
    if (triageStatus === 'false_positive' && !f.false_positive) return false
    if (triageStatus === 'accepted_risk' && f.remediation_status !== 'accepted_risk') return false
    if (triageStatus === 'resolved' && f.remediation_status !== 'resolved') return false
    // Search filter
    if (search) {
      const q = search.toLowerCase()
      if (
        !f.title.toLowerCase().includes(q) &&
        !(f.host_ip ?? '').toLowerCase().includes(q) &&
        !(f.plugin_id ?? '').toLowerCase().includes(q)
      ) return false
    }
    return true
  })

  // Bulk mutations
  const [bulkErr, setBulkErr] = useState<string | null>(null)
  const _onBulkErr = (e: unknown) => setBulkErr(e instanceof Error ? e.message : String(e))

  const bulkFpMut = useMutation({
    mutationFn: (ids: string[]) => findingsApi.bulkUpdate(ids, { false_positive: true }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings'] }); setSelectedIds(new Set()); setBulkErr(null) },
    onError: _onBulkErr,
  })

  const bulkArMut = useMutation({
    mutationFn: (ids: string[]) => findingsApi.bulkUpdate(ids, { remediation_status: 'accepted_risk' }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings'] }); setSelectedIds(new Set()); setBulkErr(null) },
    onError: _onBulkErr,
  })

  // Select-all checkbox indeterminate state
  const visibleIds = findings.map(f => f.id)
  const selectedVisible = visibleIds.filter(id => selectedIds.has(id))
  const allSelected = visibleIds.length > 0 && selectedVisible.length === visibleIds.length
  const someSelected = selectedVisible.length > 0 && !allSelected

  useEffect(() => {
    if (selectAllRef.current) {
      selectAllRef.current.indeterminate = someSelected
    }
  }, [someSelected])

  function toggleRow(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleAll() {
    if (allSelected) {
      setSelectedIds(prev => {
        const next = new Set(prev)
        visibleIds.forEach(id => next.delete(id))
        return next
      })
    } else {
      setSelectedIds(prev => {
        const next = new Set(prev)
        visibleIds.forEach(id => next.add(id))
        return next
      })
    }
  }

  const bulkIds = [...selectedIds]

  return (
    <div
      className="page-pad"
      style={{
        display: 'flex',
        gap: 16,
        height: '100%',
        boxSizing: 'border-box',
        overflow: 'hidden',
      }}
    >
      {/* ── Left: table column ── */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden' }}>
        {bulkErr && <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>{bulkErr}</div>}

        {/* Page title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Findings</h1>
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)' }}>
            {findings.length} result{findings.length !== 1 ? 's' : ''}
          </span>
        </div>

        {/* Filter bar */}
        <div className="filter-bar">
          {/* Search */}
          <div className="search" style={{ flex: 1, minWidth: 140, maxWidth: 260 }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ color: 'var(--text-3)', flexShrink: 0 }}>
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search findings…"
              style={{ minWidth: 0 }}
            />
          </div>

          {/* Scan filter */}
          <select
            className="select-field"
            value={scanId}
            onChange={e => setScanId(e.target.value)}
            style={{ width: 'auto', minWidth: 110 }}
          >
            <option value="">All scans</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>

          {/* Severity filter */}
          <select
            className="select-field"
            value={severity}
            onChange={e => setSeverity(e.target.value)}
            style={{ width: 'auto', minWidth: 120 }}
          >
            {SEVERITIES.map(s => (
              <option key={s} value={s}>{s || 'All severities'}</option>
            ))}
          </select>

          {/* Compliance filter */}
          <select
            className="select-field"
            value={complianceTag}
            onChange={e => setComplianceTag(e.target.value)}
            style={{ width: 'auto', minWidth: 120 }}
          >
            <option value="">Compliance</option>
            <option value="PCI-DSS">PCI-DSS</option>
            <option value="ISO27001">ISO 27001</option>
            <option value="CIS">CIS</option>
            <option value="NIST">NIST</option>
          </select>

          {/* Triage status filter */}
          <select
            className="select-field"
            value={triageStatus}
            onChange={e => setTriageStatus(e.target.value as TriageFilter)}
            style={{ width: 'auto', minWidth: 130 }}
          >
            <option value="all">All statuses</option>
            <option value="open">Open</option>
            <option value="false_positive">False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>

        {/* Bulk action toolbar */}
        {selectedIds.size > 0 && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              background: 'var(--accent-soft)',
              border: '1px solid var(--border-strong)',
              borderRadius: 6,
              padding: '8px 12px',
            }}
          >
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)', marginRight: 4 }}>
              {selectedIds.size} selected
            </span>
            <button
              className="btn btn-sm"
              onClick={() => bulkFpMut.mutate(bulkIds)}
              disabled={bulkFpMut.isPending}
            >
              Mark False Positive ({selectedIds.size})
            </button>
            <button
              className="btn btn-sm"
              onClick={() => bulkArMut.mutate(bulkIds)}
              disabled={bulkArMut.isPending}
            >
              Mark Accepted Risk ({selectedIds.size})
            </button>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setSelectedIds(new Set())}
              style={{ marginLeft: 'auto' }}
            >
              Clear Selection
            </button>
          </div>
        )}

        {/* Table */}
        <div className="panel" style={{ flex: 1, overflow: 'auto' }}>
          <table className="tbl">
            <thead>
              <tr>
                <th style={{ width: 36, paddingLeft: 14, paddingRight: 6 }}>
                  <input
                    ref={selectAllRef}
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                    style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                  />
                </th>
                <th>Severity</th>
                <th>Title</th>
                <th>Host</th>
                <th>Port</th>
                <th>CVSS</th>
                <th>Status</th>
                <th>Tags</th>
              </tr>
            </thead>
            <tbody>
              {findings.length === 0 && (
                <EmptyState
                  icon={
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                      <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
                    </svg>
                  }
                  message="No findings match the current filters"
                />
              )}
              {findings.map(f => {
                const isSelected = selectedIds.has(f.id)
                const isActive = selected?.id === f.id
                return (
                  <tr
                    key={f.id}
                    className={isSelected || isActive ? 'selected' : ''}
                    style={{ opacity: f.false_positive ? 0.5 : 1 }}
                    onClick={() => setSelected(f)}
                  >
                    {/* Checkbox cell — stop propagation so clicking the checkbox doesn't open the drawer */}
                    <td
                      style={{ paddingLeft: 14, paddingRight: 6 }}
                      onClick={e => { e.stopPropagation(); toggleRow(f.id) }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleRow(f.id)}
                        onClick={e => e.stopPropagation()}
                        style={{ cursor: 'pointer', accentColor: 'var(--accent)' }}
                      />
                    </td>
                    <td><SevTag severity={f.severity} /></td>
                    <td
                      style={{
                        maxWidth: 260,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        fontWeight: 500,
                        color: 'var(--text-0)',
                      }}
                    >
                      {f.title}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)' }}>
                      {f.host_ip ?? '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)' }}>
                      {f.port_number != null ? `${f.port_number}/${f.protocol}` : '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-1)' }}>
                      {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                    </td>
                    <td>
                      <span className={statusPillClass(f.remediation_status, f.false_positive)}>
                        {statusLabel(f)}
                      </span>
                    </td>
                    <td>
                      <ComplianceTags raw={f.compliance_tags} />
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Right: detail drawer ── */}
      {selected && (
        <FindingDrawer
          finding={selected}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}
