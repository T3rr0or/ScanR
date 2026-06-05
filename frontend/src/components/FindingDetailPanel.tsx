/**
 * FindingDetailPanel — slide-in drawer showing full finding details.
 * Reused across Assets, Vulnerabilities, and any other finding list.
 */
import { X, ExternalLink } from 'lucide-react'
import { SevTag } from '@/components/ui'
import type { Finding } from '@/api/findings'

interface Props {
  finding: Finding | null
  onClose: () => void
}

function safeParse(s: string | null | undefined): string[] {
  if (!s) return []
  try { return JSON.parse(s) } catch { return [] }
}

export default function FindingDetailPanel({ finding, onClose }: Props) {
  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 60,
          background: 'oklch(0.05 0.01 255 / 0.55)',
          opacity: finding ? 1 : 0,
          transition: 'opacity 0.2s ease',
          pointerEvents: finding ? 'auto' : 'none',
        }}
      />
      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, zIndex: 61,
        width: 'min(520px, 92vw)',
        background: 'var(--bg-1)',
        borderLeft: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column',
        transform: finding ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform 0.26s cubic-bezier(0.32, 0.72, 0, 1)',
        boxShadow: '-12px 0 40px #0009',
        overflow: 'hidden',
        pointerEvents: finding ? 'auto' : 'none',
      }}>
        {finding && <PanelBody finding={finding} onClose={onClose} />}
      </div>
    </>
  )
}

function PanelBody({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const refs = safeParse(finding.references)
  const cves = safeParse(finding.cve_ids)
  const complianceTags = safeParse((finding as any).compliance_tags)

  return (
    <>
      {/* Header */}
      <div style={{
        padding: '14px 16px',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'flex-start', gap: 10,
        flexShrink: 0,
      }}>
        <SevTag severity={finding.severity as any} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', lineHeight: 1.4 }}>
            {finding.title}
          </div>
          <div className="mono dimmer" style={{ fontSize: 10, marginTop: 3 }}>
            {finding.host_ip ?? '—'}
            {finding.port_number ? `:${finding.port_number}/${finding.protocol}` : ''}
            {' · '}{finding.plugin_id}
          </div>
        </div>
        <button onClick={onClose} className="btn btn-ghost btn-icon btn-sm" style={{ flexShrink: 0 }}>
          <X size={13} />
        </button>
      </div>

      {/* Scrollable body */}
      <div style={{ flex: 1, overflow: 'auto', padding: '16px', display: 'flex', flexDirection: 'column', gap: 18 }}>

        {/* Metadata row */}
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {finding.cvss_score != null && (
            <MetaPill label="CVSS" value={finding.cvss_score.toFixed(1)} />
          )}
          {finding.vpr_score != null && (
            <MetaPill label="VPR" value={finding.vpr_score.toFixed(1)} color={finding.vpr_score >= 8 ? 'var(--sev-critical)' : finding.vpr_score >= 5 ? 'var(--sev-high)' : 'var(--sev-medium)'} />
          )}
          {cves.map(c => <MetaPill key={c} label="CVE" value={c} />)}
          <MetaPill label="Status" value={finding.false_positive ? 'False Positive' : finding.remediation_status ?? 'open'} />
        </div>

        {finding.description && (
          <Section label="Description">
            <p style={{ fontSize: 12, color: 'var(--text-1)', lineHeight: 1.7, margin: 0 }}>
              {finding.description}
            </p>
          </Section>
        )}

        {finding.evidence && (
          <Section label="Evidence">
            <pre style={{
              fontSize: 10.5, background: 'var(--bg-0)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '10px 12px', margin: 0, overflow: 'auto',
              color: 'var(--text-1)', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
              maxHeight: 320,
            }}>
              {finding.evidence}
            </pre>
          </Section>
        )}

        {finding.remediation && (
          <Section label="Remediation">
            <p style={{ fontSize: 12, color: 'var(--text-1)', lineHeight: 1.7, margin: 0 }}>
              {finding.remediation}
            </p>
          </Section>
        )}

        {complianceTags.length > 0 && (
          <Section label="Compliance">
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {complianceTags.map((t: string) => (
                <span key={t} style={{ fontSize: 10, background: 'var(--bg-3)', color: 'var(--text-2)', padding: '2px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)' }}>{t}</span>
              ))}
            </div>
          </Section>
        )}

        {refs.length > 0 && (
          <Section label="References">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {refs.map((r: string, i: number) => (
                <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize: 11, color: 'var(--accent)', display: 'flex', alignItems: 'flex-start', gap: 5, wordBreak: 'break-all', lineHeight: 1.5 }}>
                  <ExternalLink size={10} style={{ flexShrink: 0, marginTop: 2 }} />
                  {r}
                </a>
              ))}
            </div>
          </Section>
        )}
      </div>
    </>
  )
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="label" style={{ marginBottom: 6 }}>{label}</div>
      {children}
    </section>
  )
}

function MetaPill({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
      <span style={{ color: 'var(--text-3)' }}>{label}</span>
      <span className="mono" style={{ color: color ?? 'var(--text-1)', background: 'var(--bg-0)', padding: '1px 6px', borderRadius: 3, border: '1px solid var(--border)' }}>{value}</span>
    </div>
  )
}
