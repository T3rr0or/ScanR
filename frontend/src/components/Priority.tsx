/** "Fix first" priority (0-100) and the reasons behind it. See backend scanr/core/priority.py. */

export function priorityBand(score: number | null | undefined): string | null {
  if (score == null) return null
  if (score >= 80) return 'fix now'
  if (score >= 60) return 'fix soon'
  if (score >= 40) return 'plan'
  return 'low'
}

function priorityColor(score: number): string {
  if (score >= 80) return 'var(--sev-critical)'
  if (score >= 60) return 'var(--sev-high)'
  if (score >= 40) return 'var(--sev-medium)'
  return 'var(--text-3)'
}

function formatProbability(p: number): string {
  if (p >= 0.999) return '>99.9%'
  if (p > 0 && p < 0.001) return '<0.1%'
  return `${(p * 100).toFixed(1)}%`
}

export function parseReasons(raw: string | null | undefined): string[] {
  if (!raw) return []
  try {
    const value = JSON.parse(raw)
    return Array.isArray(value) ? value.map(String) : []
  } catch {
    return []
  }
}

export function PriorityBadge({ score, kev, reasons }: { score: number | null | undefined; kev?: boolean; reasons?: string | null }) {
  if (score == null) return <span className="dimmer" style={{ fontSize: 11 }}>n/a</span>
  const color = priorityColor(score)
  const title = [`Fix-first priority ${Math.round(score)}/100 (${priorityBand(score)})`, ...parseReasons(reasons)].join('\n')
  return (
    <span title={title} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, whiteSpace: 'nowrap' }}>
      <span className="mono" style={{ fontSize: 11, fontWeight: 700, color, border: `1px solid ${color}`, padding: '1px 5px', minWidth: 26, textAlign: 'center' }}>
        {Math.round(score)}
      </span>
      {kev && <KevTag />}
    </span>
  )
}

export function KevTag() {
  return (
    <span
      title="Listed in the CISA Known Exploited Vulnerabilities catalog: attackers are using this in the wild"
      className="mono"
      style={{ fontSize: 9, fontWeight: 700, letterSpacing: '0.06em', color: '#0a0a0a', background: 'var(--sev-critical)', padding: '1px 4px' }}
    >
      KEV
    </span>
  )
}

export function PriorityExplanation({ score, reasons, epss, epssPercentile, kev }: {
  score: number | null | undefined
  reasons: string | null | undefined
  epss: number | null | undefined
  epssPercentile: number | null | undefined
  kev: boolean
}) {
  if (score == null) return null
  const list = parseReasons(reasons)
  return (
    <div style={{ border: '1px solid var(--border)', padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <PriorityBadge score={score} kev={kev} />
        <span style={{ fontSize: 12, color: 'var(--text-0)', fontWeight: 600, textTransform: 'capitalize' }}>{priorityBand(score)}</span>
        {epss != null && (
          <span className="mono dimmer" style={{ fontSize: 11, marginLeft: 'auto' }}>
            EPSS {formatProbability(epss)}{epssPercentile != null ? ` · top ${Math.max(0.1, 100 - epssPercentile * 100).toFixed(1)}%` : ''}
          </span>
        )}
      </div>
      {list.length > 0 && (
        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5, color: 'var(--text-2)', lineHeight: 1.6 }}>
          {list.map(reason => <li key={reason}>{reason}</li>)}
        </ul>
      )}
    </div>
  )
}
