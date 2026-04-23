/** Shared design-system primitives for the ScanR dark theme. */
import type { ReactNode } from 'react'

/* ── Status pill ────────────────────────────── */
export function StatusPill({ status }: { status: string }) {
  const cls: Record<string, string> = {
    running:   'pill-running',
    completed: 'pill-completed',
    pending:   'pill-pending',
    failed:    'pill-failed',
    cancelled: 'pill-cancelled',
    paused:    'pill-cancelled',
  }
  return (
    <span className={`pill ${cls[status] ?? ''}`}>
      {status === 'running' && (
        <span className="live-dot" style={{ width: 5, height: 5, boxShadow: 'none' }} />
      )}
      {status}
    </span>
  )
}

/* ── Severity tag ────────────────────────────── */
export function SevTag({ severity }: { severity: string }) {
  return <span className={`sev-tag ${severity}`}>{severity}</span>
}

/* ── Severity bar strip ──────────────────────── */
export function SeverityBar({
  c = 0, h = 0, m = 0, l = 0, i = 0,
}: { c?: number; h?: number; m?: number; l?: number; i?: number }) {
  const total = c + h + m + l + i
  if (!total) return <div style={{ height: 6, background: 'var(--bg-2)', borderRadius: 3 }} />
  return (
    <div style={{ height: 6, display: 'flex', gap: 1, borderRadius: 3, overflow: 'hidden' }}>
      {c > 0 && <div style={{ flex: c, background: 'var(--sev-critical)' }} />}
      {h > 0 && <div style={{ flex: h, background: 'var(--sev-high)' }} />}
      {m > 0 && <div style={{ flex: m, background: 'var(--sev-medium)' }} />}
      {l > 0 && <div style={{ flex: l, background: 'var(--sev-low)' }} />}
      {i > 0 && <div style={{ flex: i, background: 'var(--sev-info)' }} />}
    </div>
  )
}

/* ── C/H/M/L inline counts ───────────────────── */
export function CHML({
  c = 0, h = 0, m = 0, l = 0,
}: { c?: number; h?: number; m?: number; l?: number }) {
  const parts = [
    { k: 'C', v: c, sev: 'critical' },
    { k: 'H', v: h, sev: 'high' },
    { k: 'M', v: m, sev: 'medium' },
    { k: 'L', v: l, sev: 'low' },
  ]
  return (
    <span className="mono" style={{ fontSize: 11, display: 'inline-flex', gap: 8 }}>
      {parts.map(({ k, v, sev }) => (
        <span key={k} style={{ color: v > 0 ? `var(--sev-${sev})` : 'var(--text-3)' }}>
          {k}:{v}
        </span>
      ))}
    </span>
  )
}

/* ── Meter ───────────────────────────────────── */
export function Meter({ value, color }: { value: number; color?: string }) {
  return (
    <div className="meter">
      <span style={{ width: `${Math.round(value * 100)}%`, background: color ?? 'var(--accent)' }} />
    </div>
  )
}

/* ── Sparkline ───────────────────────────────── */
export function Spark({
  data, color = 'var(--accent)', height = 32, width = 80,
}: { data: number[]; color?: string; height?: number; width?: number }) {
  if (data.length < 2) return null
  const max = Math.max(...data, 1)
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width
    const y = height - (v / max) * (height - 4) - 2
    return `${x},${y}`
  }).join(' ')
  const area = `0,${height} ${pts} ${width},${height}`
  return (
    <svg width={width} height={height} style={{ display: 'block', flexShrink: 0 }}>
      <polygon points={area} fill={color} opacity="0.12" />
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.4" />
    </svg>
  )
}

/* ── Relative time ───────────────────────────── */
export function relTime(iso?: string | null): string {
  if (!iso) return '—'
  const s = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 1000))
  if (s < 60) return `${s}s ago`
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.round(h / 24)}d ago`
}

/* ── Format duration ─────────────────────────── */
export function fmtDuration(s?: number | null): string {
  if (!s) return '—'
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60), sec = s % 60
  if (m < 60) return `${m}m ${sec}s`
  const h = Math.floor(m / 60), min = m % 60
  return `${h}h ${min}m`
}

/* ── Panel ───────────────────────────────────── */
export function Panel({
  children, className = '', style,
}: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <div className={`panel ${className}`} style={style}>
      {children}
    </div>
  )
}

/* ── PanelHead ───────────────────────────────── */
export function PanelHead({
  children, className = '',
}: { children: ReactNode; className?: string }) {
  return <div className={`panel-head ${className}`}>{children}</div>
}

/* ── Section label ───────────────────────────── */
export function SectionTitle({ children }: { children: ReactNode }) {
  return <div className="panel-title">{children}</div>
}

/* ── Avatar ──────────────────────────────────── */
export function Avatar({ initials = 'AD' }: { initials?: string }) {
  return (
    <span style={{
      width: 26, height: 26, borderRadius: '50%',
      background: 'var(--accent)',
      color: 'oklch(0.14 0.01 255)',
      fontSize: 10, fontWeight: 700,
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'var(--font-mono)',
      flexShrink: 0,
    }}>
      {initials}
    </span>
  )
}

/* ── Highlight console message ───────────────── */
export function HighlightMsg({ msg }: { msg: string }) {
  const parts = msg.split(/(\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b|\d+\/tcp|\bCVE-\d+-\d+\b)/g)
  return (
    <>
      {parts.map((p, i) =>
        /\d{1,3}(\.\d{1,3}){3}/.test(p)
          ? <span key={i} className="host">{p}</span>
          : /\d+\/tcp/.test(p)
            ? <span key={i} className="port-ref">{p}</span>
            : /^CVE-/.test(p)
              ? <span key={i} style={{ color: 'var(--sev-high)' }}>{p}</span>
              : <span key={i}>{p}</span>
      )}
    </>
  )
}

/* ── Empty state ─────────────────────────────── */
export function EmptyState({
  icon, message, action,
}: { icon: ReactNode; message: string; action?: ReactNode }) {
  return (
    <tr>
      <td colSpan={20}>
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          padding: '48px 20px', gap: 10, color: 'var(--text-2)',
        }}>
          <div style={{ color: 'var(--text-3)' }}>{icon}</div>
          <div style={{ fontSize: 12.5 }}>{message}</div>
          {action}
        </div>
      </td>
    </tr>
  )
}
