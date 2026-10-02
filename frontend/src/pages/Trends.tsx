import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Download } from 'lucide-react'
import { exposureTrend, type ExposurePoint, type ExposureTrend, type TrendSeverity } from '@/api/analytics'
import { SevTag } from '@/components/ui'
import { PriorityBadge } from '@/components/Priority'
import './OperatorPages.css'
import './Trends.css'

const RANGES = [4, 12, 26, 52]
const SEVERITIES: TrendSeverity[] = ['critical', 'high', 'medium', 'low']

function fmtDate(iso: string) {
  return new Date(`${iso}T00:00:00`).toLocaleDateString(undefined, { day: 'numeric', month: 'short' })
}

function days(value: number | null | undefined) {
  return value == null ? '–' : `${value < 10 ? value.toFixed(1) : Math.round(value)} d`
}

function pct(value: number | null | undefined) {
  return value == null ? '–' : `${Math.round(value * 100)}%`
}

/** One severity, open issues per week. A single series: the panel title names it. */
/** Track an element's pixel width, so SVG text stays at its CSS size at any width. */
function useWidth(fallback: number) {
  const ref = useRef<HTMLDivElement>(null)
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const observer = new ResizeObserver(([entry]) => setWidth(Math.max(200, Math.round(entry.contentRect.width))))
    observer.observe(el)
    return () => observer.disconnect()
  }, [])
  return [ref, width] as const
}

function OpenLine({ points, field, label }: { points: ExposurePoint[]; field: TrendSeverity; label: string }) {
  const [hover, setHover] = useState<number | null>(null)
  const [plotRef, width] = useWidth(320)
  const height = 130, left = 28, right = 30, top = 10, bottom = 20
  const values = points.map(p => p[field])
  const peak = Math.max(...values, 0)
  // Even integer headroom keeps the midpoint gridline on a whole number.
  const headroom = Math.max(2, Math.ceil(peak * 1.15))
  const max = headroom + (headroom % 2)
  const x = (i: number) => left + (points.length <= 1 ? 0 : i / (points.length - 1)) * (width - left - right)
  const y = (v: number) => height - bottom - (v / max) * (height - top - bottom)
  const path = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
  const last = values.length - 1
  const first = values[0] ?? 0
  const change = (values[last] ?? 0) - first
  const onMove = (event: React.MouseEvent<SVGRectElement>) => {
    const box = event.currentTarget.getBoundingClientRect()
    const px = ((event.clientX - box.left) / box.width) * width
    const i = Math.round(((px - left) / (width - left - right)) * (points.length - 1))
    setHover(Math.max(0, Math.min(points.length - 1, i)))
  }
  return (
    <figure className="trend-panel">
      <figcaption>
        <span className={`trend-key trend-key-${field}`} aria-hidden="true" />
        <strong>{label}</strong>
        <span className="trend-now">{values[last] ?? 0} open</span>
        <span className={`trend-change ${change > 0 ? 'is-up' : change < 0 ? 'is-down' : ''}`}>
          {change === 0 ? 'no change' : `${change > 0 ? '+' : ''}${change} since ${fmtDate(points[0].date)}`}
        </span>
      </figcaption>
      <div className="trend-plot" ref={plotRef}>
        <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${label} open issues per week, ${first} to ${values[last] ?? 0}`}>
          {[0, 0.5, 1].map(t => (
            <g key={t}>
              <line x1={left} x2={width - right} y1={y(max * t)} y2={y(max * t)} className="trend-grid" />
              <text x={left - 6} y={y(max * t) + 3} textAnchor="end" className="trend-axis">{Math.round(max * t)}</text>
            </g>
          ))}
          <text x={left} y={height - 4} className="trend-axis">{fmtDate(points[0].date)}</text>
          <text x={width - right} y={height - 4} textAnchor="end" className="trend-axis">today</text>
          <path d={path} fill="none" stroke={`var(--sev-${field})`} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
          <circle cx={x(last)} cy={y(values[last] ?? 0)} r="4" fill={`var(--sev-${field})`} stroke="var(--bg-1)" strokeWidth="2" />
          <text x={x(last) + 7} y={y(values[last] ?? 0) + 4} className="trend-end">{values[last] ?? 0}</text>
          {hover != null && (
            <g pointerEvents="none">
              <line x1={x(hover)} x2={x(hover)} y1={top} y2={height - bottom} className="trend-crosshair" />
              <circle cx={x(hover)} cy={y(values[hover])} r="4" fill={`var(--sev-${field})`} stroke="var(--bg-1)" strokeWidth="2" />
            </g>
          )}
          <rect x={0} y={0} width={width} height={height} fill="transparent" onMouseMove={onMove} onMouseLeave={() => setHover(null)} />
        </svg>
        {hover != null && (
          <div className="trend-tooltip" style={{ left: `${(x(hover) / width) * 100}%` }}>
            <span>Week to {fmtDate(points[hover].date)}</span>
            <strong>{values[hover]} open</strong>
          </div>
        )}
      </div>
    </figure>
  )
}

function downloadCsv(data: ExposureTrend) {
  const header = ['week_ending', 'open_critical', 'open_high', 'open_medium', 'open_low', 'open_fix_now', 'open_kev', 'new', 'fixed']
  const rows = data.points.map(p => [p.date, p.critical, p.high, p.medium, p.low, p.fix_now, p.kev, p.new, p.fixed].join(','))
  const url = URL.createObjectURL(new Blob([[header.join(','), ...rows].join('\n') + '\n'], { type: 'text/csv' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `scanr-exposure-${data.points[data.points.length - 1]?.date ?? 'trend'}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function Trends() {
  const [weeks, setWeeks] = useState(12)
  const { data, isLoading, isError } = useQuery({
    queryKey: ['analytics', 'exposure-trend', weeks],
    queryFn: () => exposureTrend(weeks),
    placeholderData: prev => prev,
  })

  const points = data?.points ?? []
  const now = points[points.length - 1]
  const start = points[0]
  const stats = data?.by_severity
  const overdueTotal = stats ? SEVERITIES.reduce((sum, s) => sum + stats[s].overdue, 0) : 0
  const fixNowChange = now && start ? now.fix_now - start.fix_now : 0

  return (
    <div className="page-pad operator-page trends-page">
      <div className="operator-head">
        <div className="operator-heading">
          <h1>Trends <span>exposure over time</span></h1>
        </div>
        <div className="operator-controls">
          <div className="trend-range" role="group" aria-label="Time range">
            {RANGES.map(r => (
              <button key={r} className={r === weeks ? 'is-active' : ''} aria-pressed={r === weeks} onClick={() => setWeeks(r)}>
                {r < 52 ? `${r} weeks` : '1 year'}
              </button>
            ))}
          </div>
          <button className="btn btn-sm" onClick={() => data && downloadCsv(data)} disabled={!data}>
            <Download size={13} /> CSV
          </button>
        </div>
      </div>

      {isError && <div className="trend-empty">Trend data is unavailable. Check the ScanR service and retry.</div>}
      {isLoading && !data && <div className="trend-empty">Loading…</div>}

      {data && now && stats && (
        <>
          <section className="trend-tiles" aria-label="Summary">
            <div>
              <span>Fix now (priority 80+)</span>
              <strong>{now.fix_now}</strong>
              <small>{fixNowChange === 0 ? 'no change' : `${fixNowChange > 0 ? '+' : ''}${fixNowChange}`} over {weeks} weeks</small>
            </div>
            <div>
              <span>Critical + high open</span>
              <strong>{now.critical + now.high}</strong>
              <small>{now.kev} known exploited (KEV)</small>
            </div>
            <div>
              <span>Past remediation target</span>
              <strong className={overdueTotal ? 'is-alert' : ''}>{overdueTotal}</strong>
              <small>critical {stats.critical.sla_days} d · high {stats.high.sla_days} d</small>
            </div>
            <div>
              <span>Median time to fix, critical</span>
              <strong>{days(stats.critical.median_days_to_fix)}</strong>
              <small>high: {days(stats.high.median_days_to_fix)}</small>
            </div>
          </section>

          <section className="trend-grid-panels" aria-label="Open issues per week by severity">
            {SEVERITIES.map(s => <OpenLine key={s} points={points} field={s} label={s[0].toUpperCase() + s.slice(1)} />)}
          </section>
          <p className="trend-note">
            Open issues at the end of each week. An issue is the same finding on the same host and port across scans; it
            counts as fixed when a later scan ran the same check on that host and did not find it, or when it is marked resolved.
          </p>

          <section className="trend-section">
            <h2>Remediation targets</h2>
            <div className="panel operator-table-panel">
              <table className="tbl">
                <thead><tr><th>Severity</th><th>Target</th><th>Open</th><th>Past target</th><th>Fixed in range</th><th>Median to fix</th><th>Mean to fix</th><th>Fixed within target</th></tr></thead>
                <tbody>
                  {SEVERITIES.map(s => (
                    <tr key={s}>
                      <td><SevTag severity={s} /></td>
                      <td className="mono">{stats[s].sla_days} d</td>
                      <td className="mono">{stats[s].open}</td>
                      <td className={`mono ${stats[s].overdue ? 'trend-alert-text' : ''}`}>{stats[s].overdue}</td>
                      <td className="mono">{stats[s].fixed}</td>
                      <td className="mono">{days(stats[s].median_days_to_fix)}</td>
                      <td className="mono">{days(stats[s].mean_days_to_fix)}</td>
                      <td className="mono">{pct(stats[s].fixed_within_sla)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {data.overdue.length > 0 && (
            <section className="trend-section">
              <h2>Longest past target</h2>
              <div className="panel operator-table-panel">
                <table className="tbl">
                  <thead><tr><th>Priority</th><th>Severity</th><th>Issue</th><th>Location</th><th>Open for</th></tr></thead>
                  <tbody>
                    {data.overdue.map(o => (
                      <tr key={`${o.title}-${o.location}`}>
                        <td><PriorityBadge score={o.priority} kev={o.kev} /></td>
                        <td><SevTag severity={o.severity} /></td>
                        <td>{o.title}</td>
                        <td className="mono">{o.location}</td>
                        <td className="mono trend-alert-text">{Math.round(o.age_days)} d <span className="dimmer">/ {o.sla_days} d</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          <section className="trend-section">
            <h2>Week by week</h2>
            <div className="panel operator-table-panel">
              <table className="tbl">
                <thead><tr><th>Week ending</th><th>New</th><th>Fixed</th><th>Open critical</th><th>Open high</th><th>Open medium</th><th>Open low</th><th>Fix now</th></tr></thead>
                <tbody>
                  {[...points].reverse().map(p => (
                    <tr key={p.date}>
                      <td className="mono">{p.date}</td>
                      <td className="mono">{p.new}</td>
                      <td className="mono">{p.fixed}</td>
                      <td className="mono">{p.critical}</td>
                      <td className="mono">{p.high}</td>
                      <td className="mono">{p.medium}</td>
                      <td className="mono">{p.low}</td>
                      <td className="mono">{p.fix_now}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
