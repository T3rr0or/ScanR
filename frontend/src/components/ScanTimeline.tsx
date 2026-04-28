import { useMemo } from 'react'

interface PhaseTimings {
  starts: Record<string, Date>
  ends: Record<string, Date>
}

const PHASES = ['discovery', 'portscan', 'fingerprint', 'plugin', 'engine'] as const
const PHASE_LABELS: Record<string, string> = {
  discovery:   'Discovery',
  portscan:    'Port Scan',
  fingerprint: 'Fingerprint',
  plugin:      'Plugins',
  engine:      'Engine',
}
const PHASE_COLORS: Record<string, string> = {
  discovery:   'var(--accent)',
  portscan:    'var(--accent-2)',
  fingerprint: 'var(--ok)',
  plugin:      'var(--sev-medium)',
  engine:      'var(--text-3)',
}

function fmtDur(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

export default function ScanTimeline({ timings, isRunning }: { timings: PhaseTimings; isRunning: boolean }) {
  const phases = useMemo(() => {
    const now = new Date()
    return PHASES.map(id => {
      const start = timings.starts[id]
      const end = timings.ends[id]
      if (!start) return { id, state: 'pending' as const, ms: 0 }
      const ms = (end ?? (isRunning ? now : start)).getTime() - start.getTime()
      return { id, state: end ? 'done' as const : 'running' as const, ms }
    })
  }, [timings, isRunning])

  const totalMs = phases.reduce((s, p) => s + p.ms, 0)
  const anyStarted = phases.some(p => p.state !== 'pending')
  if (!anyStarted) return null

  return (
    <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)', background: 'var(--bg-1)' }}>
      <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-3)', marginBottom: 8 }}>
        Scan Progress
      </div>
      <div style={{ display: 'flex', gap: 6, alignItems: 'flex-end' }}>
        {phases.map(p => {
          if (p.state === 'pending') return null
          const widthPct = totalMs > 0 ? Math.max(4, (p.ms / totalMs) * 100) : 20
          const color = PHASE_COLORS[p.id]
          return (
            <div key={p.id} style={{ flex: widthPct, minWidth: 0 }}>
              <div style={{ fontSize: 9, color: 'var(--text-3)', marginBottom: 3, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {PHASE_LABELS[p.id]}
              </div>
              <div style={{ height: 6, borderRadius: 3, background: color, opacity: p.state === 'running' ? 1 : 0.7, position: 'relative', overflow: 'hidden' }}>
                {p.state === 'running' && (
                  <div style={{
                    position: 'absolute', inset: 0, background: `linear-gradient(90deg, transparent 0%, ${color} 50%, transparent 100%)`,
                    animation: 'shimmer 1.4s ease-in-out infinite',
                  }} />
                )}
              </div>
              {p.ms > 0 && (
                <div style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 3, whiteSpace: 'nowrap' }}>
                  {fmtDur(p.ms)}{p.state === 'running' ? '…' : ''}
                </div>
              )}
            </div>
          )
        })}
      </div>
      <style>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  )
}
