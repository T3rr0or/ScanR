import { useEffect, useRef, useState } from 'react'
import { Download, X } from 'lucide-react'
import { type LogEvent, type LogLevel, type LogPhase } from '@/hooks/useScanConsole'
import { HighlightMsg } from '@/components/ui'

interface Props {
  events: LogEvent[]
  connected: boolean
  scanStatus: string | null
}

// Map backend level → console CSS class
const LEVEL_CLS: Record<string, string> = {
  info:    'info',
  warn:    'warn',
  error:   'err',
  debug:   '',       // dim, no special class
  finding: 'crit',
}

const LEVELS: (LogLevel | 'all')[] = ['all', 'info', 'warn', 'error', 'finding', 'debug']
const PHASES: (LogPhase | 'all')[] = ['all', 'discovery', 'portscan', 'fingerprint', 'plugin', 'engine']

function fmtTs(ts: string | undefined) {
  if (!ts) return '——:——:——'
  try { return ts.slice(11, 19) } catch { return ts }
}

export default function ScanConsole({ events, connected, scanStatus }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)
  const [autoScrollDisplay, setAutoScrollDisplay] = useState(true)
  const [levelFilter, setLevelFilter] = useState<LogLevel | 'all'>('all')
  const [phaseFilter, setPhaseFilter] = useState<LogPhase | 'all'>('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    if (autoScrollRef.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [events])

  const onScroll = () => {
    const el = containerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    autoScrollRef.current = atBottom
    setAutoScrollDisplay(atBottom)
  }

  const toggleAutoScroll = () => {
    const next = !autoScrollRef.current
    autoScrollRef.current = next
    setAutoScrollDisplay(next)
    if (next && containerRef.current) containerRef.current.scrollTop = containerRef.current.scrollHeight
  }

  const filtered = events.filter(e => {
    if (e.type === 'history_marker') return true
    if (levelFilter !== 'all' && e.level !== levelFilter) return false
    if (phaseFilter !== 'all' && e.phase !== phaseFilter) return false
    if (search && !e.msg?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  function exportLogs() {
    const text = filtered
      .filter(e => e.type === 'log')
      .map(e => `${fmtTs(e.ts)}  ${(e.level ?? 'info').padEnd(8)}  ${e.msg ?? ''}`)
      .join('\n')
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'scan-console.log'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, gap: 10 }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', flexShrink: 0 }}>
        {/* Connection status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {connected
            ? <span className="live-dot" style={{ width: 6, height: 6, boxShadow: 'none' }} />
            : <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--text-3)', display: 'inline-block' }} />
          }
          <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
            {connected ? 'live' : 'disconnected'}
          </span>
          {scanStatus && <span className="dimmer mono" style={{ fontSize: 11 }}>· {scanStatus}</span>}
          <span className="mono dimmer" style={{ fontSize: 11 }}>· {filtered.length}/{events.length}</span>
        </div>

        <div style={{ width: 1, height: 14, background: 'var(--border)' }} />

        {/* Level filters */}
        {LEVELS.map(l => {
          const active = levelFilter === l
          const cls = l !== 'all' ? LEVEL_CLS[l] : ''
          const color = cls === 'info' ? 'var(--accent)' : cls === 'warn' ? 'var(--sev-medium)' : cls === 'err' ? 'var(--sev-high)' : cls === 'crit' ? 'var(--sev-critical)' : 'var(--text-2)'
          return (
            <button key={l} onClick={() => setLevelFilter(l)} style={{
              padding: '3px 8px', borderRadius: 4, fontSize: 10.5, cursor: 'pointer',
              background: active ? 'var(--bg-3)' : 'transparent',
              color: active ? (cls ? color : 'var(--text-0)') : 'var(--text-2)',
              border: '1px solid ' + (active ? 'var(--border-strong)' : 'transparent'),
              fontFamily: 'var(--font-mono)',
              fontWeight: active ? 700 : 400,
            }}>
              {l}
            </button>
          )
        })}

        <div style={{ width: 1, height: 14, background: 'var(--border)' }} />

        {/* Phase filters */}
        {PHASES.map(p => {
          const active = phaseFilter === p
          return (
            <button key={p} onClick={() => setPhaseFilter(p)} style={{
              padding: '3px 8px', borderRadius: 4, fontSize: 10.5, cursor: 'pointer',
              background: active ? 'var(--bg-3)' : 'transparent',
              color: active ? 'var(--text-0)' : 'var(--text-2)',
              border: '1px solid ' + (active ? 'var(--border-strong)' : 'transparent'),
              fontFamily: 'var(--font-mono)',
            }}>
              {p}
            </button>
          )
        })}

        <div style={{ flex: 1 }} />

        {/* Search */}
        <div className="search" style={{ width: 200 }}>
          <input
            placeholder="Search…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button onClick={() => setSearch('')} style={{ color: 'var(--text-3)', background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}>
              <X size={12} />
            </button>
          )}
        </div>

        <button
          onClick={toggleAutoScroll}
          className={`btn btn-sm ${autoScrollDisplay ? '' : 'btn-ghost'}`}
          style={autoScrollDisplay ? { background: 'var(--accent-soft)', borderColor: 'oklch(0.78 0.14 200 / 0.3)', color: 'var(--accent)' } : {}}
        >
          ↓ scroll
        </button>

        <button onClick={exportLogs} className="btn btn-ghost btn-icon btn-sm" title="Export log">
          <Download size={12} />
        </button>
      </div>

      {/* Console output */}
      <div
        ref={containerRef}
        onScroll={onScroll}
        className="console"
        style={{ flex: 1, minHeight: 0 }}
      >
        {filtered.length === 0 && (
          <div className="ln">
            <span className="ts">——:——:——</span>
            <span className="lvl info">···</span>
            <span className="msg dimmer">
              {events.length === 0 ? 'Waiting for scan events…' : 'No events match current filters.'}
            </span>
          </div>
        )}

        {filtered.map((e, i) => {
          if (e.type === 'history_marker') {
            return (
              <div key={i} style={{ textAlign: 'center', color: 'var(--text-3)', fontSize: 10, padding: '4px 0', userSelect: 'none' }}>
                {e.msg}
              </div>
            )
          }

          const lvlCls = LEVEL_CLS[e.level ?? 'info'] ?? ''

          return (
            <div key={i} className="ln">
              <span className="ts">{fmtTs(e.ts)}</span>
              <span className={`lvl ${lvlCls}`}>
                {e.level === 'error' ? 'err' : e.level === 'finding' ? 'crit' : e.level ?? 'info'}
              </span>
              <span className="msg">
                {e.msg ? <HighlightMsg msg={e.msg} /> : null}
                {e.meta?.host != null && e.level !== 'finding' && (
                  <span className="dimmer"> [{String(e.meta.host)}]</span>
                )}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
