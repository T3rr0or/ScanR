import { useEffect, useRef, useState } from 'react'
import { type LogEvent, type LogLevel, type LogPhase } from '@/hooks/useScanConsole'

interface Props {
  events: LogEvent[]
  connected: boolean
  scanStatus: string | null
}

const LEVEL_COLOR: Record<LogLevel | string, string> = {
  info:    'text-gray-200',
  debug:   'text-gray-500',
  warn:    'text-yellow-400',
  error:   'text-red-400',
  finding: 'text-emerald-400 font-semibold',
}

const PHASE_BADGE: Record<LogPhase | string, string> = {
  engine:      'bg-gray-700 text-gray-300',
  discovery:   'bg-blue-900 text-blue-300',
  portscan:    'bg-purple-900 text-purple-300',
  fingerprint: 'bg-indigo-900 text-indigo-300',
  plugin:      'bg-teal-900 text-teal-300',
}

const LEVELS: (LogLevel | 'all')[] = ['all', 'debug', 'info', 'warn', 'error', 'finding']
const PHASES: (LogPhase | 'all')[] = ['all', 'engine', 'discovery', 'portscan', 'fingerprint', 'plugin']

function fmt(ts: string | undefined) {
  if (!ts) return ''
  try {
    return ts.slice(11, 19) // HH:MM:SS from ISO string
  } catch {
    return ts
  }
}

export default function ScanConsole({ events, connected, scanStatus }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)           // ref, not state — no re-render on change
  const [autoScrollDisplay, setAutoScrollDisplay] = useState(true) // only for button UI
  const [levelFilter, setLevelFilter] = useState<LogLevel | 'all'>('all')
  const [phaseFilter, setPhaseFilter] = useState<LogPhase | 'all'>('all')
  const [search, setSearch] = useState('')

  // Auto-scroll: direct DOM mutation — no animation, no async, keeps up with bursts
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
    if (next && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }

  const filtered = events.filter(e => {
    if (e.type === 'history_marker') return true  // always show separator
    if (levelFilter !== 'all' && e.level !== levelFilter) return false
    if (phaseFilter !== 'all' && e.phase !== phaseFilter) return false
    if (search && !e.msg?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  return (
    <div className="flex flex-col h-full bg-gray-950 rounded-xl overflow-hidden border border-gray-800">
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-4 py-2 bg-gray-900 border-b border-gray-800 flex-shrink-0 flex-wrap">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
          <span className="text-xs text-gray-400 font-mono">
            {connected ? 'live' : 'disconnected'}
          </span>
          {scanStatus && (
            <span className="text-xs text-gray-500 ml-1">· {scanStatus}</span>
          )}
        </div>

        <div className="flex items-center gap-1 ml-2">
          <span className="text-xs text-gray-500 mr-1">level</span>
          {LEVELS.map(l => (
            <button
              key={l}
              onClick={() => setLevelFilter(l)}
              className={`px-2 py-0.5 rounded text-xs font-mono transition-colors ${
                levelFilter === l
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {l}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1">
          <span className="text-xs text-gray-500 mr-1">phase</span>
          {PHASES.map(p => (
            <button
              key={p}
              onClick={() => setPhaseFilter(p)}
              className={`px-2 py-0.5 rounded text-xs font-mono transition-colors ${
                phaseFilter === p
                  ? 'bg-gray-700 text-white'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              {p}
            </button>
          ))}
        </div>

        <input
          type="text"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="filter..."
          className="ml-auto bg-gray-800 border border-gray-700 text-gray-300 text-xs font-mono rounded px-2 py-0.5 w-36 focus:outline-none focus:border-gray-500 placeholder-gray-600"
        />

        <button
          onClick={toggleAutoScroll}
          className={`text-xs px-2 py-0.5 rounded border font-mono transition-colors ${
            autoScrollDisplay
              ? 'border-emerald-700 text-emerald-400'
              : 'border-gray-700 text-gray-500 hover:text-gray-300'
          }`}
          title="Toggle auto-scroll"
        >
          ↓ scroll
        </button>
      </div>

      {/* Log output */}
      <div
        ref={containerRef}
        onScroll={onScroll}
        className="flex-1 overflow-y-auto font-mono text-xs leading-5 px-4 py-3 space-y-0.5"
      >
        {filtered.length === 0 && (
          <div className="text-gray-600 pt-4 text-center">
            {events.length === 0 ? 'Waiting for scan events...' : 'No events match current filters.'}
          </div>
        )}

        {filtered.map((e, i) => {
          if (e.type === 'history_marker') {
            return (
              <div key={i} className="text-center text-gray-600 text-[10px] py-1 select-none">
                {e.msg}
              </div>
            )
          }
          return (
            <div key={i} className="flex items-start gap-2 hover:bg-gray-900 px-1 rounded">
              <span className="text-gray-600 w-16 flex-shrink-0 select-none">{fmt(e.ts)}</span>
              <span className={`w-16 flex-shrink-0 text-center rounded px-1 text-[10px] ${PHASE_BADGE[e.phase ?? 'engine'] ?? PHASE_BADGE.engine}`}>
                {e.phase ?? '—'}
              </span>
              <span className={`flex-1 break-all ${LEVEL_COLOR[e.level ?? 'info'] ?? LEVEL_COLOR.info}`}>
                {e.level === 'finding' && (
                  <span className="mr-2">
                    {severityIcon(typeof e.meta?.severity === 'string' ? e.meta.severity : undefined)}
                  </span>
                )}
                {e.msg}
                {e.meta?.host != null && e.level !== 'finding' && (
                  <span className="text-gray-600 ml-2">[{String(e.meta.host as string)}]</span>
                )}
              </span>
            </div>
          )
        })}
      </div>

      {/* Footer: event count */}
      <div className="px-4 py-1 bg-gray-900 border-t border-gray-800 flex-shrink-0">
        <span className="text-xs text-gray-600 font-mono">
          {filtered.length}/{events.length} events
          {search && ` · filtered by "${search}"`}
        </span>
      </div>
    </div>
  )
}

function severityIcon(severity: string | undefined) {
  switch (severity) {
    case 'critical': return '🔴'
    case 'high':     return '🟠'
    case 'medium':   return '🟡'
    case 'low':      return '🟢'
    default:         return '⚪'
  }
}
