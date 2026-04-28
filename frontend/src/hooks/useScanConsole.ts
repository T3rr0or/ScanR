import { useEffect, useRef, useState, useCallback, useMemo } from 'react'
import { useAuthStore } from '@/store/auth'

export type LogLevel = 'info' | 'warn' | 'error' | 'debug' | 'finding'
export type LogPhase = 'discovery' | 'portscan' | 'fingerprint' | 'plugin' | 'engine'

export interface LogEvent {
  type: 'log' | 'status' | 'error' | 'pong' | 'history_end' | 'history_marker'
  scan_id?: string
  ts?: string
  level?: LogLevel
  phase?: LogPhase
  msg?: string
  meta?: Record<string, unknown>
  status?: string
  hosts_total?: number
  hosts_up?: number
  count?: number
}

const MAX_LINES = 5000
const MAX_RECONNECT = 5

export function useScanConsole(scanId: string | null) {
  const [events, setEvents] = useState<LogEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [scanStatus, setScanStatus] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const attemptsRef = useRef(0)
  const pingRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const token = useAuthStore(s => s.token)

  const connect = useCallback(() => {
    if (!scanId || !token) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws/scans/${scanId}/progress`
    const ws = new WebSocket(url, [`token.${token}`])
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      attemptsRef.current = 0
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.send('ping')
      }, 25_000)
    }

    ws.onclose = (e) => {
      setConnected(false)
      if (pingRef.current) { clearInterval(pingRef.current); pingRef.current = null }
      // Don't reconnect on clean close (1000) or auth errors (4401/4404)
      if (e.code === 1000 || e.code === 4401 || e.code === 4404) return
      if (attemptsRef.current >= MAX_RECONNECT) return
      const delay = Math.min(1000 * 2 ** attemptsRef.current, 30_000)
      attemptsRef.current++
      setTimeout(connect, delay)
    }

    ws.onmessage = (e) => {
      try {
        const event: LogEvent = JSON.parse(e.data)

        if (event.type === 'status') {
          setScanStatus(event.status ?? null)
          return
        }

        if (event.type === 'history_end') {
          if ((event.count ?? 0) > 0) {
            setEvents(prev => [...prev, {
              type: 'history_marker',
              msg: `── ${event.count} events loaded from history ──`,
            }])
          }
          return
        }

        if (event.type === 'log') {
          setEvents(prev => {
            const next = [...prev, event]
            return next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
          })
        }
      } catch {
        // ignore parse errors
      }
    }
  }, [scanId, token])

  useEffect(() => {
    if (!scanId || !token) return
    setEvents([])
    setScanStatus(null)
    attemptsRef.current = 0
    connect()

    return () => {
      if (pingRef.current) { clearInterval(pingRef.current); pingRef.current = null }
      wsRef.current?.close(1000)
    }
  }, [scanId, token, connect])

  // Extract phase timing from ▶ phase_start and ✓ phase_done log messages
  const phaseTimings = useMemo(() => {
    const starts: Record<string, Date> = {}
    const ends: Record<string, Date> = {}
    for (const e of events) {
      if (!e.ts || !e.phase || e.type !== 'log') continue
      if (e.msg?.startsWith('▶')) starts[e.phase] = new Date(e.ts)
      if (e.msg?.startsWith('✓')) ends[e.phase] = new Date(e.ts)
    }
    return { starts, ends }
  }, [events])

  return { events, connected, scanStatus, phaseTimings }
}
