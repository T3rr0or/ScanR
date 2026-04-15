import { useEffect, useRef, useState } from 'react'

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
  // status event fields
  status?: string
  hosts_total?: number
  hosts_up?: number
  // history_end
  count?: number
}

const MAX_LINES = 5000

export function useScanConsole(scanId: string | null) {
  const [events, setEvents] = useState<LogEvent[]>([])
  const [connected, setConnected] = useState(false)
  const [scanStatus, setScanStatus] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    setEvents([])
    setScanStatus(null)

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws/scans/${scanId}/progress`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)

    ws.onmessage = (e) => {
      try {
        const event: LogEvent = JSON.parse(e.data)

        if (event.type === 'status') {
          setScanStatus(event.status ?? null)
          return
        }

        if (event.type === 'history_end') {
          if ((event.count ?? 0) > 0) {
            // Insert a visual separator between history and live events
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

    // Keepalive ping every 25s
    const ping = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send('ping')
    }, 25_000)

    return () => {
      clearInterval(ping)
      ws.close()
    }
  }, [scanId])

  return { events, connected, scanStatus }
}
