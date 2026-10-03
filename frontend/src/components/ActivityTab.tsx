import { useQuery } from '@tanstack/react-query'
import { ShieldCheck, ShieldAlert } from 'lucide-react'
import api from '@/api/client'

interface ActivityLog {
  scan_id: string
  testing_window: string | null
  window_open_now: boolean | null
  verified: boolean
  entries: { at: string; event: string; detail: string | null; source_ip: string | null; actor: string | null; hash: string }[]
}

const LABELS: Record<string, string> = {
  started: 'Scan started', completed: 'Scan completed', failed: 'Scan failed', cancelled: 'Scan cancelled',
  paused: 'Paused by tester', resumed: 'Resumed by tester', cancel_requested: 'Cancelled by tester',
  window_closed: 'Paused: testing window closed', window_opened: 'Resumed: testing window opened',
}

/** When the scan sent traffic and from where, with an integrity check. */
export default function ActivityTab({ scanId }: { scanId: string }) {
  const { data } = useQuery({
    queryKey: ['scan-activity', scanId],
    queryFn: () => api.get<ActivityLog>(`/scans/${scanId}/activity`).then(r => r.data),
    refetchInterval: 15_000,
  })
  if (!data) return <div className="dimmer" style={{ padding: 24 }}>Loading…</div>
  return (
    <div className="activity-tab">
      <div className="activity-summary">
        <div><span>Testing window</span><strong>{data.testing_window ?? 'Not restricted'}</strong>
          {data.window_open_now !== null && <small className={data.window_open_now ? 'is-open' : 'is-closed'}>{data.window_open_now ? 'open now' : 'closed now'}</small>}</div>
        <div><span>Integrity</span>
          {data.verified
            ? <strong className="is-open"><ShieldCheck size={14} /> Record intact</strong>
            : <strong className="is-closed"><ShieldAlert size={14} /> Record was altered</strong>}
        </div>
      </div>
      <table className="tbl" style={{ width: '100%' }}>
        <thead><tr><th>Time</th><th>Event</th><th>Source address</th><th>By</th><th>Detail</th></tr></thead>
        <tbody>
          {data.entries.map(e => (
            <tr key={e.hash}>
              <td className="mono" style={{ fontSize: 11 }}>{new Date(e.at).toLocaleString()}</td>
              <td style={{ fontSize: 12 }}>{LABELS[e.event] ?? e.event}</td>
              <td className="mono dimmer" style={{ fontSize: 11 }}>{e.source_ip ?? '–'}</td>
              <td style={{ fontSize: 12 }}>{e.actor ?? <span className="dimmer">ScanR</span>}</td>
              <td className="dimmer" style={{ fontSize: 11, whiteSpace: 'normal' }}>{e.detail ?? ''}</td>
            </tr>
          ))}
          {data.entries.length === 0 && <tr><td colSpan={5} className="dimmer" style={{ padding: 24, textAlign: 'center' }}>No activity yet. Entries appear when the scan starts.</td></tr>}
        </tbody>
      </table>
    </div>
  )
}
