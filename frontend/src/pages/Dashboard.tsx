import { useQuery, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Plus, Activity, Server, AlertTriangle, Clock } from 'lucide-react'
import api from '@/api/client'
import { scansApi } from '@/api/scans'
import { analyticsApi } from '@/api/analytics'
import {
  StatusPill, CHML, SeverityBar, Spark, Meter, relTime,
} from '@/components/ui'
import { useScanConsole } from '@/hooks/useScanConsole'

export default function Dashboard({ onOpenScan, onNavigate }: {
  onOpenScan?: (id: string) => void
  onNavigate?: (page: 'dashboard' | 'scans' | 'findings' | 'templates' | 'schedules' | 'agents' | 'credentials' | 'plugins' | 'reports' | 'settings') => void
}) {
  const qc = useQueryClient()
  const { data: stats } = useQuery({
    queryKey: ['system-stats'],
    queryFn: () => api.get('/system/stats').then(r => r.data),
    refetchInterval: 10_000,
  })
  const { data: scans = [] } = useQuery({
    queryKey: ['scans', 0],
    queryFn: () => scansApi.list({ limit: 200 }),
    refetchInterval: 5_000,
  })
  const { data: severityDist = {} } = useQuery({
    queryKey: ['analytics', 'severity-distribution'],
    queryFn: () => analyticsApi.severityDistribution(),
    refetchInterval: 30_000,
  })
  const { data: timeline = [] } = useQuery({
    queryKey: ['analytics', 'findings-timeline'],
    queryFn: () => analyticsApi.findingsTimeline(30),
    refetchInterval: 60_000,
  })
  const { data: topHosts = [] } = useQuery({
    queryKey: ['analytics', 'top-vulnerable-hosts'],
    queryFn: () => analyticsApi.topVulnerableHosts(10),
    refetchInterval: 60_000,
  })

  const running = scans.filter(s => s.status === 'running')
  const recent = scans.slice(0, 6)

  const tot = {
    c: severityDist.critical ?? 0,
    h: severityDist.high ?? 0,
    m: severityDist.medium ?? 0,
    l: severityDist.low ?? 0,
    i: severityDist.info ?? 0,
  }

  return (
    <div className="page-pad" style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 1480, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, letterSpacing: '-0.01em' }}>Overview</h1>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => qc.invalidateQueries()}>
            <RefreshCw size={12} /> Refresh
          </button>
          <button className="btn btn-primary" onClick={() => onNavigate?.('scans')}>
            <Plus size={12} /> New Scan
          </button>
        </div>
      </div>

      {/* KPI row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
        <KpiCard
          label="Running Scans"
          value={stats?.scans_running ?? 0}
          hint={`${stats?.scans_total ?? 0} total`}
          icon={<Activity size={14} />}
          sparkColor="var(--accent-2)"
          spark={[1,0,0,1,1,2,2,2,1,2]}
        />
        <KpiCard
          label="Hosts Found"
          value={stats?.hosts_total ?? 0}
          hint="across all scans"
          icon={<Server size={14} />}
          spark={[4,5,6,5,7,8,7,9,10,10]}
        />
        <KpiCard
          label="Critical Findings"
          value={stats?.findings_critical ?? 0}
          hint={`${tot.c + tot.h} critical + high`}
          icon={<AlertTriangle size={14} />}
          sparkColor="var(--sev-critical)"
          spark={[1,2,1,3,2,3,4,3,4,tot.c]}
          criticalAccent
        />
        <KpiCard
          label="Total Scans"
          value={stats?.scans_total ?? 0}
          hint={`${stats?.scans_completed ?? 0} completed`}
          icon={<Clock size={14} />}
          spark={[2,3,3,4,4,5,5,6,7,stats?.scans_total ?? 0]}
        />
      </div>

      {/* Main grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
        {/* Live scan card or placeholder */}
        {running.length > 0
          ? <LiveScanCard scan={running[0]} onOpen={() => onOpenScan?.(running[0].id)} />
          : (
            <div className="panel" style={{ padding: 20, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ textAlign: 'center', color: 'var(--text-3)' }}>
                <Activity size={28} style={{ margin: '0 auto 8px' }} />
                <div style={{ fontSize: 12.5 }}>No active scans</div>
              </div>
            </div>
          )
        }

        {/* Severity summary */}
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Severity Distribution</span>
            <span className="mono dim" style={{ marginLeft: 'auto', fontSize: 11 }}>
              {tot.c + tot.h + tot.m + tot.l + tot.i} total
            </span>
          </div>
          <div style={{ padding: 14 }}>
            <SeverityBar c={tot.c} h={tot.h} m={tot.m} l={tot.l} i={tot.i} />
            <div style={{ marginTop: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {([
                ['Critical', tot.c, 'critical'],
                ['High', tot.h, 'high'],
                ['Medium', tot.m, 'medium'],
                ['Low', tot.l, 'low'],
                ['Info', tot.i, 'info'],
              ] as [string, number, string][]).map(([label, v, sev]) => (
                <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="sev-bar" style={{ background: `var(--sev-${sev})` }} />
                  <span style={{ fontSize: 11.5, color: 'var(--text-2)', flex: 1 }}>{label}</span>
                  <span className="mono" style={{ fontSize: 12, fontWeight: 600, color: v > 0 ? 'var(--text-0)' : 'var(--text-3)' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Timeline + top hosts */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
        {/* Findings timeline */}
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Findings Trend · 30d</span>
            <div style={{ marginLeft: 'auto', display: 'flex', gap: 10 }}>
              {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
                <span key={sev} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10.5, color: 'var(--text-2)' }}>
                  <span style={{ width: 8, height: 2, background: `var(--sev-${sev})`, display: 'inline-block', borderRadius: 1 }} />
                  {sev}
                </span>
              ))}
            </div>
          </div>
          <div style={{ padding: 14 }}>
            <TimelineChart data={timeline} />
          </div>
        </div>

        {/* Top vulnerable hosts */}
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">Top Vulnerable Hosts</span>
          </div>
          <div style={{ padding: '4px 0' }}>
            {topHosts.length === 0 && (
              <div style={{ padding: '24px 14px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                No data yet
              </div>
            )}
            {topHosts.slice(0, 7).map((h: any) => {
              const sev = h.top_severity ?? 'high'
              return (
              <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 14px', fontSize: 12 }}>
                <span className="sev-bar" style={{ background: `var(--sev-${sev})` }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="mono" style={{ color: 'var(--accent)', fontSize: 11.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {h.hostname ?? h.ip}
                  </div>
                  <div className="mono dim" style={{ fontSize: 10.5 }}>{h.ip}</div>
                </div>
                <div style={{ width: 60, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <div className="meter" style={{ flex: 1 }}>
                    <span style={{
                      width: `${Math.min(100, (h.finding_count / (topHosts[0]?.finding_count || 1)) * 100)}%`,
                      background: `var(--sev-${sev})`,
                    }} />
                  </div>
                  <span className="mono" style={{ fontSize: 11, fontWeight: 600, minWidth: 18, textAlign: 'right' }}>{h.finding_count}</span>
                </div>
              </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent scans table */}
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Recent Scans</span>
          <button className="btn btn-ghost btn-sm" style={{ marginLeft: 'auto' }} onClick={() => onNavigate?.('scans')}>
            View all
          </button>
        </div>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th>Name</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Hosts</th>
              <th>Findings (C/H/M/L)</th>
              <th>Severity</th>
              <th>Started</th>
            </tr>
          </thead>
          <tbody>
            {recent.map(s => (
              <tr key={s.id} onClick={() => onOpenScan?.(s.id)}>
                <td style={{ color: 'var(--text-3)' }}>
                  {s.status === 'running'
                    ? <span className="live-dot" style={{ width: 6, height: 6, display: 'inline-block' }} />
                    : <Activity size={13} />
                  }
                </td>
                <td style={{ fontWeight: 500 }}>{s.name}</td>
                <td className="mono dim" style={{ fontSize: 11.5 }}>{s.profile}</td>
                <td><StatusPill status={s.status} /></td>
                <td className="mono">
                  <span style={{ color: 'var(--text-0)' }}>{s.hosts_up ?? 0}</span>
                  <span className="dim">/{s.hosts_total ?? 0}</span>
                </td>
                <td>
                  <CHML c={s.findings_critical} h={s.findings_high} m={s.findings_medium} l={s.findings_low} />
                </td>
                <td style={{ width: 110 }}>
                  <SeverityBar c={s.findings_critical} h={s.findings_high} m={s.findings_medium} l={s.findings_low} i={s.findings_info} />
                </td>
                <td className="mono dim" style={{ fontSize: 11.5 }}>{relTime(s.created_at)}</td>
              </tr>
            ))}
            {recent.length === 0 && (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '32px 20px', color: 'var(--text-3)', fontSize: 12 }}>
                  No scans yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function KpiCard({
  label, value, hint, icon, spark, sparkColor, criticalAccent,
}: {
  label: string; value: number | string; hint: React.ReactNode;
  icon: React.ReactNode; spark?: number[]; sparkColor?: string; criticalAccent?: boolean
}) {
  return (
    <div className="panel" style={{ padding: 14, borderLeft: criticalAccent ? '2px solid var(--sev-critical)' : undefined }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{
          width: 26, height: 26, borderRadius: 6, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          background: 'var(--bg-2)', color: criticalAccent ? 'var(--sev-critical)' : 'var(--accent)',
        }}>
          {icon}
        </span>
        <span className="panel-title" style={{ fontSize: 10.5 }}>{label}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginTop: 10, gap: 12 }}>
        <div>
          <div className="mono" style={{
            fontSize: 26, fontWeight: 600, letterSpacing: '-0.02em', lineHeight: 1,
            color: criticalAccent ? 'var(--sev-critical)' : 'var(--text-0)',
          }}>
            {value}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-2)', marginTop: 5 }}>{hint}</div>
        </div>
        {spark && <Spark data={spark} color={sparkColor} height={32} width={80} />}
      </div>
    </div>
  )
}

function LiveScanCard({ scan, onOpen }: { scan: any; onOpen: () => void }) {
  const { events } = useScanConsole(scan.id)
  const recent = events.slice(-6)
  return (
    <div className="panel" style={{ overflow: 'hidden' }}>
      <div className="panel-head">
        <span className="live-dot" />
        <span className="panel-title">Live scan</span>
        <span style={{ fontSize: 13, fontWeight: 500, marginLeft: 8 }}>{scan.name}</span>
        <span className="mono dim" style={{ fontSize: 11, marginLeft: 6 }}>{scan.id.slice(0, 8)}</span>
        <button className="btn btn-sm" style={{ marginLeft: 'auto' }} onClick={onOpen}>
          Open console
        </button>
      </div>
      <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-2)', marginBottom: 6 }}>
            Progress · {Math.round((scan.progress ?? 0) * 100)}%
          </div>
          <Meter value={scan.progress ?? 0} color="var(--accent-2)" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 14 }}>
            <MiniStat k="Hosts up" v={`${scan.hosts_up}`} sub={`of ${scan.hosts_total}`} />
            <MiniStat k="Findings" v={String(scan.findings_critical + scan.findings_high + scan.findings_medium)} />
          </div>
          <div style={{ display: 'flex', gap: 16, marginTop: 14, paddingTop: 12, borderTop: '1px solid var(--border-subtle)' }}>
            {([
              { label: 'Critical', count: scan.findings_critical, sev: 'critical' },
              { label: 'High',     count: scan.findings_high,     sev: 'high' },
              { label: 'Medium',   count: scan.findings_medium,   sev: 'medium' },
            ] as const).map(({ label, count, sev }) => (
              <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span className="sev-bar" style={{ background: `var(--sev-${sev})` }} />
                <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: `var(--sev-${sev})` }}>{count}</span>
                <span style={{ fontSize: 10.5, color: 'var(--text-2)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="console" style={{ height: 220, padding: 10, overflow: 'hidden' }}>
          {recent.length === 0 && (
            <div className="ln"><span className="ts">—</span><span className="lvl info">···</span><span className="msg">waiting for events…</span></div>
          )}
          {recent.map((e, i) => (
            <div key={i} className="ln">
              <span className="ts">{new Date(e.ts ?? '').toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>
              <span className={`lvl ${e.level ?? 'info'}`}>{e.level ?? 'info'}</span>
              <span className="msg">{e.msg ?? String(e)}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function MiniStat({ k, v, sub }: { k: string; v: string; sub?: string }) {
  return (
    <div>
      <div className="panel-title" style={{ fontSize: 10 }}>{k}</div>
      <div className="mono" style={{ fontSize: 14, fontWeight: 500, marginTop: 2, color: 'var(--text-0)' }}>{v}</div>
      {sub && <div className="mono dim" style={{ fontSize: 10.5 }}>{sub}</div>}
    </div>
  )
}

function TimelineChart({ data }: { data: any[] }) {
  if (data.length === 0) {
    return <div style={{ height: 140, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 12 }}>No data</div>
  }
  const W = 640, H = 140, PAD_L = 28, PAD_R = 6, PAD_T = 8, PAD_B = 18
  const sevs = ['low', 'medium', 'high', 'critical'] as const
  const allVals = data.flatMap(d => sevs.map(s => d[s] ?? 0))
  const max = Math.max(...allVals, 1) * 1.15
  const n = data.length
  const px = (i: number) => PAD_L + (i / (n - 1)) * (W - PAD_L - PAD_R)
  const py = (v: number) => H - PAD_B - (v / max) * (H - PAD_T - PAD_B)
  const path = (arr: number[]) => arr.map((v, i) => `${i === 0 ? 'M' : 'L'}${px(i).toFixed(1)},${py(v).toFixed(1)}`).join(' ')
  const area = (arr: number[]) => `${path(arr)} L${px(n - 1)},${H - PAD_B} L${px(0)},${H - PAD_B} Z`
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} style={{ display: 'block' }}>
      {[0, 0.33, 0.66, 1].map(t => (
        <line key={t} x1={PAD_L} x2={W - PAD_R} y1={PAD_T + t * (H - PAD_T - PAD_B)} y2={PAD_T + t * (H - PAD_T - PAD_B)}
          stroke="var(--border-subtle)" strokeDasharray="2 3" />
      ))}
      {[0, 0.5, 1].map(t => (
        <text key={t} x={PAD_L - 6} y={PAD_T + t * (H - PAD_T - PAD_B) + 3}
          fontSize="9" fill="var(--text-3)" textAnchor="end" fontFamily="var(--font-mono)">
          {Math.round(max - t * max)}
        </text>
      ))}
      {sevs.map(sev => (
        <path key={sev} d={area(data.map(d => d[sev] ?? 0))} fill={`var(--sev-${sev})`} opacity="0.08" />
      ))}
      {sevs.map(sev => (
        <path key={`l-${sev}`} d={path(data.map(d => d[sev] ?? 0))} fill="none" stroke={`var(--sev-${sev})`} strokeWidth="1.4" />
      ))}
      {[0, 7, 14, 21, 29].map(i => {
        const di = Math.min(i, n - 1)
        return (
          <text key={i} x={px(di)} y={H - 4} fontSize="9" fill="var(--text-3)" textAnchor="middle" fontFamily="var(--font-mono)">
            {`-${n - 1 - di}d`}
          </text>
        )
      })}
    </svg>
  )
}
