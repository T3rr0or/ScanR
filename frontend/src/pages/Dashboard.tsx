import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, RefreshCw } from 'lucide-react'
import api from '@/api/client'
import { scansApi, type ScanSummary } from '@/api/scans'
import { analyticsApi, type TimelinePoint } from '@/api/analytics'
import { CHML, SeverityBar, StatusPill, relTime } from '@/components/ui'
import { useScanConsole } from '@/hooks/useScanConsole'
import ScanActivityHeatmap from '@/components/charts/ScanActivityHeatmap'
import './Dashboard.css'

type Page = 'dashboard' | 'scans' | 'findings' | 'templates' | 'schedules' | 'agents' | 'credentials' | 'plugins' | 'reports' | 'settings'

export default function Dashboard({ onOpenScan, onNavigate }: {
  onOpenScan?: (id: string) => void
  onNavigate?: (page: Page) => void
}) {
  const qc = useQueryClient()
  const { data: stats, isError: statsError } = useQuery({
    queryKey: ['system-stats'],
    queryFn: () => api.get('/system/stats').then(r => r.data),
    refetchInterval: 10_000,
  })
  const { data: scans = [], isError: scansError } = useQuery({
    queryKey: ['scans', 0],
    queryFn: () => scansApi.list({ limit: 200 }),
    refetchInterval: 5_000,
  })
  const { data: severityDist = {}, isError: severityError } = useQuery({
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
  const { data: activityData = [] } = useQuery({
    queryKey: ['analytics', 'scan-activity'],
    queryFn: () => analyticsApi.scanActivity(30),
    refetchInterval: 300_000,
  })

  const running = scans.filter(s => s.status === 'running')
  const recent = scans.slice(0, 6)
  const severity = [
    { label: 'Critical', count: severityDist.critical ?? 0, key: 'critical' },
    { label: 'High', count: severityDist.high ?? 0, key: 'high' },
    { label: 'Medium', count: severityDist.medium ?? 0, key: 'medium' },
    { label: 'Low', count: severityDist.low ?? 0, key: 'low' },
    { label: 'Info', count: severityDist.info ?? 0, key: 'info' },
  ]
  const findingTotal = severity.reduce((sum, item) => sum + item.count, 0)

  return <main className="dashboard page-pad">
    <header className="dashboard-header"><div><h1>Dashboard</h1><p>Scan status and findings across this instance.</p></div><div className="dashboard-header-actions"><button onClick={() => qc.invalidateQueries()}><RefreshCw size={13}/> Refresh</button><button className="dashboard-primary" onClick={() => onNavigate?.('scans')}>New scan <ArrowRight size={14}/></button></div></header>
    {(statsError || scansError || severityError) && <div className="dashboard-data-error" role="alert"><strong>Dashboard data unavailable.</strong><span>Some totals and lists may be incomplete. Check the ScanR service, then retry.</span><button onClick={() => qc.invalidateQueries()}>Retry <RefreshCw size={12}/></button></div>}
    <section className="dashboard-metrics" aria-label="System metrics"><div><span>Running scans</span><strong>{statsError ? '-' : stats?.scans_running ?? 0}</strong></div><div><span>Hosts found</span><strong>{statsError ? '-' : stats?.hosts_total ?? 0}</strong></div><div><span>Critical findings</span><strong className="dashboard-accent">{statsError ? '-' : stats?.findings_critical ?? 0}</strong></div><div><span>Completed scans</span><strong>{statsError ? '-' : stats?.scans_completed ?? 0}<small> / {statsError ? '-' : stats?.scans_total ?? 0}</small></strong></div></section>
    {stats?.scans_total === 0 && <div className="dashboard-start-note"><strong>No scans recorded.</strong><span>Use New scan to start host discovery and vulnerability checks.</span></div>}
    <div className="dashboard-primary-grid"><section className="dashboard-block"><div className="dashboard-block-head"><h2>Active scans</h2><span>{scansError ? 'unavailable' : `${running.length} running`}</span></div>{running.length > 0 ? <><LiveScan scan={running[0]} onOpen={() => onOpenScan?.(running[0].id)}/>{running.length > 1 && <div className="dashboard-more-running">+ {running.length-1} other active {running.length===2?'scan':'scans'}</div>}</> : <div className="dashboard-quiet">{scansError ? 'Scan status unavailable' : 'No active scans'}</div>}</section>
    <section className="dashboard-block dashboard-findings-block"><div className="dashboard-block-head"><h2>Findings</h2><button onClick={() => onNavigate?.('findings')}>View all <ArrowRight size={13}/></button></div><div className="dashboard-findings-total"><strong>{severityError ? '-' : findingTotal}</strong><span>across all scans</span></div>{!severityError && <SeverityBar c={severity[0].count} h={severity[1].count} m={severity[2].count} l={severity[3].count} i={severity[4].count}/>}<div className="dashboard-severity-list">{severity.map(item=><div key={item.key}><span className={`dashboard-severity-dot dashboard-severity-dot-${item.key}`}/><span>{item.label}</span><strong>{severityError ? '-' : item.count}</strong></div>)}</div></section></div>
    <section className="dashboard-block dashboard-scans"><div className="dashboard-block-head"><h2>Recent scans</h2><button onClick={() => onNavigate?.('scans')}>All scans <ArrowRight size={13}/></button></div><div className="dashboard-scan-table-wrap"><table><thead><tr><th>Name / profile</th><th>Status</th><th>Hosts</th><th>Findings C/H/M/L</th><th>Started</th><th/></tr></thead><tbody>{recent.map(scan=><tr key={scan.id} onClick={()=>onOpenScan?.(scan.id)} tabIndex={0} onKeyDown={event=>{if(event.key==='Enter')onOpenScan?.(scan.id)}}><td><strong>{scan.name}</strong><small>{scan.profile}</small></td><td><StatusPill status={scan.status}/></td><td>{scan.hosts_up??0}<span> / {scan.hosts_total??0}</span></td><td><CHML c={scan.findings_critical} h={scan.findings_high} m={scan.findings_medium} l={scan.findings_low}/></td><td>{relTime(scan.created_at)}</td><td><ArrowRight size={14}/></td></tr>)}{recent.length===0&&<tr><td colSpan={6} className="dashboard-table-empty">{scansError ? 'Scan list unavailable' : 'No scans recorded'}</td></tr>}</tbody></table></div></section>
    <div className="dashboard-secondary-grid"><section className="dashboard-block"><div className="dashboard-block-head"><h2>Findings trend</h2><span>Last 30 days</span></div><div className="dashboard-timeline"><TimelineChart data={timeline}/></div></section><section className="dashboard-block"><div className="dashboard-block-head"><h2>Exposed hosts</h2><span>{topHosts.length} hosts</span></div>{topHosts.length===0?<div className="dashboard-quiet">No host findings yet</div>:<ol className="dashboard-host-list">{topHosts.slice(0,7).map((host,index)=><li key={host.id}><span>{String(index+1).padStart(2,'0')}</span><strong>{host.hostname??host.ip}<small>{host.ip}</small></strong><b>{host.finding_count}</b></li>)}</ol>}</section></div>
    {activityData.length>0&&<section className="dashboard-block dashboard-activity"><div className="dashboard-block-head"><h2>Scan activity</h2><span>Last 30 days</span></div><div><ScanActivityHeatmap data={activityData}/></div></section>}
  </main>
}

function LiveScan({ scan, onOpen }: { scan: ScanSummary; onOpen: () => void }) {
  const { events } = useScanConsole(scan.id)
  const recent = events.slice(-4)
  const progress = Math.round((scan.progress ?? 0) * 100)
  return <div className="dashboard-live"><div className="dashboard-live-top"><div><span className="dashboard-running-dot"/><strong>{scan.name}</strong><small>{scan.id.slice(0,8)}</small></div><button onClick={onOpen}>Open console <ArrowRight size={13}/></button></div><div className="dashboard-progress"><span>Progress</span><div><i style={{width:`${progress}%`}}/></div><strong>{progress}%</strong></div><div className="dashboard-live-stats"><span>Hosts up <strong>{scan.hosts_up??0} / {scan.hosts_total??0}</strong></span><span>Critical <strong>{scan.findings_critical??0}</strong></span><span>High <strong>{scan.findings_high??0}</strong></span><span>Medium <strong>{scan.findings_medium??0}</strong></span></div><div className="dashboard-console"><span>Latest output</span>{recent.length===0?<p>Waiting for scan events...</p>:recent.map((event,index)=><p key={index}><time>{event.ts?new Date(event.ts).toLocaleTimeString([], {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'}):'-'}</time><b>{event.level??'info'}</b>{event.msg??String(event)}</p>)}</div></div>
}

function TimelineChart({ data }: { data: TimelinePoint[] }) {
  if (data.length === 0) return <div className="dashboard-chart-empty">Findings trend appears after scans complete.</div>
  const width = 640, height = 176, left = 30, right = 8, top = 12, bottom = 24
  const sevs = ['low', 'medium', 'high', 'critical'] as const
  const peak = Math.max(...data.flatMap(point => sevs.map(sev => point[sev] ?? 0)), 0)
  // Even integer headroom: the three axis labels (max, max/2, 0) stay distinct integers.
  const headroom = Math.max(Math.ceil(peak * 1.15), 2)
  const max = headroom + (headroom % 2)
  const x = (index: number) => data.length <= 1 ? left + (width - left - right) / 2 : left + index / (data.length - 1) * (width - left - right)
  const y = (value: number) => height - bottom - value / max * (height - top - bottom)
  const path = (sev: typeof sevs[number]) => data.map((point, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(point[sev] ?? 0).toFixed(1)}`).join(' ')
  return <svg className="dashboard-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Findings over the last 30 days">
    {[0, .25, .5, .75, 1].map(tick => <line key={tick} x1={left} x2={width - right} y1={top + tick * (height - top - bottom)} y2={top + tick * (height - top - bottom)} stroke="var(--border)" />)}
    {[0, .5, 1].map(tick => <text key={tick} x={left - 7} y={top + tick * (height - top - bottom) + 3} fontSize="10" fill="var(--text-2)" textAnchor="end">{max - tick * max}</text>)}
    {sevs.map(sev => <path key={sev} d={path(sev)} fill="none" stroke={`var(--sev-${sev})`} strokeWidth="2" vectorEffect="non-scaling-stroke" />)}
    {[0, Math.floor((data.length - 1) / 2), data.length - 1].map((index, position) => <text key={position} x={x(index)} y={height - 3} fontSize="10" fill="var(--text-2)" textAnchor={position === 0 ? 'start' : position === 2 ? 'end' : 'middle'}>{position === 2 ? 'TODAY' : `-${data.length - 1 - index}D`}</text>)}
  </svg>
}
