import { useQuery } from '@tanstack/react-query'
import api from '@/api/client'
import { scansApi } from '@/api/scans'
import { analyticsApi } from '@/api/analytics'
import SeverityDonut from '@/components/charts/SeverityDonut'
import FindingsTimeline from '@/components/charts/FindingsTimeline'
import TopVulnerableHosts from '@/components/charts/TopVulnerableHosts'
import ScanActivityHeatmap from '@/components/charts/ScanActivityHeatmap'

export default function Dashboard() {
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
  const { data: scanActivity = [] } = useQuery({
    queryKey: ['analytics', 'scan-activity'],
    queryFn: () => analyticsApi.scanActivity(30),
    refetchInterval: 60_000,
  })

  const running = scans.filter(s => s.status === 'running')
  const recent = scans.slice(0, 5)

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: 'Total Scans', value: stats?.scans_total ?? 0, color: 'bg-blue-50 text-blue-700' },
          { label: 'Running', value: stats?.scans_running ?? 0, color: 'bg-yellow-50 text-yellow-700' },
          { label: 'Hosts Found', value: stats?.hosts_total ?? 0, color: 'bg-green-50 text-green-700' },
          { label: 'Critical Findings', value: stats?.findings_critical ?? 0, color: 'bg-red-50 text-red-700' },
        ].map(({ label, value, color }) => (
          <div key={label} className={`${color} rounded-xl p-5`}>
            <div className="text-3xl font-bold">{value}</div>
            <div className="text-sm font-medium mt-1 opacity-80">{label}</div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Severity Distribution</h3>
          <div className="h-52">
            <SeverityDonut data={severityDist} />
          </div>
        </div>
        <div className="lg:col-span-2 bg-white border border-gray-200 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Findings Timeline (30 days)</h3>
          <div className="h-52">
            <FindingsTimeline data={timeline} />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Top Vulnerable Hosts</h3>
          <div className="h-56">
            <TopVulnerableHosts data={topHosts} />
          </div>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-700 mb-3">Scan Activity (30 days)</h3>
          <div className="h-56">
            <ScanActivityHeatmap data={scanActivity} />
          </div>
        </div>
      </div>

      {/* Running scans */}
      {running.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Active Scans</h2>
          <div className="space-y-2">
            {running.map(scan => (
              <div key={scan.id} className="bg-white border border-yellow-200 rounded-lg px-4 py-3 flex items-center gap-4">
                <div className="w-2 h-2 bg-yellow-400 rounded-full animate-pulse" />
                <span className="font-medium">{scan.name}</span>
                <span className="text-sm text-gray-500">{scan.hosts_up} hosts up</span>
                <span className="text-sm text-gray-500 ml-auto">
                  C:{scan.findings_critical} H:{scan.findings_high} M:{scan.findings_medium}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent scans */}
      <div>
        <h2 className="text-lg font-semibold mb-3">Recent Scans</h2>
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="px-4 py-3 text-left font-medium text-gray-600">Name</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Hosts</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Findings</th>
                <th className="px-4 py-3 text-left font-medium text-gray-600">Date</th>
              </tr>
            </thead>
            <tbody>
              {recent.map(scan => (
                <tr key={scan.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="px-4 py-3 font-medium">{scan.name}</td>
                  <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                  <td className="px-4 py-3 text-gray-600">{scan.hosts_up}/{scan.hosts_total}</td>
                  <td className="px-4 py-3">
                    <span className="text-red-600 font-medium">{scan.findings_critical}C</span>
                    {' '}<span className="text-orange-500">{scan.findings_high}H</span>
                    {' '}<span className="text-yellow-600">{scan.findings_medium}M</span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
              {recent.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-400">No scans yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    running: 'bg-yellow-100 text-yellow-700',
    completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700',
    cancelled: 'bg-gray-100 text-gray-600',
    pending: 'bg-blue-100 text-blue-700',
  }
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${colors[status] ?? 'bg-gray-100 text-gray-600'}`}>
      {status}
    </span>
  )
}
