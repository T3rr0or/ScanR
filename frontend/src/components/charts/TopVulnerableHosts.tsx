import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

interface Host {
  id: string
  ip: string
  hostname: string | null
  finding_count: number
}

interface Props {
  data: Host[]
}

export default function TopVulnerableHosts({ data }: Props) {
  if (data.length === 0) {
    return <div className="flex items-center justify-center h-full text-gray-500 text-sm">No data</div>
  }

  const chartData = data.map(h => ({
    name: h.hostname || h.ip,
    findings: h.finding_count,
  }))

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} />
        <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#9ca3af' }} width={90} />
        <Tooltip
          contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 6 }}
          labelStyle={{ color: '#e5e7eb' }}
          itemStyle={{ color: '#d1d5db' }}
        />
        <Bar dataKey="findings" fill="#dc2626" radius={[0, 3, 3, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}
