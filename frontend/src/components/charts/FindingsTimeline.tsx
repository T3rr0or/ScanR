import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

interface DataPoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface Props {
  data: DataPoint[]
}

export default function FindingsTimeline({ data }: Props) {
  const formatDate = (d: string) => {
    const dt = new Date(d)
    return `${dt.getMonth() + 1}/${dt.getDate()}`
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
        <defs>
          {[
            ['critical', '#dc2626'],
            ['high', '#ea580c'],
            ['medium', '#d97706'],
            ['low', '#16a34a'],
            ['info', '#2563eb'],
          ].map(([key, color]) => (
            <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={color} stopOpacity={0.3} />
              <stop offset="95%" stopColor={color} stopOpacity={0.05} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#374151" opacity={0.3} />
        <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 11, fill: '#9ca3af' }} />
        <YAxis tick={{ fontSize: 11, fill: '#9ca3af' }} />
        <Tooltip
          contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: 6 }}
          labelStyle={{ color: '#e5e7eb' }}
          itemStyle={{ color: '#d1d5db' }}
        />
        <Legend formatter={v => String(v).charAt(0).toUpperCase() + String(v).slice(1)} />
        {[
          ['critical', '#dc2626'],
          ['high', '#ea580c'],
          ['medium', '#d97706'],
          ['low', '#16a34a'],
          ['info', '#2563eb'],
        ].map(([key, color]) => (
          <Area
            key={key}
            type="monotone"
            dataKey={key}
            stroke={color}
            fill={`url(#grad-${key})`}
            strokeWidth={1.5}
            dot={false}
            activeDot={{ r: 3 }}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}
