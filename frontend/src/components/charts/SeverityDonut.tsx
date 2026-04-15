import { Cell, Pie, PieChart, Tooltip, Legend, ResponsiveContainer } from 'recharts'

interface Props {
  data: Record<string, number>
}

const COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
  info: '#2563eb',
}

export default function SeverityDonut({ data }: Props) {
  const entries = Object.entries(data)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  if (entries.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        No findings
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height="100%">
      <PieChart>
        <Pie
          data={entries}
          cx="50%"
          cy="50%"
          innerRadius={50}
          outerRadius={80}
          paddingAngle={2}
          dataKey="value"
        >
          {entries.map(entry => (
            <Cell key={entry.name} fill={COLORS[entry.name] ?? '#6b7280'} />
          ))}
        </Pie>
        <Tooltip formatter={(value, name) => [value, String(name).charAt(0).toUpperCase() + String(name).slice(1)]} />
        <Legend formatter={v => String(v).charAt(0).toUpperCase() + String(v).slice(1)} />
      </PieChart>
    </ResponsiveContainer>
  )
}
