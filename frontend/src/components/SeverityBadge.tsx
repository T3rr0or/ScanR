const COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-green-100 text-green-700 border-green-200',
  info: 'bg-blue-100 text-blue-700 border-blue-200',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase ${COLORS[severity] ?? 'bg-gray-100 text-gray-600 border-gray-200'}`}>
      {severity}
    </span>
  )
}
