interface DayEntry {
  date: string
  scans: number
}

interface Props {
  data: DayEntry[]
}

function intensity(scans: number): string {
  if (scans === 0) return 'bg-gray-100'
  if (scans === 1) return 'bg-blue-200'
  if (scans <= 3) return 'bg-blue-400'
  if (scans <= 6) return 'bg-blue-600'
  return 'bg-blue-800'
}

export default function ScanActivityHeatmap({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        No activity
      </div>
    )
  }

  return (
    <div className="flex flex-wrap gap-1 items-start content-start h-full overflow-hidden">
      {data.map(({ date, scans }) => (
        <div
          key={date}
          title={`${date}: ${scans} scan${scans !== 1 ? 's' : ''}`}
          className={`w-4 h-4 rounded-sm ${intensity(scans)} transition-colors cursor-default`}
        />
      ))}
      <div className="w-full flex items-center gap-2 mt-2 text-xs text-gray-400">
        <span>Less</span>
        {['bg-gray-100', 'bg-blue-200', 'bg-blue-400', 'bg-blue-600', 'bg-blue-800'].map(c => (
          <div key={c} className={`w-3 h-3 rounded-sm ${c}`} />
        ))}
        <span>More</span>
      </div>
    </div>
  )
}
