interface DayEntry {
  date: string
  scans: number
}

interface Props {
  data: DayEntry[]
}

function intensity(scans: number): string {
  if (scans === 0) return '#202020'
  if (scans === 1) return 'rgba(255,77,26,.25)'
  if (scans <= 3) return 'rgba(255,77,26,.5)'
  if (scans <= 6) return 'rgba(255,77,26,.75)'
  return '#ff4d1a'
}

export default function ScanActivityHeatmap({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-sm" style={{ color: 'var(--text-2)' }}>
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
          className="w-4 h-4 cursor-default"
          style={{ background: intensity(scans) }}
        />
      ))}
      <div className="w-full flex items-center gap-2 mt-2 text-xs" style={{ color: 'var(--text-2)' }}>
        <span>Less</span>
        {[0, 1, 2, 4, 7].map(c => (
          <div key={c} className="w-3 h-3" style={{ background: intensity(c) }} />
        ))}
        <span>More</span>
      </div>
    </div>
  )
}
