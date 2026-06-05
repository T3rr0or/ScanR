import type { FindingSortKey } from '@/hooks/useSortableFindings'

interface Props {
  label: string
  sortKey: FindingSortKey
  active: FindingSortKey
  dir: 'asc' | 'desc'
  onSort: (k: FindingSortKey) => void
  style?: React.CSSProperties
}

export default function SortableTh({ label, sortKey, active, dir, onSort, style }: Props) {
  const isActive = active === sortKey
  return (
    <th
      onClick={() => onSort(sortKey)}
      style={{
        cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
        color: isActive ? 'var(--accent)' : undefined,
        ...style,
      }}
    >
      {label}
      <span style={{ marginLeft: 4, opacity: isActive ? 1 : 0.25, fontSize: 9 }}>
        {isActive ? (dir === 'asc' ? '▲' : '▼') : '⇅'}
      </span>
    </th>
  )
}
