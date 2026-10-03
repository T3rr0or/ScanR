import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { libraryApi, type LibraryEntry } from '@/api/library'
import { SevTag } from '@/components/ui'

/** Search the finding library and pick one entry. */
export default function LibraryPicker({ onPick, selectedId }: { onPick: (entry: LibraryEntry) => void; selectedId?: string | null }) {
  const [q, setQ] = useState('')
  const { data: entries = [], isLoading } = useQuery({
    queryKey: ['library', q],
    queryFn: () => libraryApi.list(q ? { q } : undefined),
    placeholderData: prev => prev,
  })
  return (
    <div className="library-picker">
      <input className="input" placeholder="Search the finding library…" value={q} onChange={e => setQ(e.target.value)} aria-label="Search the finding library" />
      <ul role="listbox" aria-label="Library entries">
        {entries.map(e => (
          <li key={e.id}>
            <button type="button" role="option" aria-selected={selectedId === e.id} className={selectedId === e.id ? 'is-selected' : ''} onClick={() => onPick(e)}>
              <SevTag severity={e.severity} />
              <span>{e.title}</span>
            </button>
          </li>
        ))}
        {!isLoading && entries.length === 0 && <li className="library-picker-empty">No matching entries</li>}
      </ul>
    </div>
  )
}
