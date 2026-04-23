import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, Eye, X } from 'lucide-react'
import { wordlistsApi, type Wordlist, type WordlistPreview } from '@/api/wordlists'

function TypePill({ type }: { type: Wordlist['type'] }) {
  const styles: Record<string, string> = {
    usernames: 'bg-blue-100 text-blue-700',
    passwords: 'bg-orange-100 text-orange-700',
    credentials: 'bg-red-100 text-red-700',
    paths: 'bg-gray-100 text-gray-600',
  }
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-medium ${styles[type] ?? 'bg-gray-100 text-gray-600'}`}>
      {type}
    </span>
  )
}

function WordlistTable({
  wordlists,
  showDelete,
  onPreview,
  onDelete,
}: {
  wordlists: Wordlist[]
  showDelete: boolean
  onPreview: (id: string) => void
  onDelete?: (id: string) => void
}) {
  const cols = ['Name', 'Type', 'Entries', 'Description', '']
  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-50 border-b border-gray-200">
            {cols.map(h => (
              <th key={h} className="px-4 py-3 text-left font-medium text-gray-600">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {wordlists.map(w => (
            <tr key={w.id} className="border-b border-gray-100 hover:bg-gray-50">
              <td className="px-4 py-3 font-medium">{w.name}</td>
              <td className="px-4 py-3"><TypePill type={w.type} /></td>
              <td className="px-4 py-3 font-mono text-xs text-gray-600">{w.entry_count.toLocaleString()}</td>
              <td className="px-4 py-3 text-gray-400 text-xs">{w.description ?? '—'}</td>
              <td className="px-4 py-3 text-right">
                <div className="flex items-center justify-end gap-1">
                  <button
                    onClick={() => onPreview(w.id)}
                    className="p-1 text-gray-400 hover:text-blue-600"
                    title="Preview"
                  >
                    <Eye size={14} />
                  </button>
                  {showDelete && onDelete && (
                    <button
                      onClick={() => { if (confirm(`Delete wordlist "${w.name}"?`)) onDelete(w.id) }}
                      className="p-1 text-gray-400 hover:text-red-600"
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
          {wordlists.length === 0 && (
            <tr>
              <td colSpan={5} className="px-4 py-6 text-center text-gray-400 text-sm">
                None
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

function PreviewModal({ preview, onClose }: { preview: WordlistPreview; onClose: () => void }) {
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
      }}
      onClick={onClose}
    >
      <div
        className="bg-white rounded-xl shadow-2xl w-full max-w-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <span className="font-semibold text-sm">{preview.name}</span>
            <span className="text-xs text-gray-400 ml-3 font-mono">{preview.entry_count.toLocaleString()} entries</span>
          </div>
          <button onClick={onClose} className="p-1 text-gray-400 hover:text-gray-700">
            <X size={16} />
          </button>
        </div>
        <div
          style={{
            background: '#0d1117',
            color: '#c9d1d9',
            fontFamily: 'var(--font-mono, monospace)',
            fontSize: 12,
            padding: '12px 16px',
            maxHeight: 400,
            overflowY: 'auto',
            lineHeight: 1.6,
          }}
        >
          {preview.preview.map((line, i) => (
            <div key={i}>{line}</div>
          ))}
          {preview.preview.length === 0 && (
            <div style={{ color: '#6e7681' }}>No entries to preview.</div>
          )}
        </div>
        <div className="px-5 py-3 bg-gray-50 text-xs text-gray-400 border-t border-gray-200">
          Showing first {preview.preview.length} of {preview.entry_count.toLocaleString()} entries
        </div>
      </div>
    </div>
  )
}

export default function Wordlists() {
  const qc = useQueryClient()
  const [showUpload, setShowUpload] = useState(false)
  const [preview, setPreview] = useState<WordlistPreview | null>(null)
  const [form, setForm] = useState({ name: '', type: 'passwords', description: '' })
  const fileRef = useRef<HTMLInputElement>(null)

  const { data: wordlists = [], isLoading } = useQuery({
    queryKey: ['wordlists'],
    queryFn: wordlistsApi.list,
  })

  const uploadMut = useMutation({
    mutationFn: () => {
      const file = fileRef.current?.files?.[0]
      if (!file) throw new Error('No file selected')
      return wordlistsApi.upload(file, form.name, form.type, form.description)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['wordlists'] })
      setShowUpload(false)
      setForm({ name: '', type: 'passwords', description: '' })
      if (fileRef.current) fileRef.current.value = ''
    },
  })

  const deleteMut = useMutation({
    mutationFn: wordlistsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['wordlists'] }),
  })

  const previewMut = useMutation({
    mutationFn: wordlistsApi.preview,
    onSuccess: (data) => setPreview(data),
  })

  const builtins = wordlists.filter(w => w.is_builtin)
  const custom = wordlists.filter(w => !w.is_builtin)

  return (
    <div className="p-8 max-w-5xl">
      {preview && (
        <PreviewModal preview={preview} onClose={() => setPreview(null)} />
      )}

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold">Wordlists</h1>
          <p className="text-sm text-gray-500 mt-1">
            Custom username, password and credential lists for brute-force testing
          </p>
        </div>
        <button
          onClick={() => setShowUpload(v => !v)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          <Upload size={15} /> Upload
        </button>
      </div>

      {/* Upload form */}
      {showUpload && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 mb-6 space-y-4">
          <h2 className="font-semibold text-sm">Upload Wordlist</h2>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Name *</label>
              <input
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Top 1000 passwords"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Type</label>
              <select
                value={form.type}
                onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
              >
                <option value="usernames">Usernames</option>
                <option value="passwords">Passwords</option>
                <option value="credentials">Credentials (user:password)</option>
                <option value="paths">Paths</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1.5">Description <span className="font-normal text-gray-400">(optional)</span></label>
            <input
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Brief note about this list"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1.5">File *</label>
            <input
              ref={fileRef}
              type="file"
              accept=".txt,.csv,text/plain"
              className="text-sm text-gray-600 file:mr-3 file:py-1.5 file:px-3 file:rounded file:border-0 file:bg-gray-100 file:text-gray-700 file:text-xs file:font-medium hover:file:bg-gray-200"
            />
            <p className="text-xs text-gray-400 mt-1.5">
              One entry per line. For credentials: <span className="font-mono">user:password</span> format.
            </p>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => uploadMut.mutate()}
              disabled={!form.name || uploadMut.isPending}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
            >
              {uploadMut.isPending ? 'Uploading...' : 'Upload'}
            </button>
            <button
              onClick={() => {
                setShowUpload(false)
                setForm({ name: '', type: 'passwords', description: '' })
                if (fileRef.current) fileRef.current.value = ''
              }}
              className="px-4 py-2 text-gray-600 rounded-lg text-sm hover:bg-gray-100"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-sm text-gray-400 py-8 text-center">Loading wordlists…</div>
      ) : (
        <div className="space-y-8">
          {/* Built-in section */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-3">Built-in</p>
            <WordlistTable
              wordlists={builtins}
              showDelete={false}
              onPreview={(id) => previewMut.mutate(id)}
            />
          </div>

          {/* My Wordlists section */}
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 mb-3">My Wordlists</p>
            <WordlistTable
              wordlists={custom}
              showDelete={true}
              onPreview={(id) => previewMut.mutate(id)}
              onDelete={(id) => deleteMut.mutate(id)}
            />
          </div>
        </div>
      )}
    </div>
  )
}
