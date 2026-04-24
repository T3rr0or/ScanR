import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, Eye, X } from 'lucide-react'
import { wordlistsApi, type Wordlist, type WordlistPreview } from '@/api/wordlists'

const TYPE_COLOR: Record<string, string> = {
  usernames:   'var(--accent)',
  passwords:   'var(--sev-medium)',
  credentials: 'var(--sev-high)',
  paths:       'var(--text-3)',
}
const TYPE_BG: Record<string, string> = {
  usernames:   'var(--accent-soft)',
  passwords:   'oklch(0.24 0.08 85 / 0.25)',
  credentials: 'oklch(0.24 0.08 30 / 0.25)',
  paths:       'var(--bg-3)',
}

function TypePill({ type }: { type: Wordlist['type'] }) {
  return (
    <span className="mono" style={{
      fontSize: 10.5, fontWeight: 600,
      padding: '2px 7px', borderRadius: 4,
      background: TYPE_BG[type] ?? 'var(--bg-3)',
      color: TYPE_COLOR[type] ?? 'var(--text-3)',
    }}>
      {type}
    </span>
  )
}

function WordlistTable({ wordlists, showDelete, onPreview, onDelete }: {
  wordlists: Wordlist[]
  showDelete: boolean
  onPreview: (id: string) => void
  onDelete?: (id: string) => void
}) {
  return (
    <div className="panel" style={{ overflow: 'hidden' }}>
      <table className="tbl">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Entries</th>
            <th>Description</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {wordlists.map(w => (
            <tr key={w.id}>
              <td style={{ fontWeight: 500, color: 'var(--text-0)' }}>{w.name}</td>
              <td><TypePill type={w.type} /></td>
              <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)' }}>{w.entry_count.toLocaleString()}</td>
              <td className="dimmer" style={{ fontSize: 12 }}>{w.description ?? '—'}</td>
              <td style={{ textAlign: 'right' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 4 }}>
                  <button onClick={() => onPreview(w.id)} className="btn btn-ghost btn-icon btn-sm" title="Preview">
                    <Eye size={13} />
                  </button>
                  {showDelete && onDelete && (
                    <button
                      onClick={() => { if (confirm(`Delete "${w.name}"?`)) onDelete(w.id) }}
                      className="btn btn-ghost btn-icon btn-sm"
                      title="Delete"
                      style={{ color: 'var(--sev-high)' }}
                    >
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              </td>
            </tr>
          ))}
          {wordlists.length === 0 && (
            <tr>
              <td colSpan={5} style={{ padding: '24px 16px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
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
      style={{ position: 'fixed', inset: 0, background: 'oklch(0.05 0.01 255 / 0.7)', zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24 }}
      onClick={onClose}
    >
      <div
        className="panel"
        style={{ width: '100%', maxWidth: 640, overflow: 'hidden', boxShadow: '0 24px 80px #0009', padding: 0 }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-2)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-0)' }}>{preview.name}</span>
            <span className="mono dimmer" style={{ fontSize: 11 }}>{preview.entry_count.toLocaleString()} entries</span>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-icon btn-sm"><X size={14} /></button>
        </div>
        <div className="console" style={{ maxHeight: 400, overflowY: 'auto', borderRadius: 0 }}>
          {preview.preview.map((line, i) => (
            <div key={i} className="ln" style={{ padding: '1px 14px' }}>
              <span className="mono" style={{ color: 'var(--text-1)', fontSize: 12 }}>{line}</span>
            </div>
          ))}
          {preview.preview.length === 0 && (
            <div style={{ padding: 14, color: 'var(--text-3)', fontSize: 12 }}>No entries to preview.</div>
          )}
        </div>
        <div style={{ padding: '8px 16px', borderTop: '1px solid var(--border)', background: 'var(--bg-2)' }}>
          <span className="dimmer" style={{ fontSize: 11 }}>Showing first {preview.preview.length} of {preview.entry_count.toLocaleString()} entries</span>
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

  const { data: wordlists = [], isLoading } = useQuery({ queryKey: ['wordlists'], queryFn: wordlistsApi.list })

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
    onSuccess: data => setPreview(data),
  })

  const builtins = wordlists.filter(w => w.is_builtin)
  const custom   = wordlists.filter(w => !w.is_builtin)

  return (
    <div style={{ padding: '24px 28px', maxWidth: 960 }}>
      {preview && <PreviewModal preview={preview} onClose={() => setPreview(null)} />}

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)', margin: 0 }}>Wordlists</h1>
          <p style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 4 }}>
            Custom username, password and credential lists for brute-force testing
          </p>
        </div>
        <button onClick={() => setShowUpload(v => !v)} className="btn btn-primary btn-sm">
          <Upload size={13} /> Upload
        </button>
      </div>

      {/* Upload form */}
      {showUpload && (
        <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 14 }}>Upload Wordlist</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <label className="label">Name</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Top 1000 passwords" className="input" />
            </div>
            <div>
              <label className="label">Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))} className="select-field">
                <option value="usernames">Usernames</option>
                <option value="passwords">Passwords</option>
                <option value="credentials">Credentials (user:password)</option>
                <option value="paths">Paths</option>
              </select>
            </div>
          </div>
          <div style={{ marginBottom: 10 }}>
            <label className="label">Description <span className="dimmer" style={{ fontWeight: 400 }}>(optional)</span></label>
            <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
              placeholder="Brief note about this list" className="input" />
          </div>
          <div style={{ marginBottom: 14 }}>
            <label className="label">File (.txt, one entry per line)</label>
            <input ref={fileRef} type="file" accept=".txt,.csv,text/plain"
              style={{ fontSize: 12, color: 'var(--text-2)' }} />
            <div className="dimmer" style={{ fontSize: 11, marginTop: 4 }}>
              For credentials: <span className="mono">user:password</span> format per line.
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => uploadMut.mutate()} disabled={!form.name || uploadMut.isPending} className="btn btn-primary btn-sm">
              {uploadMut.isPending ? 'Uploading…' : 'Upload'}
            </button>
            <button onClick={() => { setShowUpload(false); setForm({ name: '', type: 'passwords', description: '' }); if (fileRef.current) fileRef.current.value = '' }}
              className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="dimmer" style={{ fontSize: 13, padding: '20px 0' }}>Loading…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          <section>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 8 }}>Built-in</div>
            <WordlistTable wordlists={builtins} showDelete={false} onPreview={id => previewMut.mutate(id)} />
          </section>
          <section>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 8 }}>My Wordlists</div>
            <WordlistTable wordlists={custom} showDelete onPreview={id => previewMut.mutate(id)} onDelete={id => deleteMut.mutate(id)} />
          </section>
        </div>
      )}
    </div>
  )
}
