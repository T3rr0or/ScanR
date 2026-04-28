import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Trash2, Plus, ShieldCheck } from 'lucide-react'
import { credentialsApi, type CredentialCreate } from '@/api/credentials'
import { relTime, EmptyState } from '@/components/ui'

export default function Credentials() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<{
    name: string; type: string; username: string; description: string
    password: string; private_key: string
  }>({ name: '', type: 'password', username: '', description: '', password: '', private_key: '' })

  const { data: credentials = [] } = useQuery({
    queryKey: ['credentials'],
    queryFn: credentialsApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => {
      const body: CredentialCreate = {
        name: form.name,
        type: form.type,
        username: form.username || undefined,
        description: form.description || undefined,
        secret_data: form.type === 'ssh' ? { private_key: form.private_key } : { password: form.password },
      }
      return credentialsApi.create(body)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      setShowForm(false)
      setForm({ name: '', type: 'password', username: '', description: '', password: '', private_key: '' })
    },
  })

  const deleteMut = useMutation({
    mutationFn: credentialsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })

  return (
    <div className="page-pad" style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Key size={18} style={{ color: 'var(--accent)' }} />
          <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Credentials</h1>
        </div>
        <button onClick={() => setShowForm(!showForm)} className="btn btn-primary btn-sm">
          <Plus size={13} /> New Credential
        </button>
      </div>

      <p style={{ fontSize: 12, color: 'var(--text-3)', marginBottom: 20 }}>
        Used by authenticated plugins (SSH audit, AD password policy, SMB share enumeration). Secret data is encrypted at rest.
      </p>

      {/* Create form */}
      {showForm && (
        <div className="panel" style={{ marginBottom: 20, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 14 }}>New Credential</div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
            <div>
              <label className="label">Name *</label>
              <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Domain Admin" className="input" />
            </div>
            <div>
              <label className="label">Type</label>
              <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))} className="select-field">
                <option value="password">Password</option>
                <option value="ssh">SSH Key</option>
              </select>
            </div>
            <div>
              <label className="label">Username</label>
              <input value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="administrator" className="input" />
            </div>
            <div>
              <label className="label">Description</label>
              <input value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional note" className="input" />
            </div>
          </div>

          {form.type === 'password' ? (
            <div style={{ marginBottom: 12 }}>
              <label className="label">Password *</label>
              <input type="password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} className="input" />
            </div>
          ) : (
            <div style={{ marginBottom: 12 }}>
              <label className="label">Private Key (PEM) *</label>
              <textarea
                value={form.private_key}
                onChange={e => setForm(f => ({ ...f, private_key: e.target.value }))}
                rows={5}
                placeholder={"-----BEGIN RSA PRIVATE KEY-----\n..."}
                className="textarea"
                style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}
              />
            </div>
          )}

          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => createMut.mutate()}
              disabled={
                !form.name ||
                (form.type === 'password' && !form.password) ||
                (form.type === 'ssh' && !form.private_key) ||
                createMut.isPending
              }
              className="btn btn-primary btn-sm"
            >
              {createMut.isPending ? 'Saving…' : 'Save'}
            </button>
            <button onClick={() => setShowForm(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Type</th>
              <th>Username</th>
              <th>Description</th>
              <th>Created</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {credentials.map(c => (
              <tr key={c.id}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ShieldCheck size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    <span style={{ fontWeight: 500, color: 'var(--text-0)' }}>{c.name}</span>
                  </div>
                </td>
                <td>
                  <span className="mono" style={{ fontSize: 10, background: 'var(--bg-3)', color: 'var(--text-2)', padding: '2px 6px', borderRadius: 4 }}>
                    {c.type}
                  </span>
                </td>
                <td className="mono dimmer" style={{ fontSize: 11 }}>{c.username ?? '—'}</td>
                <td className="dimmer" style={{ fontSize: 11 }}>{c.description ?? '—'}</td>
                <td className="dimmer" style={{ fontSize: 11 }}>{relTime(c.created_at)}</td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    onClick={() => { if (confirm(`Delete credential "${c.name}"?`)) deleteMut.mutate(c.id) }}
                    className="btn btn-ghost btn-icon btn-sm"
                    title="Delete"
                    style={{ color: 'var(--sev-high)' }}
                  >
                    <Trash2 size={13} />
                  </button>
                </td>
              </tr>
            ))}
            {credentials.length === 0 && (
              <EmptyState
                icon={<Key size={28} />}
                message="No credentials — add one to enable authenticated plugins"
              />
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
