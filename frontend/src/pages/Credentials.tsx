import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Trash2, Plus } from 'lucide-react'
import { credentialsApi, type CredentialCreate } from '@/api/credentials'

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
        secret_data: form.type === 'ssh'
          ? { private_key: form.private_key }
          : { password: form.password },
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
    <div className="p-8 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Credentials</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          <Plus size={16} /> New Credential
        </button>
      </div>

      <p className="text-sm text-gray-500 mb-5">
        Credentials are used by authenticated plugins (SSH audit, AD password policy, SMB share enumeration).
        Secret data is encrypted at rest.
      </p>

      {showForm && (
        <div className="bg-white border border-gray-200 rounded-xl p-5 mb-6 space-y-4">
          <h2 className="font-semibold text-sm">New Credential</h2>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Name *</label>
              <input
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                placeholder="e.g. Domain Admin"
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
                <option value="password">Password</option>
                <option value="ssh">SSH Key</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Username</label>
              <input
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                placeholder="administrator"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Description</label>
              <input
                value={form.description}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                placeholder="Optional note"
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
              />
            </div>
          </div>

          {form.type === 'password' ? (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Password *</label>
              <input
                type="password"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
              />
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1.5">Private Key (PEM) *</label>
              <textarea
                value={form.private_key}
                onChange={e => setForm(f => ({ ...f, private_key: e.target.value }))}
                rows={6}
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;..."
                className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono text-xs"
              />
            </div>
          )}

          <div className="flex gap-3">
            <button
              onClick={() => createMut.mutate()}
              disabled={
                !form.name ||
                (form.type === 'password' && !form.password) ||
                (form.type === 'ssh' && !form.private_key) ||
                createMut.isPending
              }
              className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Saving...' : 'Save'}
            </button>
            <button
              onClick={() => setShowForm(false)}
              className="px-4 py-2 text-gray-600 rounded-lg text-sm hover:bg-gray-100"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              {['Name', 'Type', 'Username', 'Description', 'Created', ''].map(h => (
                <th key={h} className="px-4 py-3 text-left font-medium text-gray-600">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {credentials.map(c => (
              <tr key={c.id} className="border-b border-gray-100 hover:bg-gray-50">
                <td className="px-4 py-3 font-medium flex items-center gap-2">
                  <Key size={14} className="text-gray-400" />{c.name}
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded font-mono">{c.type}</span>
                </td>
                <td className="px-4 py-3 text-gray-500 font-mono text-xs">{c.username ?? '—'}</td>
                <td className="px-4 py-3 text-gray-400 text-xs">{c.description ?? '—'}</td>
                <td className="px-4 py-3 text-gray-400 text-xs">{new Date(c.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => { if (confirm(`Delete credential "${c.name}"?`)) deleteMut.mutate(c.id) }}
                    className="p-1 text-gray-400 hover:text-red-600"
                    title="Delete"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {credentials.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-400">
                  No credentials — add one to enable authenticated plugins
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
