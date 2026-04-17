import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Key, Webhook, Copy, Check, Trash2, Plus, Send, Database, RefreshCw } from 'lucide-react'
import { apiKeysApi, type APIKeyCreated } from '@/api/apiKeys'
import { webhooksApi } from '@/api/webhooks'
import api from '@/api/client'

export default function Settings() {
  const [activeTab, setActiveTab] = useState<'api-keys' | 'webhooks' | 'cve'>('api-keys')

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Settings</h1>

      <div className="flex gap-1 border-b border-gray-200 mb-6">
        <TabBtn active={activeTab === 'api-keys'} onClick={() => setActiveTab('api-keys')} icon={<Key size={14} />} label="API Keys" />
        <TabBtn active={activeTab === 'webhooks'} onClick={() => setActiveTab('webhooks')} icon={<Webhook size={14} />} label="Webhooks" />
        <TabBtn active={activeTab === 'cve'} onClick={() => setActiveTab('cve')} icon={<Database size={14} />} label="CVE Database" />
      </div>

      {activeTab === 'api-keys' && <ApiKeysSection />}
      {activeTab === 'webhooks' && <WebhooksSection />}
      {activeTab === 'cve' && <CveDatabaseSection />}
    </div>
  )
}

function CveDatabaseSection() {
  const qc = useQueryClient()
  const { data: status } = useQuery({
    queryKey: ['cve-status'],
    queryFn: () => api.get('/system/cve-status').then(r => r.data),
    refetchInterval: 5000,
  })

  const refreshMut = useMutation({
    mutationFn: () => api.post('/system/cve-refresh'),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['cve-status'] }),
  })

  return (
    <div className="space-y-4">
      <div className="bg-white border border-gray-200 rounded-xl p-5">
        <h2 className="font-semibold text-gray-900 mb-4">CVE Feed Status</h2>
        <div className="grid grid-cols-2 gap-4 mb-5 text-sm">
          <div>
            <div className="text-xs text-gray-500 mb-1">NVD Database</div>
            <div className={`font-medium ${status?.nvd_db_exists ? 'text-green-600' : 'text-red-500'}`}>
              {status?.nvd_db_exists ? 'Loaded' : 'Not downloaded'}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 mb-1">CISA KEV Entries</div>
            <div className="font-medium text-gray-900">{status?.kev_count ?? '—'}</div>
          </div>
          <div className="col-span-2">
            <div className="text-xs text-gray-500 mb-1">Last Updated</div>
            <div className="font-mono text-xs text-gray-700">
              {status?.last_updated
                ? new Date(status.last_updated).toLocaleString()
                : 'Never'}
            </div>
          </div>
        </div>
        <button
          onClick={() => refreshMut.mutate()}
          disabled={refreshMut.isPending}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          <RefreshCw size={14} className={refreshMut.isPending ? 'animate-spin' : ''} />
          {refreshMut.isPending ? 'Refreshing...' : 'Refresh CVE Feeds'}
        </button>
        <p className="text-xs text-gray-400 mt-2">
          Downloads NVD feeds (2020–present) and CISA Known Exploited Vulnerabilities catalog.
          Takes a few minutes. Runs automatically on first worker boot.
        </p>
      </div>
    </div>
  )
}

function TabBtn({ active, onClick, icon, label }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
        active ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
      }`}
    >
      {icon}{label}
    </button>
  )
}

const ALL_SCOPES = [
  { value: 'scans:read',        label: 'Scans — read',         desc: 'List and view scans' },
  { value: 'scans:write',       label: 'Scans — write',        desc: 'Create, launch, cancel, delete scans' },
  { value: 'findings:read',     label: 'Findings — read',      desc: 'List and view findings' },
  { value: 'findings:triage',   label: 'Findings — triage',    desc: 'Mark false positives, update status' },
  { value: 'reports:read',      label: 'Reports — read',       desc: 'View reports' },
  { value: 'reports:export',    label: 'Reports — export',     desc: 'Generate and download PDF reports' },
  { value: 'credentials:read',  label: 'Credentials — read',   desc: 'List credentials' },
  { value: 'credentials:write', label: 'Credentials — write',  desc: 'Create/delete credentials' },
  { value: 'agents:read',       label: 'Agents — read',        desc: 'List scan agents' },
  { value: 'agents:write',      label: 'Agents — write',       desc: 'Register/remove agents' },
  { value: '*',                 label: 'Full access',          desc: 'All scopes (same as a user session)' },
]

function ApiKeysSection() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [selectedScopes, setSelectedScopes] = useState<string[]>(['scans:read', 'findings:read'])
  const [createdKey, setCreatedKey] = useState<APIKeyCreated | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: keys = [] } = useQuery({ queryKey: ['api-keys'], queryFn: apiKeysApi.list })

  const toggleScope = (s: string) => {
    if (s === '*') {
      setSelectedScopes(['*'])
      return
    }
    setSelectedScopes(prev => {
      const without = prev.filter(x => x !== '*')
      return without.includes(s) ? without.filter(x => x !== s) : [...without, s]
    })
  }

  const createMut = useMutation({
    mutationFn: () => apiKeysApi.create({ name: newKeyName, scopes: selectedScopes }),
    onSuccess: (key) => {
      setCreatedKey(key)
      setShowCreate(false)
      setNewKeyName('')
      setSelectedScopes(['scans:read', 'findings:read'])
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })

  const revokeMut = useMutation({
    mutationFn: apiKeysApi.revoke,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-600">API keys allow CI/CD pipelines and external tools to authenticate with ScanR.</p>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
        >
          <Plus size={14} /> New Key
        </button>
      </div>

      {createdKey && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4">
          <p className="text-sm font-medium text-green-800 mb-2">API key created — copy it now, it won't be shown again:</p>
          <div className="flex items-center gap-2 bg-white border border-green-300 rounded px-3 py-2 font-mono text-sm">
            <span className="flex-1 break-all">{createdKey.key}</span>
            <button onClick={() => copyKey(createdKey.key)} className="text-green-600 hover:text-green-800">
              {copied ? <Check size={16} /> : <Copy size={16} />}
            </button>
          </div>
          <button onClick={() => setCreatedKey(null)} className="mt-2 text-xs text-green-700 underline">Dismiss</button>
        </div>
      )}

      {showCreate && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-3">
          <h3 className="font-medium text-sm">New API Key</h3>
          <input
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. CI/CD pipeline)"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <div>
            <p className="text-xs font-medium text-gray-600 mb-2">Scopes</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
              {ALL_SCOPES.map(s => (
                <label key={s.value} className="flex items-start gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={selectedScopes.includes(s.value) || selectedScopes.includes('*')}
                    onChange={() => toggleScope(s.value)}
                    className="mt-0.5 flex-shrink-0"
                  />
                  <div>
                    <div className="text-xs font-medium text-gray-700">{s.label}</div>
                    <div className="text-xs text-gray-400">{s.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => createMut.mutate()}
              disabled={!newKeyName || selectedScopes.length === 0 || createMut.isPending}
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Creating...' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-gray-600 text-sm hover:text-gray-900">
              Cancel
            </button>
          </div>
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              <th className="px-4 py-3 text-left font-medium text-gray-600">Name</th>
              <th className="px-4 py-3 text-left font-medium text-gray-600">Prefix</th>
              <th className="px-4 py-3 text-left font-medium text-gray-600">Scopes</th>
              <th className="px-4 py-3 text-left font-medium text-gray-600">Last Used</th>
              <th className="px-4 py-3 text-left font-medium text-gray-600">Created</th>
              <th className="px-4 py-3" />
            </tr>
          </thead>
          <tbody>
            {keys.map(k => (
              <tr key={k.id} className="border-b border-gray-100">
                <td className="px-4 py-3 font-medium">{k.name}</td>
                <td className="px-4 py-3 font-mono text-gray-500 text-xs">{k.prefix}...</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {k.scopes.map(s => (
                      <span key={s} className="text-xs bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded font-mono">{s}</span>
                    ))}
                  </div>
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">
                  {k.last_used_at ? new Date(k.last_used_at).toLocaleDateString() : 'Never'}
                </td>
                <td className="px-4 py-3 text-gray-500 text-xs">{new Date(k.created_at).toLocaleDateString()}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => revokeMut.mutate(k.id)}
                    className="text-red-500 hover:text-red-700 p-1"
                    title="Revoke"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {keys.length === 0 && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-400">No API keys</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function WebhooksSection() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', url: '', secret: '', events: ['scan.completed', 'finding.critical'] })

  const { data: webhooks = [] } = useQuery({ queryKey: ['webhooks'], queryFn: webhooksApi.list })

  const createMut = useMutation({
    mutationFn: () => webhooksApi.create({ ...form, secret: form.secret || undefined }),
    onSuccess: () => {
      setShowCreate(false)
      setForm({ name: '', url: '', secret: '', events: ['scan.completed', 'finding.critical'] })
      qc.invalidateQueries({ queryKey: ['webhooks'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: webhooksApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks'] }),
  })

  const testMut = useMutation({
    mutationFn: webhooksApi.test,
  })

  const toggleEvent = (event: string) => {
    setForm(f => ({
      ...f,
      events: f.events.includes(event) ? f.events.filter(e => e !== event) : [...f.events, event],
    }))
  }

  const ALL_EVENTS = ['scan.completed', 'scan.failed', 'finding.critical', 'finding.high', '*']

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-600">Webhooks send HTTP POST requests to external URLs when events occur.</p>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
        >
          <Plus size={14} /> New Webhook
        </button>
      </div>

      {showCreate && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-3">
          <h3 className="font-medium text-sm">New Webhook</h3>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Name"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <input
            value={form.url}
            onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
            placeholder="https://hooks.example.com/payload"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"
          />
          <input
            value={form.secret}
            onChange={e => setForm(f => ({ ...f, secret: e.target.value }))}
            placeholder="HMAC signing secret (optional)"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <div>
            <p className="text-xs font-medium text-gray-600 mb-2">Events:</p>
            <div className="flex flex-wrap gap-2">
              {ALL_EVENTS.map(ev => (
                <label key={ev} className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.events.includes(ev)}
                    onChange={() => toggleEvent(ev)}
                  />
                  <span className="font-mono">{ev}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => createMut.mutate()}
              disabled={!form.name || !form.url || createMut.isPending}
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Creating...' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-gray-600 text-sm">Cancel</button>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {webhooks.map(w => (
          <div key={w.id} className="bg-white border border-gray-200 rounded-lg p-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-sm">{w.name}</span>
                  {w.last_status && (
                    <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${w.last_status < 300 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                      {w.last_status}
                    </span>
                  )}
                  <span className={`text-xs px-1.5 py-0.5 rounded ${w.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                    {w.enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <div className="text-xs text-gray-500 font-mono mt-1 truncate">{w.url}</div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {w.events.map(ev => (
                    <span key={ev} className="text-xs bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded font-mono">{ev}</span>
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => testMut.mutate(w.id)}
                  disabled={testMut.isPending}
                  className="p-1.5 text-gray-500 hover:text-blue-600 rounded"
                  title="Send test payload"
                >
                  <Send size={14} />
                </button>
                <button
                  onClick={() => deleteMut.mutate(w.id)}
                  className="p-1.5 text-gray-500 hover:text-red-600 rounded"
                  title="Delete"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          </div>
        ))}
        {webhooks.length === 0 && (
          <div className="text-center py-8 text-gray-400 text-sm">No webhooks configured</div>
        )}
      </div>
    </div>
  )
}
