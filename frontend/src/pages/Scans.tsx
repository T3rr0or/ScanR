import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Play, StopCircle, Trash2, Terminal, GitCompare } from 'lucide-react'
import { scansApi, type ScanCreate } from '@/api/scans'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { credentialsApi } from '@/api/credentials'
import { wordlistsApi } from '@/api/wordlists'
import { ProfileEditor, ALL_CATEGORIES, PORT_RANGES, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import ScanDelta from './ScanDelta'

interface Props {
  onOpenScan?: (id: string) => void
}

const PAGE_SIZE = 50

export default function Scans({ onOpenScan }: Props) {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [deltaScan, setDeltaScan] = useState<{ id: string; name: string } | null>(null)
  const [page, setPage] = useState(0)
  const { data: scans = [] } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    refetchInterval: 5000,
  })

  const createMut = useMutation({
    mutationFn: (body: ScanCreate) => scansApi.create(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); setShowForm(false) },
  })
  const launchMut = useMutation({
    mutationFn: (id: string) => scansApi.launch(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
  const cancelMut = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  return (
    <div className="p-8">
      {deltaScan && (
        <ScanDelta scanId={deltaScan.id} scanName={deltaScan.name} onClose={() => setDeltaScan(null)} />
      )}

      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold">Scans</h1>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          <Plus size={16} /> New Scan
        </button>
      </div>

      {showForm && <ScanForm onSubmit={b => createMut.mutate(b)} onCancel={() => setShowForm(false)} loading={createMut.isPending} />}

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-200">
              {['Name', 'Profile', 'Status', 'Hosts', 'C/H/M/L', 'Actions'].map(h => (
                <th key={h} className="px-4 py-3 text-left font-medium text-gray-600">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.map(s => (
              <tr
                key={s.id}
                className="border-b border-gray-100 hover:bg-gray-50 cursor-pointer"
                onClick={() => onOpenScan?.(s.id)}
              >
                <td className="px-4 py-3 font-medium">{s.name}</td>
                <td className="px-4 py-3 text-gray-500">{s.profile}</td>
                <td className="px-4 py-3"><StatusPill status={s.status} /></td>
                <td className="px-4 py-3 text-gray-600">{s.hosts_up}/{s.hosts_total}</td>
                <td className="px-4 py-3 font-mono text-xs">
                  <span className="text-red-600">{s.findings_critical}</span>/
                  <span className="text-orange-500">{s.findings_high}</span>/
                  <span className="text-yellow-600">{s.findings_medium}</span>/
                  <span className="text-green-600">{s.findings_low}</span>
                </td>
                <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                  <div className="flex gap-2">
                    <button onClick={() => onOpenScan?.(s.id)} className="p-1 text-blue-500 hover:text-blue-700" title="Open console">
                      <Terminal size={15} />
                    </button>
                    {s.status === 'pending' && (
                      <button onClick={() => launchMut.mutate(s.id)} className="p-1 text-green-600 hover:text-green-700" title="Launch">
                        <Play size={15} />
                      </button>
                    )}
                    {s.status === 'running' && (
                      <button onClick={() => cancelMut.mutate(s.id)} className="p-1 text-red-600 hover:text-red-700" title="Cancel">
                        <StopCircle size={15} />
                      </button>
                    )}
                    {(s.status === 'completed' || s.status === 'failed') && (
                      <button onClick={() => setDeltaScan({ id: s.id, name: s.name })} className="p-1 text-gray-400 hover:text-purple-600" title="Compare">
                        <GitCompare size={15} />
                      </button>
                    )}
                    <button onClick={() => { if (confirm('Delete scan?')) deleteMut.mutate(s.id) }} className="p-1 text-gray-400 hover:text-red-600" title="Delete">
                      <Trash2 size={15} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {scans.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No scans yet</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {(page > 0 || scans.length === PAGE_SIZE) && (
        <div className="flex items-center gap-3 mt-4 justify-end">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1.5 text-sm rounded border border-gray-300 disabled:opacity-40 hover:bg-gray-50"
          >
            Previous
          </button>
          <span className="text-sm text-gray-500">Page {page + 1}</span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={scans.length < PAGE_SIZE}
            className="px-3 py-1.5 text-sm rounded border border-gray-300 disabled:opacity-40 hover:bg-gray-50"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

function StatusPill({ status }: { status: string }) {
  const c: Record<string, string> = {
    running: 'bg-yellow-100 text-yellow-700', completed: 'bg-green-100 text-green-700',
    failed: 'bg-red-100 text-red-700', pending: 'bg-blue-100 text-blue-700',
    cancelled: 'bg-gray-100 text-gray-600',
  }
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${c[status] ?? 'bg-gray-100 text-gray-600'}`}>{status}</span>
}

// ── Scan creation form ──────────────────────────────────────────────────────

function ScanForm({ onSubmit, onCancel, loading }: {
  onSubmit: (b: ScanCreate) => void; onCancel: () => void; loading: boolean
}) {
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [credentialId, setCredentialId] = useState('')
  const [selectedTemplate, setSelectedTemplate] = useState<ScanTemplate | null>(null)
  const [profileConfig, setProfileConfig] = useState<ProfileConfig>({
    port_range: 'top-10000',
    categories: ALL_CATEGORIES.map(x => x.id),
  })
  const [bruteForce, setBruteForce] = useState({
    enabled: false,
    credential_wordlist_id: '',
    username_wordlist_id: '',
    password_wordlist_id: '',
    max_concurrent: 3,
    delay_ms: 500,
    stop_on_success: true,
  })

  const { data: templates = [] } = useQuery({ queryKey: ['templates'], queryFn: templatesApi.list })
  const { data: credentials = [] } = useQuery({ queryKey: ['credentials'], queryFn: credentialsApi.list })
  const { data: wordlists = [] } = useQuery({ queryKey: ['wordlists'], queryFn: wordlistsApi.list })
  const systemTemplates = templates.filter(t => t.is_system)
  const credWordlists = wordlists.filter(w => w.type === 'credentials')
  const userWordlists = wordlists.filter(w => w.type === 'usernames')
  const passWordlists = wordlists.filter(w => w.type === 'passwords')

  function applyTemplate(t: ScanTemplate) {
    setSelectedTemplate(t)
    setProfileConfig(jsonToConfig(t.profile_json))
    if (!name) setName(t.name)
  }

  function handleSubmit() {
    const pj: Record<string, unknown> = { ...configToJson(profileConfig) }
    if (bruteForce.enabled) {
      pj.brute_force = {
        credential_wordlist_id: bruteForce.credential_wordlist_id || null,
        username_wordlist_id: bruteForce.username_wordlist_id || null,
        password_wordlist_id: bruteForce.password_wordlist_id || null,
        max_concurrent: bruteForce.max_concurrent,
        delay_ms: bruteForce.delay_ms,
        stop_on_success: bruteForce.stop_on_success,
      }
    }
    onSubmit({
      name,
      targets: targets.split('\n').map(t => t.trim()).filter(Boolean),
      profile: 'custom',
      profile_json: JSON.stringify(pj),
      credential_id: credentialId || undefined,
    })
  }

  return (
    <div className="bg-white border border-gray-200 rounded-xl p-6 mb-6">
      <h2 className="text-lg font-semibold mb-4">New Scan</h2>

      {/* Quick-start templates */}
      {systemTemplates.length > 0 && (
        <div className="mb-5">
          <p className="text-xs font-medium text-gray-500 mb-2">Start from a template</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {systemTemplates.map(t => (
              <button
                key={t.id}
                type="button"
                onClick={() => applyTemplate(t)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  selectedTemplate?.id === t.id
                    ? 'border-blue-400 bg-blue-50 ring-1 ring-blue-300'
                    : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                }`}
              >
                <div className="text-xs font-semibold text-gray-800 truncate">{t.name}</div>
                {t.profile_json && (
                  <div className="text-xs text-gray-400 mt-0.5 font-mono truncate">
                    {PORT_RANGES.find(r => r.value === (t.profile_json as any).port_range)?.label.split(' —')[0]
                      ?? (t.profile_json as any).port_range}
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="col-span-2 md:col-span-1">
            <label className="block text-xs font-medium text-gray-600 mb-1.5">Scan Name</label>
            <input value={name} onChange={e => setName(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm" placeholder="Internal Network Q4" />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1.5">
            Targets <span className="text-gray-400 font-normal">(one per line: IP, CIDR, hostname, range)</span>
          </label>
          <textarea value={targets} onChange={e => setTargets(e.target.value)} rows={3}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono"
            placeholder={"192.168.1.0/24\n10.0.0.1-10.0.0.50\nexample.com"} />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1.5">
            Credential <span className="text-gray-400 font-normal">(optional — required for authenticated plugins)</span>
          </label>
          <select value={credentialId} onChange={e => setCredentialId(e.target.value)}
            className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm">
            <option value="">None</option>
            {credentials.map(c => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.type}{c.username ? ` — ${c.username}` : ''})
              </option>
            ))}
          </select>
        </div>

        {/* Port Range — locked to template or manually selectable */}
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1.5">Port Range</label>
          {selectedTemplate ? (
            <div className="flex items-center gap-2 px-3 py-2 bg-blue-50 border border-blue-200 rounded-lg text-sm">
              <span className="font-mono text-blue-700 text-xs flex-1">
                {PORT_RANGES.find(r => r.value === profileConfig.port_range)?.label
                  ?? `Custom: ${profileConfig.port_range}`}
              </span>
              <span className="text-xs text-blue-500 flex-shrink-0">set by {selectedTemplate.name}</span>
              <button
                type="button"
                onClick={() => setSelectedTemplate(null)}
                className="text-xs text-gray-400 hover:text-gray-600 underline flex-shrink-0"
              >
                unlock
              </button>
            </div>
          ) : (
            <select
              value={PORT_RANGES.find(r => r.value === profileConfig.port_range) ? profileConfig.port_range : '__custom__'}
              onChange={e => {
                if (e.target.value !== '__custom__') setProfileConfig(c => ({ ...c, port_range: e.target.value }))
              }}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
            >
              {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
              {!PORT_RANGES.find(r => r.value === profileConfig.port_range) && (
                <option value="__custom__" disabled>Custom: {profileConfig.port_range}</option>
              )}
            </select>
          )}
        </div>

        <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
          <p className="text-xs font-medium text-gray-600 mb-3">Plugin Categories</p>
          <ProfileEditor config={profileConfig} onChange={setProfileConfig} hidePortRange />
        </div>

        {/* Brute Force section */}
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#9ca3af' }}>
              Brute Force
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12, color: '#6b7280' }}>
              <input
                type="checkbox"
                checked={bruteForce.enabled}
                onChange={e => setBruteForce(b => ({ ...b, enabled: e.target.checked }))}
                style={{ accentColor: '#2563eb' }}
              />
              Enable
            </label>
          </div>

          {bruteForce.enabled && (
            <div style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: 6, padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1.5">
                  Credential pairs list <span className="text-gray-400 font-normal">(user:password format)</span>
                </label>
                <select
                  className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                  value={bruteForce.credential_wordlist_id}
                  onChange={e => setBruteForce(b => ({ ...b, credential_wordlist_id: e.target.value }))}
                >
                  <option value="">None (use separate lists below)</option>
                  {credWordlists.map(w => (
                    <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()} pairs)</option>
                  ))}
                </select>
              </div>

              {!bruteForce.credential_wordlist_id && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1.5">Username list</label>
                    <select
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                      value={bruteForce.username_wordlist_id}
                      onChange={e => setBruteForce(b => ({ ...b, username_wordlist_id: e.target.value }))}
                    >
                      <option value="">Built-in defaults</option>
                      {userWordlists.map(w => (
                        <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()})</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1.5">Password list</label>
                    <select
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                      value={bruteForce.password_wordlist_id}
                      onChange={e => setBruteForce(b => ({ ...b, password_wordlist_id: e.target.value }))}
                    >
                      <option value="">Built-in defaults</option>
                      {passWordlists.map(w => (
                        <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()})</option>
                      ))}
                    </select>
                  </div>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1.5">Max concurrent</label>
                  <input
                    type="number" min={1} max={10}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                    value={bruteForce.max_concurrent}
                    onChange={e => setBruteForce(b => ({ ...b, max_concurrent: +e.target.value }))}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1.5">Delay (ms)</label>
                  <input
                    type="number" min={0} max={5000} step={100}
                    className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                    value={bruteForce.delay_ms}
                    onChange={e => setBruteForce(b => ({ ...b, delay_ms: +e.target.value }))}
                  />
                </div>
                <div style={{ display: 'flex', alignItems: 'flex-end', paddingBottom: 1 }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12, color: '#6b7280' }}>
                    <input
                      type="checkbox"
                      checked={bruteForce.stop_on_success}
                      onChange={e => setBruteForce(b => ({ ...b, stop_on_success: e.target.checked }))}
                      style={{ accentColor: '#2563eb' }}
                    />
                    Stop on first success
                  </label>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex gap-3 mt-5">
        <button
          onClick={handleSubmit}
          disabled={loading || !name || !targets.trim()}
          className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          {loading ? 'Creating...' : 'Create Scan'}
        </button>
        <button onClick={onCancel} className="px-4 py-2 rounded-lg text-sm text-gray-600 hover:bg-gray-100">Cancel</button>
      </div>
    </div>
  )
}
