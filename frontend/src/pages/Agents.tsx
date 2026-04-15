import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, Plus, Trash2, Copy, Check, Wifi, WifiOff } from 'lucide-react'
import { agentsApi, type AgentCreated } from '@/api/agents'

export default function Agents() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [createdAgent, setCreatedAgent] = useState<AgentCreated | null>(null)
  const [copied, setCopied] = useState(false)

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => agentsApi.create({ name: form.name, description: form.description || undefined }),
    onSuccess: (agent) => {
      setCreatedAgent(agent)
      setShowCreate(false)
      setForm({ name: '', description: '' })
      qc.invalidateQueries({ queryKey: ['agents'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: agentsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const copy = (s: string) => {
    navigator.clipboard.writeText(s)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function isOnline(last_seen: string | null) {
    if (!last_seen) return false
    return Date.now() - new Date(last_seen).getTime() < 90_000  // 90s
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan Agents</h1>
          <p className="text-sm text-gray-500 mt-1">Remote agents scan internal/firewalled networks and report findings back</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
        >
          <Plus size={14} /> Register Agent
        </button>
      </div>

      {createdAgent && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-6">
          <p className="text-sm font-semibold text-green-800 mb-1">Agent registered — copy the token now, it won't be shown again:</p>
          <div className="flex items-center gap-2 bg-white border border-green-300 rounded px-3 py-2 font-mono text-xs mb-3">
            <span className="flex-1 break-all">{createdAgent.token}</span>
            <button onClick={() => copy(createdAgent.token)} className="text-green-600 hover:text-green-800">
              {copied ? <Check size={14} /> : <Copy size={14} />}
            </button>
          </div>

          {/* Option A: Docker full agent */}
          <p className="text-xs font-semibold text-green-800 mb-1">Option A — Docker (full plugin suite, recommended):</p>
          <p className="text-xs text-green-700 mb-1">Uses the same image as the ScanR worker — runs all plugins (SSL, web, service, CVE, etc.):</p>
          <div className="bg-gray-900 text-green-400 text-xs font-mono px-3 py-2 rounded space-y-1 mb-3">
            <div>docker run --rm \</div>
            <div className="pl-4">-e SCANR_SERVER={window.location.origin} \</div>
            <div className="pl-4">-e SCANR_TOKEN={createdAgent.token} \</div>
            <div className="pl-4">--network host \</div>
            <div className="pl-4">{'<your-scanr-worker-image>'} \</div>
            <div className="pl-4">python -m scanr.agent.full_runner</div>
          </div>

          {/* Option B: Lightweight nmap-only script */}
          <p className="text-xs font-semibold text-green-800 mb-1">Option B — Lightweight script (nmap only, minimal deps):</p>
          <p className="text-xs text-green-700 mb-1">Needs Python 3.10+, httpx, and nmap installed on the target machine:</p>
          <div className="bg-gray-900 text-green-400 text-xs font-mono px-3 py-2 rounded space-y-1">
            <div><span className="text-gray-500"># 1. install the only Python dependency</span></div>
            <div>pip install httpx</div>
            <div className="mt-1"><span className="text-gray-500"># 2. download the agent script</span></div>
            <div>curl {window.location.origin}/api/v1/agent/script -o scanr_agent.py</div>
            <div className="mt-1"><span className="text-gray-500"># 3. run it</span></div>
            <div>python scanr_agent.py --server {window.location.origin} --token {createdAgent.token}</div>
          </div>
          <button onClick={() => setCreatedAgent(null)} className="mt-3 text-xs text-green-700 underline">Dismiss</button>
        </div>
      )}

      {showCreate && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-3 mb-6">
          <h3 className="font-medium text-sm">Register Agent</h3>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Agent name (e.g. Office-Network-Agent)"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <input
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <div className="flex gap-2">
            <button
              onClick={() => createMut.mutate()}
              disabled={!form.name || createMut.isPending}
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Registering...' : 'Register'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-gray-600 text-sm">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-gray-500 text-sm">Loading...</div>
      ) : agents.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Bot size={40} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">No agents registered</p>
          <p className="text-xs mt-1">Register an agent to scan internal networks</p>
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200 text-left text-xs font-semibold text-gray-500 uppercase tracking-wide">
                <th className="px-4 py-3">Agent</th>
                <th className="px-4 py-3">Token Prefix</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Last Seen</th>
                <th className="px-4 py-3">IP</th>
                <th className="px-4 py-3">Version</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {agents.map((a, i) => {
                const online = isOnline(a.last_seen_at)
                return (
                  <tr key={a.id} className={`border-b border-gray-100 ${i === agents.length - 1 ? 'border-b-0' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="font-medium">{a.name}</div>
                      {a.description && <div className="text-xs text-gray-400">{a.description}</div>}
                    </td>
                    <td className="px-4 py-3 font-mono text-gray-500 text-xs">{a.prefix}...</td>
                    <td className="px-4 py-3">
                      <span className={`flex items-center gap-1 text-xs ${online ? 'text-green-600' : 'text-gray-400'}`}>
                        {online ? <Wifi size={12} /> : <WifiOff size={12} />}
                        {a.last_seen_at ? (online ? 'Online' : 'Offline') : 'Never connected'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-500">
                      {a.last_seen_at ? new Date(a.last_seen_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-gray-500">{a.ip_address || '—'}</td>
                    <td className="px-4 py-3 text-xs text-gray-500">{a.agent_version || '—'}</td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => deleteMut.mutate(a.id)}
                        className="p-1 text-gray-400 hover:text-red-500"
                        title="Remove agent"
                      >
                        <Trash2 size={13} />
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
