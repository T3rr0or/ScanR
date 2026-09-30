import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Copy, Check, RotateCcw } from 'lucide-react'
import { agentsApi, type AgentCreated } from '@/api/agents'
import { relTime } from '@/components/ui'
import './OperatorSetup.css'

export default function Agents() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [createdAgent, setCreatedAgent] = useState<AgentCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const [showDisabled, setShowDisabled] = useState(false)

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['agents', showDisabled],
    queryFn: () => agentsApi.list(showDisabled),
  })

  const activeAgents = agents.filter(a => a.enabled)
  const disabledAgents = agents.filter(a => !a.enabled)

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

  const enableMut = useMutation({
    mutationFn: (id: string) => agentsApi.update(id, { enabled: true }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const copy = (s: string) => {
    navigator.clipboard.writeText(s)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function isOnline(last_seen: string | null) {
    if (!last_seen) return false
    return Date.now() - new Date(last_seen).getTime() < 90_000
  }

  return <main className="setup-page agents-page page-pad">
    <header className="setup-header"><div><h1>Scan agents</h1><p>Remote scanners for internal and segmented networks.</p></div><div className="setup-header-actions"><button className="setup-button" onClick={() => setShowDisabled(v => !v)}>{showDisabled ? 'Hide disabled' : `Show disabled (${disabledAgents.length})`}</button><button className="setup-button setup-button-primary" onClick={() => setShowCreate(true)}><Plus size={14} /> Register agent</button></div></header>
    <div className="setup-summary"><span>{activeAgents.length} enabled</span><span>{activeAgents.filter(a => isOnline(a.last_seen_at)).length} online</span><span>{disabledAgents.length} disabled</span></div>
    {createdAgent && <section className="setup-form setup-token"><div className="setup-form-heading"><strong>Agent registered</strong><button onClick={() => setCreatedAgent(null)}>Dismiss</button></div><p>Copy this token now. It will not be shown again.</p><div className="setup-token-value"><code>{createdAgent.token}</code><button onClick={() => copy(createdAgent.token)} aria-label="Copy agent token">{copied ? <Check size={14} /> : <Copy size={14} />}</button></div><div className="setup-token-methods"><div><h3>Docker</h3><pre>{String.raw`docker run --rm \
  -e SCANR_SERVER=${window.location.origin} \
  -e SCANR_TOKEN=${createdAgent.token} \
  --network host \
  <your-scanr-worker-image> \
  python -m scanr.agent.full_runner`}</pre></div><div><h3>Lightweight script</h3><pre>{`pip install httpx
curl ${window.location.origin}/api/v1/agent/script -o scanr_agent.py
python scanr_agent.py --server ${window.location.origin} --token ${createdAgent.token}`}</pre></div></div></section>}
    {showCreate && <section className="setup-form"><div className="setup-form-heading"><strong>Register agent</strong><button onClick={() => setShowCreate(false)}>Close</button></div><div className="setup-form-row"><label>Name<input value={form.name} onChange={e => setForm(f => ({...f,name:e.target.value}))} placeholder="Office network agent" /></label><label>Description<input value={form.description} onChange={e => setForm(f => ({...f,description:e.target.value}))} placeholder="Optional" /></label></div><div className="setup-form-actions"><button className="setup-button setup-button-primary" onClick={() => createMut.mutate()} disabled={!form.name.trim() || createMut.isPending}>{createMut.isPending ? 'Registering...' : 'Register'}</button><button className="setup-button" onClick={() => setShowCreate(false)}>Cancel</button></div></section>}
    <section className="setup-list"><div className="setup-list-heading"><span>Active agents</span><span>{activeAgents.length} records</span></div><div className="agent-row agent-table-head"><span>Agent</span><span>Status</span><span>IP</span><span>Version</span><span>Last seen</span><span>Action</span></div>{isLoading ? <div className="setup-empty">Loading agents...</div> : activeAgents.length === 0 ? <div className="setup-empty">No active agents. Register one to scan an internal network.</div> : activeAgents.map((agent) => { const online=isOnline(agent.last_seen_at); return <div className="agent-row" key={agent.id}><div className="agent-identity"><strong>{agent.name}</strong><small>{agent.description || agent.prefix}</small></div><div className="agent-state"><i className={online?'online':''}/>{online?'Online':agent.last_seen_at?'Offline':'Never connected'}</div><div className="agent-data"><span>IP</span><strong>{agent.ip_address || '-'}</strong></div><div className="agent-data"><span>Version</span><strong>{agent.agent_version || '-'}</strong></div><div className="agent-data"><span>Last seen</span><strong>{agent.last_seen_at?relTime(agent.last_seen_at):'-'}</strong></div><button className="setup-icon-button" onClick={() => deleteMut.mutate(agent.id)} title={`Remove ${agent.name}`} aria-label={`Remove ${agent.name}`}><Trash2 size={14}/></button></div>})}</section>
    {showDisabled && disabledAgents.length>0 && <section className="setup-list"><div className="setup-list-heading"><span>Disabled agents</span><span>{disabledAgents.length} records</span></div>{disabledAgents.map((agent)=><div className="agent-row agent-row-disabled" key={agent.id}><div className="agent-identity"><strong>{agent.name}</strong><small>{agent.description || agent.prefix}</small></div><span className="agent-state">Disabled</span><button className="setup-button" onClick={()=>enableMut.mutate(agent.id)}><RotateCcw size={12}/> Re-enable</button></div>)}</section>}
  </main>
}
