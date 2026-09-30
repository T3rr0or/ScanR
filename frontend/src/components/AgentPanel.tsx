import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Plus, Square, Send } from 'lucide-react'
import api from '@/api/client'
import { PROVIDER_LABEL } from '@/api/ai'
import { useAuthStore } from '@/store/auth'
import { isAdminToken } from '@/utils/jwt'
import Markdown from '@/components/Markdown'
import './AgentPanel.css'

export interface AgentRun {
  id: string
  scan_id: string
  status: string
  mode: string
  objective: string
  provider?: string | null
  model?: string | null
  stop_reason?: string | null
  final_text?: string | null
  actions: { tool: string; arguments: Record<string, unknown>; result: string }[]
  max_iterations?: number | null
  max_tokens?: number | null
  token_usage?: { input_tokens: number; output_tokens: number } | null
  error?: string | null
  pending_approval?: { approval_id: string; tool: string; args: Record<string, unknown>; reason: string } | null
  conversation?: {
    role: string
    content?: string
    tool_calls?: { id: string; name: string; arguments: Record<string, unknown> }[]
    tool_call_id?: string
    name?: string
  }[]
  created_at?: string | null
}

type Mode = 'guided' | 'autonomous'
type Capability = 'analyze' | 'active' | 'full'
const SETTINGS_KEY = 'scanr_agent_settings'
const ACTIVE_STATUSES = ['queued', 'running']
const CAPS: Record<Capability, Record<string, boolean>> = {
  analyze: { aggressive: false, allow_exploitation: false, allow_privilege_escalation: false, allow_command_exec: false, allow_target_egress: false },
  active: { aggressive: true, allow_exploitation: false, allow_privilege_escalation: false, allow_command_exec: false, allow_target_egress: false },
  full: { aggressive: true, allow_exploitation: true, allow_privilege_escalation: true, allow_command_exec: true, allow_target_egress: true },
}
const CAP_LABEL: Record<Capability, string> = { analyze: 'Read-only', active: 'Active', full: 'Full access' }

function loadSettings(): { mode: Mode; capability: Capability; provider: string } {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? '{}') as Record<string, unknown>
    return {
      mode: raw.mode === 'guided' ? 'guided' : 'autonomous',
      capability: raw.capability === 'active' || raw.capability === 'full' ? raw.capability : 'analyze',
      provider: typeof raw.provider === 'string' ? raw.provider : '',
    }
  } catch {
    return { mode: 'autonomous', capability: 'analyze', provider: '' }
  }
}

function errorText(error: unknown): string | null {
  if (!error) return null
  const e = error as { response?: { data?: { detail?: string } }; message?: string }
  return e.response?.data?.detail ?? e.message ?? 'Request failed'
}

function runLabel(run: AgentRun): string {
  const text = run.objective?.trim() || 'Scan investigation'
  return text.length > 54 ? `${text.slice(0, 54)}…` : text
}

export default function AgentPanel({ scanId, enabled, autoScheduled = false }: { scanId: string; enabled: boolean; autoScheduled?: boolean }) {
  const qc = useQueryClient()
  const token = useAuthStore(s => s.token)
  const isAdmin = isAdminToken(token)
  const [saved] = useState(loadSettings)
  const [mode, setMode] = useState<Mode>(saved.mode)
  const [capability, setCapability] = useState<Capability>(isAdmin ? saved.capability : 'analyze')
  const [provider, setProvider] = useState(saved.provider)
  const [message, setMessage] = useState('')
  const [showSettings, setShowSettings] = useState(false)
  const [selectedRunId, setSelectedRunId] = useState<string | 'new' | null>(null)
  const [stopRequested, setStopRequested] = useState(false)
  const transcriptRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify({ mode, capability, provider })) } catch { /* local storage may be unavailable */ }
  }, [mode, capability, provider])

  const { data: aiStatus } = useQuery<{ providers: string[]; configured: Record<string, boolean>; default_provider: string }>({
    queryKey: ['ai-status'], queryFn: () => api.get('/ai/status').then(r => r.data),
  })
  const availableProviders = (aiStatus?.providers ?? []).filter(p => aiStatus?.configured?.[p])
  const { data: runs = [], error: runsError } = useQuery<AgentRun[]>({
    queryKey: ['ai-agent-runs', scanId],
    queryFn: () => api.get(`/ai/scans/${scanId}/agent/runs`).then(r => r.data),
    refetchInterval: 3000,
  })
  const activeRun = runs.find(run => ACTIVE_STATUSES.includes(run.status))
  const selectedRun = selectedRunId === 'new' ? undefined : runs.find(run => run.id === selectedRunId) ?? runs[0]
  const canContinue = selectedRun?.status === 'completed' && Boolean(selectedRun.conversation?.length)
  const newSession = selectedRunId === 'new' || !selectedRun

  useEffect(() => {
    if (!activeRun) setStopRequested(false)
  }, [activeRun])
  useEffect(() => {
    if (transcriptRef.current) transcriptRef.current.scrollTop = transcriptRef.current.scrollHeight
  }, [selectedRunId, selectedRun?.conversation, selectedRun?.final_text])

  const launch = useMutation({
    mutationFn: (objective: string) => api.post<AgentRun>(`/ai/scans/${scanId}/agent`, {
      mode, objective, provider: provider || undefined,
      max_iterations: 0, max_tokens: 0,
      ...Object.fromEntries(Object.entries(CAPS[capability]).map(([key, value]) => [key, isAdmin && value])),
    }).then(r => r.data),
    onSuccess: run => { setMessage(''); setSelectedRunId(run.id); qc.invalidateQueries({ queryKey: ['ai-agent-runs', scanId] }) },
  })
  const chat = useMutation({
    mutationFn: ({ runId, text }: { runId: string; text: string }) => api.post(`/ai/agent/runs/${runId}/chat`, { message: text, provider: provider || undefined }).then(r => r.data),
    onSuccess: () => { setMessage(''); qc.invalidateQueries({ queryKey: ['ai-agent-runs', scanId] }) },
  })
  const stop = useMutation({
    mutationFn: (runId: string) => api.post(`/ai/agent/runs/${runId}/stop`).then(r => r.data),
    onMutate: () => setStopRequested(true),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-agent-runs', scanId] }),
    onError: () => setStopRequested(false),
  })
  const decide = useMutation({
    mutationFn: ({ runId, approvalId, decision }: { runId: string; approvalId: string; decision: 'allow' | 'deny' }) =>
      api.post(`/ai/agent/runs/${runId}/approval`, { approval_id: approvalId, decision }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-agent-runs', scanId] }),
  })

  const send = () => {
    const text = message.trim()
    if (!text || !enabled || activeRun || launch.isPending || chat.isPending) return
    if (canContinue && selectedRun && !newSession) chat.mutate({ runId: selectedRun.id, text })
    else launch.mutate(text)
  }
  const exportTrace = async (runId: string) => {
    const response = await api.get(`/ai/agent/runs/${runId}/export`, { params: { format: 'md' }, responseType: 'blob' })
    const url = URL.createObjectURL(response.data as Blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `agent-trace-${runId.slice(0, 8)}.md`
    link.click()
    window.setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  const toolResults: Record<string, string> = {}
  for (const entry of selectedRun?.conversation ?? []) {
    if (entry.role === 'tool' && entry.tool_call_id) toolResults[entry.tool_call_id] = entry.content ?? ''
  }
  const busy = Boolean(activeRun || launch.isPending || chat.isPending)
  const sendError = errorText(launch.error ?? chat.error ?? stop.error ?? decide.error ?? runsError)

  return (
    <section className="agent-workspace" aria-label="AI agent workspace">
      <aside className="agent-history" aria-label="Agent sessions">
        <div className="agent-history-head"><span>Sessions</span><button type="button" onClick={() => { setSelectedRunId('new'); setMessage('') }} disabled={busy} title="Start a new session"><Plus size={15} /> New</button></div>
        <div className="agent-history-list">
          {runs.length === 0 && <p>No sessions yet</p>}
          {runs.map(run => <button type="button" key={run.id} className={`agent-history-item ${selectedRun?.id === run.id && !newSession ? 'is-selected' : ''}`} onClick={() => setSelectedRunId(run.id)}>
            <span className="agent-history-title">{runLabel(run)}</span>
            <span className="agent-history-meta"><span className={`agent-state agent-state-${run.status}`}>{run.status}</span><span>{run.mode}</span></span>
          </button>)}
        </div>
      </aside>

      <div className="agent-main">
        <header className="agent-header">
          <div className="agent-header-copy"><span className="agent-eyebrow">Agent session</span><h2>{newSession ? 'New investigation' : runLabel(selectedRun!)}</h2><div className="agent-run-meta">
            {selectedRun ? <><span className={`agent-state agent-state-${selectedRun.status}`}>{selectedRun.status}</span><span>{selectedRun.mode}</span><span>{selectedRun.provider ? `${PROVIDER_LABEL[selectedRun.provider] ?? selectedRun.provider}${selectedRun.model ? ` / ${selectedRun.model}` : ''}` : 'Default model'}</span>{selectedRun.token_usage && <span>{(selectedRun.token_usage.input_tokens + selectedRun.token_usage.output_tokens).toLocaleString()} tokens used</span>}</> : <span>Runs until it finishes or you stop it</span>}
          </div></div>
          <div className="agent-header-actions">
            {selectedRun && <button type="button" className="agent-button" onClick={() => void exportTrace(selectedRun.id)}><Download size={14} /> Export trace</button>}
            <button type="button" className="agent-button" onClick={() => setShowSettings(value => !value)} aria-expanded={showSettings}>Settings</button>
            {activeRun && <button type="button" className="agent-button agent-stop" onClick={() => stop.mutate(activeRun.id)} disabled={stop.isPending || stopRequested}><Square size={12} fill="currentColor" /> {stop.isPending || stopRequested ? 'Stopping…' : 'Stop agent'}</button>}
          </div>
        </header>

        {showSettings && <div className="agent-settings">
          <div className="agent-setting-group"><span>Mode</span><div className="agent-segments">{(['autonomous', 'guided'] as Mode[]).map(value => <button type="button" key={value} className={mode === value ? 'is-selected' : ''} onClick={() => setMode(value)} aria-pressed={mode === value}>{value === 'autonomous' ? 'Autonomous' : 'Guided approval'}</button>)}</div></div>
          <div className="agent-setting-group"><label htmlFor="agent-provider">Provider</label><select id="agent-provider" value={provider} onChange={event => setProvider(event.target.value)}><option value="">Default{aiStatus?.default_provider ? ` (${PROVIDER_LABEL[aiStatus.default_provider] ?? aiStatus.default_provider})` : ''}</option>{availableProviders.map(value => <option key={value} value={value}>{PROVIDER_LABEL[value] ?? value}</option>)}</select></div>
          {isAdmin && <div className="agent-setting-group"><span>Access</span><div className="agent-segments">{(['analyze', 'active', 'full'] as Capability[]).map(value => <button type="button" key={value} className={capability === value ? 'is-selected' : ''} onClick={() => setCapability(value)} aria-pressed={capability === value}>{CAP_LABEL[value]}</button>)}</div></div>}
          <p className="agent-settings-note">No step or session token cap. Access permissions still control what the agent can do.</p>
        </div>}

        {!enabled && <div className="agent-notice" role="status"><strong>AI provider required</strong><span>Add a provider key in <a href="#/settings">Settings → AI providers</a> to start an agent. Previous sessions remain available below.</span></div>}
        {autoScheduled && !activeRun && runs.length === 0 && <div className="agent-notice" role="status"><strong>Automatic agent scheduled</strong><span>The agent starts after scan checks. Use Stop AI in the scan header to cancel before it starts.</span></div>}
        {sendError && <div className="agent-error" role="alert">{sendError}</div>}

        <div className="agent-transcript" ref={transcriptRef}>
          {newSession ? <div className="agent-empty"><span>AI AGENT</span><h3>Set an objective for this scan.</h3><p>Ask the agent to investigate findings, verify exposure, or explain a route. It keeps working until it finishes or you stop it.</p></div> : <div className="agent-messages">
            {selectedRun?.conversation?.map((entry, index) => {
              if (entry.role === 'tool') return null
              if (entry.role === 'user') return <article className="agent-message agent-message-user" key={index}><div className="agent-message-label">You</div><div className="agent-message-body">{entry.content}</div></article>
              if (entry.role === 'assistant') return <article className="agent-message" key={index}><div className="agent-message-label">Agent</div>{entry.content && <div className="agent-message-body"><Markdown>{entry.content}</Markdown></div>}{entry.tool_calls?.length ? <div className="agent-tools">{entry.tool_calls.map(call => <details key={call.id}><summary><span>{call.name}</span><span>View command and result</span></summary><div><strong>Arguments</strong><pre>{JSON.stringify(call.arguments, null, 2)}</pre><strong>Result</strong><pre>{toolResults[call.id] ?? 'Waiting for result…'}</pre></div></details>)}</div> : null}</article>
              return null
            })}
            {!selectedRun?.conversation?.length && selectedRun?.actions?.length ? <div className="agent-tools agent-legacy-tools">{selectedRun.actions.map((action, index) => <details key={index}><summary><span>{action.tool}</span><span>View command and result</span></summary><div><strong>Arguments</strong><pre>{JSON.stringify(action.arguments, null, 2)}</pre><strong>Result</strong><pre>{action.result}</pre></div></details>)}</div> : null}
            {selectedRun?.final_text && !selectedRun.conversation?.some(entry => entry.role === 'assistant' && entry.content === selectedRun.final_text) && <article className="agent-message"><div className="agent-message-label">Report</div><div className="agent-message-body"><Markdown>{selectedRun.final_text}</Markdown></div></article>}
            {selectedRun?.error && <div className="agent-error" role="alert">{selectedRun.error}</div>}
            {selectedRun?.pending_approval && <div className="agent-approval"><strong>Approval required</strong><p>{selectedRun.pending_approval.reason || `${selectedRun.pending_approval.tool} requires approval.`}</p><pre>{selectedRun.pending_approval.tool}({JSON.stringify(selectedRun.pending_approval.args, null, 2)})</pre><div><button type="button" onClick={() => decide.mutate({ runId: selectedRun.id, approvalId: selectedRun.pending_approval!.approval_id, decision: 'allow' })} disabled={decide.isPending}>Approve</button><button type="button" onClick={() => decide.mutate({ runId: selectedRun.id, approvalId: selectedRun.pending_approval!.approval_id, decision: 'deny' })} disabled={decide.isPending}>Deny</button></div></div>}
            {activeRun?.id === selectedRun?.id && <div className="agent-working"><span className="agent-working-mark" />{stopRequested ? 'Stopping after the current operation…' : activeRun.status === 'queued' ? 'Agent queued…' : 'Agent working…'}</div>}
            {selectedRun?.stop_reason && <div className="agent-end-state">Run ended: {selectedRun.stop_reason.replace(/_/g, ' ')}</div>}
          </div>}
        </div>

        <footer className="agent-composer"><div className="agent-composer-inner"><label htmlFor="agent-message">{canContinue && !newSession ? 'Continue this session' : 'New objective'}</label><textarea id="agent-message" value={message} onChange={event => setMessage(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); send() } }} placeholder="What should the agent investigate?" rows={3} disabled={!enabled} /><div className="agent-composer-bottom"><span>{busy ? 'Agent is active. Stop it or wait before sending.' : 'Enter to send · Shift+Enter for a new line'}</span><button type="button" className="agent-send" onClick={send} disabled={!enabled || !message.trim() || busy}><Send size={14} /> {canContinue && !newSession ? 'Send' : 'Start agent'}</button></div></div></footer>
      </div>
    </section>
  )
}
