import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import api from '@/api/client'
import type { Finding } from '@/api/findings'
import Markdown from '@/components/Markdown'
import './AssistPanel.css'

interface FpItem { id: string; confidence: string; reason: string; verification?: string }
interface SavedResult {
  id: string
  type: string
  content: { text?: string; items?: FpItem[]; methodology?: string }
  provider: string
  model: string
  token_usage: { input_tokens: number; output_tokens: number } | null
  created_at: string
}
interface SummaryResult { summary: string; provider: string; model: string; usage?: { input_tokens: number; output_tokens: number }; truncated?: boolean }
interface FpResult { items: FpItem[]; methodology?: string; assessed_count: number; flagged_count: number; provider: string; model: string; usage?: { input_tokens: number; output_tokens: number } | null; truncated?: boolean }

function errorText(error: unknown): string | null {
  if (!error) return null
  const e = error as { response?: { data?: { detail?: string } }; message?: string }
  return e.response?.data?.detail ?? e.message ?? 'Request failed'
}
function metaText(provider: string, model: string, usage?: { input_tokens: number; output_tokens: number } | null): string {
  return `${provider}${model ? ` / ${model}` : ''}${usage ? ` · ${(usage.input_tokens + usage.output_tokens).toLocaleString()} tokens` : ''}`
}

export default function AssistPanel({ scanId, findings, enabled }: { scanId: string; findings: Finding[]; enabled: boolean }) {
  const qc = useQueryClient()
  const { data: savedResults = [] } = useQuery<SavedResult[]>({ queryKey: ['ai-results', scanId], queryFn: () => api.get(`/ai/scans/${scanId}/results`).then(r => r.data) })
  const summary = useMutation<SummaryResult>({ mutationFn: () => api.post(`/ai/scans/${scanId}/summary`).then(r => r.data), onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-results', scanId] }) })
  const falsePositives = useMutation<FpResult>({ mutationFn: () => api.post(`/ai/scans/${scanId}/false-positives`).then(r => r.data), onSuccess: () => qc.invalidateQueries({ queryKey: ['ai-results', scanId] }) })
  const pending = summary.isPending || falsePositives.isPending
  const error = errorText(summary.error ?? falsePositives.error)
  const findingTitle = (id: string) => findings.find(finding => finding.id === id)?.title ?? id

  return <section className="assist-workspace" aria-label="Quick AI analysis">
    <header className="assist-header"><div><span>READ-ONLY TOOLS</span><h2>Quick analysis</h2><p>Generate a finding summary or review likely false positives. Results are saved with this scan.</p></div><span className={`assist-status ${enabled ? 'is-ready' : ''}`}>{enabled ? 'Ready' : 'Provider required'}</span></header>
    {!enabled && <div className="assist-notice" role="status">Add a provider key in <a href="#/settings">Settings → AI providers</a> to run these actions.</div>}
    <div className="assist-actions"><button type="button" onClick={() => summary.mutate()} disabled={!enabled || pending}>{summary.isPending ? 'Summarizing…' : 'Summarize findings'}</button><button type="button" onClick={() => falsePositives.mutate()} disabled={!enabled || pending}>{falsePositives.isPending ? 'Reviewing…' : 'Review false positives'}</button></div>
    {error && <div className="assist-error" role="alert">{error}</div>}
    <div className="assist-results">
      {summary.data && <SummaryView title="Latest summary" result={summary.data} />}
      {falsePositives.data && <FalsePositiveView title="Latest false-positive review" result={falsePositives.data} findingTitle={findingTitle} />}
      {savedResults.length > 0 && <div className="assist-saved"><h3>Saved analysis <span>{savedResults.length}</span></h3>{savedResults.map(result => <details key={result.id} className="assist-saved-item"><summary><span>{result.type === 'false_positives' ? 'False-positive review' : result.type === 'summary' ? 'Finding summary' : result.type}</span><span>{new Date(result.created_at).toLocaleString()}</span></summary>{result.type === 'false_positives' ? <FalsePositiveView title="Saved review" result={{ items: result.content.items ?? [], methodology: result.content.methodology, assessed_count: result.content.items?.length ?? 0, flagged_count: result.content.items?.length ?? 0, provider: result.provider, model: result.model, usage: result.token_usage }} findingTitle={findingTitle} /> : <SummaryView title="Saved result" result={{ summary: result.content.text ?? '', provider: result.provider, model: result.model, usage: result.token_usage ?? undefined }} />}</details>)}</div>}
      {!summary.data && !falsePositives.data && savedResults.length === 0 && !pending && <div className="assist-empty">No analysis saved for this scan. Choose an action above to generate one.</div>}
    </div>
  </section>
}

function SummaryView({ title, result }: { title: string; result: SummaryResult }) {
  return <article className="assist-result"><header><h3>{title}</h3><span>{metaText(result.provider, result.model, result.usage)}</span></header>{result.truncated && <p className="assist-warning">The provider returned a partial result. Review the underlying findings.</p>}<div className="assist-result-body"><Markdown>{result.summary}</Markdown></div></article>
}

function FalsePositiveView({ title, result, findingTitle }: { title: string; result: FpResult; findingTitle: (id: string) => string }) {
  return <article className="assist-result"><header><div><h3>{title}</h3><small>{result.flagged_count} flagged of {result.assessed_count} assessed</small></div><span>{metaText(result.provider, result.model, result.usage)}</span></header>{result.truncated && <p className="assist-warning">The provider returned a partial result. Review the underlying findings.</p>}{result.methodology && <div className="assist-method"><strong>Method</strong><p>{result.methodology}</p></div>}<div className="assist-fp-list">{result.items.length === 0 ? <p>No findings flagged as likely false positives.</p> : result.items.map(item => <div className="assist-fp-row" key={item.id}><div><strong>{findingTitle(item.id)}</strong><span>{item.confidence} confidence</span></div><p>{item.reason}</p>{item.verification && <details><summary>Verification steps</summary><pre>{item.verification}</pre></details>}</div>)}</div><p className="assist-advisory">Review the evidence before changing a finding's status.</p></article>
}
