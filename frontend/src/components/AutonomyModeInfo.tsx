/**
 * AutonomyModeInfo — an info popup explaining each AI autonomy mode so the user
 * knows exactly what they are enabling before they turn it on.
 *
 * `AUTONOMY_MODES` is the single source of truth for mode copy — drive the mode
 * selector AND this popup from it so they never drift. The same definitions are
 * mirrored in docs/ai-pentest-design.md §"Autonomy modes".
 *
 * Drop-in usage:
 *   const [showInfo, setShowInfo] = useState(false)
 *   <button className="btn btn-ghost btn-sm" onClick={() => setShowInfo(true)}>
 *     What do these modes mean?
 *   </button>
 *   {showInfo && <AutonomyModeInfo onClose={() => setShowInfo(false)} />}
 */
import type { ReactNode } from 'react'

export type AutonomyModeId =
  | 'off'
  | 'assist'
  | 'guided'
  | 'autonomous'
  | 'autonomous_aggressive'

export interface AutonomyMode {
  id: AutonomyModeId
  label: string
  /** One-line gist shown next to the mode in a selector. */
  tagline: string
  /** The single most important fact: does this mode send NEW traffic to targets? */
  touchesTargets: 'no' | 'yes-safe' | 'yes-intrusive'
  riskLabel: 'None' | 'Low' | 'Medium' | 'Medium–High' | 'High'
  riskColor: string
  /** Concrete things this mode WILL do. */
  does: string[]
  /** Hard guarantees — things this mode will NEVER do. */
  neverDoes: string[]
  /** What the operator must also enable for this mode to function. */
  requires?: string
}

const TOUCH_LABEL: Record<AutonomyMode['touchesTargets'], string> = {
  'no': 'No new traffic to targets',
  'yes-safe': 'Sends new traffic — non-intrusive only',
  'yes-intrusive': 'Sends new traffic — including intrusive actions',
}

const TOUCH_COLOR: Record<AutonomyMode['touchesTargets'], string> = {
  'no': 'var(--sev-info)',
  'yes-safe': 'var(--sev-medium)',
  'yes-intrusive': 'var(--sev-critical)',
}

export const AUTONOMY_MODES: AutonomyMode[] = [
  {
    id: 'off',
    label: 'Off',
    tagline: 'No AI. Standard static scan only.',
    touchesTargets: 'no',
    riskLabel: 'None',
    riskColor: 'var(--text-3)',
    does: ['Runs the normal plugin-based scan with no AI involvement.'],
    neverDoes: ['Calls any AI provider.', 'Sends data off-box.'],
  },
  {
    id: 'assist',
    label: 'Assist',
    tagline: 'AI reads the results you already have. It never touches your targets.',
    touchesTargets: 'no',
    riskLabel: 'Low',
    riskColor: 'var(--sev-low)',
    does: [
      'Writes an executive + technical summary of existing findings.',
      'Generates report narrative and prioritized remediation.',
      'Re-validates findings to flag likely false positives (for your review).',
    ],
    neverDoes: [
      'Send any new packet, request, or probe to a target.',
      'Start new scans or run plugins.',
      'Change scope, hide findings, or act without you reading the output.',
    ],
    requires: 'An AI provider + API key configured in Settings.',
  },
  {
    id: 'guided',
    label: 'Guided',
    tagline: 'AI decides what to scan next and runs it — but only safe checks, and it asks you before anything intrusive.',
    touchesTargets: 'yes-safe',
    riskLabel: 'Medium',
    riskColor: 'var(--sev-medium)',
    does: [
      'Runs an agent loop that chooses which ScanR plugins / safe checks to run next, reacting to what it finds.',
      'Actively sends new non-intrusive traffic to your targets (port scans, service probes, web requests, Nuclei).',
      'Pauses and asks for your approval in the console before ANY intrusive action.',
    ],
    neverDoes: [
      'Run brute force, default-credential, privilege-escalation, or exploitation steps without your explicit per-step approval.',
      'Scan anything outside scope — loopback, link-local, cloud metadata, and scanner infrastructure are blocked in code.',
    ],
    requires: 'An AI provider + API key. Intrusive steps still need their own capabilities enabled.',
  },
  {
    id: 'autonomous',
    label: 'Autonomous',
    tagline: 'Same as Guided, but runs hands-off — no per-step approval — within scope, safety, and budget limits.',
    touchesTargets: 'yes-safe',
    riskLabel: 'Medium–High',
    riskColor: 'var(--sev-high)',
    does: [
      'Runs the engagement end-to-end with the non-destructive tool set, no per-step approval.',
      'Adapts in real time and goes deeper into web/app logic than a static scan.',
      'Stops automatically when it hits the cost/time budget you set.',
    ],
    neverDoes: [
      'Perform intrusive/aggressive actions unless you switch on Aggressive mode AND the specific capability.',
      'Exceed your scope or budget. Every action is logged for replay.',
    ],
    requires: 'An AI provider + API key, and a per-scan budget cap.',
  },
  {
    id: 'autonomous_aggressive',
    label: 'Autonomous + Aggressive',
    tagline: 'Adds offensive actions: brute force, default creds, privilege escalation, and exploitation of confirmed vulns.',
    touchesTargets: 'yes-intrusive',
    riskLabel: 'High',
    riskColor: 'var(--sev-critical)',
    does: [
      'Everything Autonomous does, plus intrusive actions you have separately enabled.',
      'Example: on a confirmed credential match it may attempt privilege escalation — only if "Allow privilege escalation" is on.',
      'Can modify target state. Treat this as a real, active attack against the system.',
    ],
    neverDoes: [
      'Enable any aggressive capability by itself — each (brute force, default creds, privesc, exploitation) is a separate opt-in you control.',
      'Run against out-of-scope hosts. Scope enforcement still applies in code.',
    ],
    requires: 'Explicit per-capability opt-ins. Only use with written authorization for active exploitation.',
  },
]

/* The distinction users most often confuse, stated once, plainly. */
function AssistVsGuided() {
  return (
    <div
      style={{
        background: 'var(--bg-2)',
        borderRadius: 8,
        padding: '12px 14px',
        fontSize: 12.5,
        lineHeight: 1.55,
        color: 'var(--text-2)',
        marginBottom: 16,
      }}
    >
      <strong style={{ color: 'var(--text-1)' }}>Assist vs Guided — the key difference:</strong>{' '}
      <span style={{ color: 'var(--sev-info)' }}>Assist</span> only <em>thinks about
      results you already collected</em> — it never sends a single new packet to your
      targets. <span style={{ color: 'var(--sev-medium)' }}>Guided</span> actively{' '}
      <em>performs new scanning</em> on your targets (deciding what to run next as it
      learns), but keeps you in control by asking before anything intrusive.
    </div>
  )
}

function Bullets({ items, marker, color }: { items: string[]; marker: string; color: string }) {
  return (
    <ul style={{ margin: '4px 0 0', padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 4 }}>
      {items.map((t, i) => (
        <li key={i} style={{ fontSize: 12, lineHeight: 1.5, color: 'var(--text-2)', display: 'flex', gap: 8 }}>
          <span style={{ color, flexShrink: 0 }}>{marker}</span>
          <span>{t}</span>
        </li>
      ))}
    </ul>
  )
}

function ModeCard({ mode }: { mode: AutonomyMode }) {
  return (
    <div
      style={{
        border: '1px solid var(--border)',
        borderLeft: `3px solid ${mode.riskColor}`,
        borderRadius: 8,
        padding: '12px 14px',
        background: 'var(--bg-1)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13.5, fontWeight: 700, color: 'var(--text-1)' }}>{mode.label}</span>
        <span style={{ fontSize: 10.5, fontWeight: 700, color: mode.riskColor, textTransform: 'uppercase', letterSpacing: 0.4 }}>
          {mode.riskLabel} risk
        </span>
      </div>

      <div style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 4, lineHeight: 1.5 }}>{mode.tagline}</div>

      <div
        style={{
          display: 'inline-flex', alignItems: 'center', gap: 6, marginTop: 8,
          fontSize: 11, fontWeight: 600, color: TOUCH_COLOR[mode.touchesTargets],
        }}
      >
        <span style={{ width: 6, height: 6, borderRadius: '50%', background: TOUCH_COLOR[mode.touchesTargets] }} />
        {TOUCH_LABEL[mode.touchesTargets]}
      </div>

      <div style={{ marginTop: 10 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--text-3)' }}>Does</div>
        <Bullets items={mode.does} marker="→" color="var(--accent)" />
      </div>

      <div style={{ marginTop: 8 }}>
        <div style={{ fontSize: 10.5, textTransform: 'uppercase', letterSpacing: 0.4, color: 'var(--text-3)' }}>Never does</div>
        <Bullets items={mode.neverDoes} marker="✕" color="var(--sev-low)" />
      </div>

      {mode.requires && (
        <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-3)', fontStyle: 'italic' }}>
          Requires: {mode.requires}
        </div>
      )}
    </div>
  )
}

export default function AutonomyModeInfo({
  onClose,
  highlight,
}: {
  onClose: () => void
  /** Optionally scroll/emphasize a specific mode (e.g. the one being selected). */
  highlight?: AutonomyModeId
}): ReactNode {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="AI autonomy modes explained"
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        background: 'oklch(0.05 0.01 255 / 0.7)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="panel"
        style={{ width: 'min(640px, 100%)', maxHeight: '88vh', overflowY: 'auto' }}
      >
        <div className="panel-head" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="panel-title">AI autonomy modes</span>
          <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div style={{ padding: 16 }}>
          <p style={{ fontSize: 12.5, color: 'var(--text-2)', lineHeight: 1.55, marginTop: 0, marginBottom: 14 }}>
            Each mode unlocks strictly more than the one above it. Higher modes are opt-in and can
            actively act on your targets — only run them against systems you are authorized to test.
          </p>

          <AssistVsGuided />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {AUTONOMY_MODES.map((m) => (
              <div
                key={m.id}
                style={highlight === m.id ? { outline: '1px solid var(--accent)', borderRadius: 8 } : undefined}
              >
                <ModeCard mode={m} />
              </div>
            ))}
          </div>

          <div style={{ marginTop: 16, textAlign: 'right' }}>
            <button className="btn btn-primary btn-sm" onClick={onClose}>Got it</button>
          </div>
        </div>
      </div>
    </div>
  )
}
