import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Clock, Plus, Trash2, ToggleLeft, ToggleRight, Calendar,
  ChevronDown, ChevronUp, Pencil, Target, Settings2,
} from 'lucide-react'
import { schedulesApi, type Schedule } from '@/api/schedules'
import { credentialsApi } from '@/api/credentials'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ALL_CATEGORIES, PORT_RANGES, defaultProfileConfig, type ProfileConfig } from '@/components/ProfileEditor'

const CRON_PRESETS = [
  { label: 'Every hour',   value: '0 * * * *' },
  { label: 'Daily 2am',    value: '0 2 * * *' },
  { label: 'Mon 2am',      value: '0 2 * * 1' },
  { label: 'Sun midnight', value: '0 0 * * 0' },
  { label: 'Every 6h',     value: '0 */6 * * *' },
  { label: '1st of month', value: '0 2 1 * *' },
]

const PLUGIN_CATEGORIES = ALL_CATEGORIES

function categoriesFromPlugins(plugins: unknown): string[] {
  if (!Array.isArray(plugins) || plugins.includes('*')) return ALL_CATEGORIES.map(c => c.id)
  return ALL_CATEGORIES
    .filter(cat => plugins.some(p => typeof p === 'string' && (p === cat.id || p === `${cat.id}.*` || p.startsWith(`${cat.id}.`))))
    .map(c => c.id)
}

/* ─── Schedule form (create + edit) ──────────────────────────── */
function ScheduleForm({
  initial,
  onSubmit,
  onCancel,
  loading,
  submitLabel,
}: {
  initial?: Schedule
  onSubmit: (data: {
    name: string; description: string; targets: string[];
    cron_expr: string; scan_profile_json: string; enabled: boolean;
  }) => void
  onCancel: () => void
  loading: boolean
  submitLabel: string
}) {
  const [name, setName]         = useState(initial?.name ?? '')
  const [desc, setDesc]         = useState(initial?.description ?? '')
  const [targets, setTargets]   = useState((initial?.targets ?? []).join('\n'))
  const [cron, setCron]         = useState(initial?.cron_expr ?? '0 2 * * *')
  const [enabled, setEnabled]   = useState(initial?.enabled ?? true)
  const [showAdvanced, setShowAdvanced] = useState(false)

  // Parse existing profile_json if editing
  const parsedInitial = (() => {
    try { return initial?.scan_profile_json ? JSON.parse(initial.scan_profile_json) : {} } catch { return {} }
  })()
  const [profileConfig, setProfileConfig] = useState<ProfileConfig>(defaultProfileConfig({
    port_range: parsedInitial.port_range ?? 'top-1000',
    categories: parsedInitial.categories ?? ALL_CATEGORIES.map(c => c.id),
  }))
  const [enabledCategories, setEnabledCategories] = useState<Set<string>>(
    new Set(parsedInitial.categories ?? ALL_CATEGORIES.map(c => c.id))
  )
  const [bruteForce, setBruteForce] = useState({
    enabled: parsedInitial.brute_force?.enabled ?? false,
    delay_ms: parsedInitial.brute_force?.delay_ms ?? 500,
  })
  const [intrusive, setIntrusive]     = useState(parsedInitial.intrusive ?? false)
  const [stealth, setStealth]         = useState(parsedInitial.stealth ?? false)
  const [credentialId, setCredentialId] = useState<string>(parsedInitial.credential_id ?? '')
  const [baseProfileJson, setBaseProfileJson] = useState<Record<string, unknown>>(parsedInitial)

  const { data: credentials = [] } = useQuery({
    queryKey: ['credentials'],
    queryFn: credentialsApi.list,
  })
  const { data: templates = [] } = useQuery({
    queryKey: ['templates'],
    queryFn: templatesApi.list,
  })

  function buildProfileJson() {
    const cats = [...enabledCategories]
    const pluginGlobs = cats.length === ALL_CATEGORIES.length ? ['*'] : cats.map(c => `${c}.*`)
    const pj: Record<string, unknown> = {
      ...baseProfileJson,
      port_range: profileConfig.port_range,
      plugins: pluginGlobs,
    }
    if (bruteForce.enabled) pj.brute_force = { enabled: true, delay_ms: bruteForce.delay_ms }
    if (intrusive) pj.intrusive = true
    if (stealth) pj.stealth = true
    if (credentialId) pj.credential_id = credentialId
    return JSON.stringify(pj)
  }

  function applyTemplate(templateId: string) {
    const template = templates.find((t: ScanTemplate) => t.id === templateId)
    if (!template?.profile_json) return
    const pj = template.profile_json
    const cats = categoriesFromPlugins(pj.plugins)
    setBaseProfileJson(pj)
    setProfileConfig(defaultProfileConfig({
      port_range: typeof pj.port_range === 'string' ? pj.port_range : 'top-1000',
      categories: cats,
    }))
    setEnabledCategories(new Set(cats))
    setIntrusive(Boolean(pj.intrusive))
    setStealth(Boolean(pj.stealth))
    const brute = typeof pj.brute_force === 'object' && pj.brute_force !== null ? pj.brute_force as Record<string, unknown> : {}
    setBruteForce({
      enabled: Boolean(brute.enabled),
      delay_ms: typeof brute.delay_ms === 'number' ? brute.delay_ms : 500,
    })
  }

  function handleSubmit() {
    const targetList = targets.split('\n').map(t => t.trim()).filter(Boolean)
    onSubmit({
      name, description: desc,
      targets: targetList,
      cron_expr: cron,
      scan_profile_json: buildProfileJson(),
      enabled,
    })
  }

  const canSubmit = name.trim() && targets.trim()

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Name + description */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input value={name} onChange={e => setName(e.target.value)}
          placeholder="Schedule name *" className="input" style={{ flex: 2, minWidth: 180 }} />
        <input value={desc} onChange={e => setDesc(e.target.value)}
          placeholder="Description (optional)" className="input" style={{ flex: 3, minWidth: 200 }} />
      </div>

      {/* Targets */}
      <div>
        <label className="label">Targets — one per line (IPs, CIDRs, hostnames)</label>
        <textarea value={targets} onChange={e => setTargets(e.target.value)}
          placeholder={"192.168.1.0/24\n10.0.0.1-50\nexample.com"}
          rows={3} className="textarea"
          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}
        />
      </div>

      {/* Template */}
      <div>
        <label className="label">Template</label>
        <select className="select-field" onChange={e => applyTemplate(e.target.value)} defaultValue="">
          <option value="">Custom schedule profile</option>
          {templates.map(t => (
            <option key={t.id} value={t.id}>{t.name}{t.is_system ? ' (system)' : ''}</option>
          ))}
        </select>
      </div>

      {/* Port range */}
      <div>
        <label className="label">Port range</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {PORT_RANGES.map(r => (
            <button key={r.value}
              onClick={() => setProfileConfig(p => ({ ...p, port_range: r.value }))}
              className={`btn btn-sm ${profileConfig.port_range === r.value ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 11 }}
            >{r.label}</button>
          ))}
        </div>
      </div>

      {/* Plugin categories */}
      <div>
        <label className="label">Plugin categories</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {PLUGIN_CATEGORIES.map(cat => {
            const on = enabledCategories.has(cat.id)
            return (
              <button key={cat.id}
                onClick={() => setEnabledCategories(prev => {
                  const next = new Set(prev)
                  if (on) next.delete(cat.id); else next.add(cat.id)
                  return next
                })}
                className={`btn btn-sm ${on ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 11 }}
              >
                {on ? '✓ ' : ''}{cat.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Credentials */}
      <div>
        <label className="label">Credentials (optional — for authenticated plugins)</label>
        <select
          value={credentialId}
          onChange={e => setCredentialId(e.target.value)}
          className="select-field"
        >
          <option value="">No credentials (unauthenticated scan)</option>
          {credentials.map(c => (
            <option key={c.id} value={c.id}>
              {c.name} ({c.type}{c.username ? ` · ${c.username}` : ''})
            </option>
          ))}
        </select>
        {credentialId && (
          <p style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 4 }}>
            Selected credentials will be used for SSH audit, SMB, LDAP, AD, and other authenticated plugins.
          </p>
        )}
        {credentials.length === 0 && (
          <p style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 4 }}>
            No credentials saved. Add them in <strong>Credentials</strong> to enable authenticated scanning.
          </p>
        )}
      </div>

      {/* Cron */}
      <div>
        <label className="label">Schedule (cron)</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
          {CRON_PRESETS.map(p => (
            <button key={p.value}
              onClick={() => setCron(p.value)}
              className={`btn btn-sm ${cron === p.value ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: 11 }}
            >{p.label}</button>
          ))}
        </div>
        <input value={cron} onChange={e => setCron(e.target.value)}
          placeholder="0 2 * * *" className="input"
          style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} />
        <p style={{ fontSize: 10, color: 'var(--text-3)', marginTop: 4 }}>
          Minimum interval: 1 hour. Format: minute hour day month weekday
        </p>
      </div>

      {/* Advanced toggle */}
      <button
        onClick={() => setShowAdvanced(v => !v)}
        className="btn btn-ghost btn-sm"
        style={{ alignSelf: 'flex-start', fontSize: 11, gap: 4 }}
      >
        <Settings2 size={12} /> Advanced options {showAdvanced ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>

      {showAdvanced && (
        <div className="panel" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={intrusive} onChange={e => setIntrusive(e.target.checked)} />
            <span><strong>Intrusive mode</strong> — enables POST-form SQL injection, form brute-force</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={stealth} onChange={e => setStealth(e.target.checked)} />
            <span><strong>Stealth mode</strong> — randomised delays, UA rotation, WAF bypass encoding</span>
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={bruteForce.enabled}
              onChange={e => setBruteForce(b => ({ ...b, enabled: e.target.checked }))} />
            <span><strong>Brute-force</strong> — credential/password spraying against detected services</span>
          </label>
          {bruteForce.enabled && (
            <div style={{ paddingLeft: 22, display: 'flex', alignItems: 'center', gap: 8 }}>
              <label className="label" style={{ margin: 0 }}>Delay between attempts (ms)</label>
              <input type="number" min={200} max={5000} step={100}
                value={bruteForce.delay_ms}
                onChange={e => setBruteForce(b => ({ ...b, delay_ms: Number(e.target.value) }))}
                className="input" style={{ width: 90, fontSize: 12 }}
              />
            </div>
          )}
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
            <span>Schedule <strong>enabled</strong> immediately after creation</span>
          </label>
        </div>
      )}

      {/* Buttons */}
      <div style={{ display: 'flex', gap: 8 }}>
        <button
          onClick={handleSubmit}
          disabled={!canSubmit || loading}
          className="btn btn-primary btn-sm"
        >
          {loading ? 'Saving…' : submitLabel}
        </button>
        <button onClick={onCancel} className="btn btn-ghost btn-sm">Cancel</button>
      </div>
    </div>
  )
}

/* ─── Schedule card ───────────────────────────────────────────── */
function ScheduleCard({ schedule: s, onToggle, onDelete, onEdit, credentialName }: {
  schedule: Schedule
  onToggle: () => void
  onDelete: () => void
  onEdit: () => void
  credentialName?: string
}) {
  // Parse profile summary
  const profile = (() => {
    try { return JSON.parse(s.scan_profile_json || '{}') } catch { return {} }
  })()
  const portRange = profile.port_range ?? '—'
  const plugins   = Array.isArray(profile.plugins) ? profile.plugins : ['*']
  const flags     = [
    profile.intrusive && 'intrusive',
    profile.stealth   && 'stealth',
    profile.brute_force?.enabled && 'brute-force',
  ].filter(Boolean)

  function fmtDate(d: string | null) {
    if (!d) return '—'
    const dt = new Date(d)
    return dt.toLocaleDateString() + ' ' + dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }

  return (
    <div className="panel" style={{ padding: 14, opacity: s.enabled ? 1 : 0.6, borderLeft: `3px solid ${s.enabled ? 'var(--accent)' : 'var(--border)'}` }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        {/* Left: info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Title row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text-0)' }}>{s.name}</span>
            <span className={`pill ${s.enabled ? 'pill-completed' : 'pill-cancelled'}`} style={{ fontSize: 10 }}>
              {s.enabled ? 'enabled' : 'paused'}
            </span>
            {flags.map(f => (
              <span key={f} className="pill" style={{ fontSize: 10, color: 'var(--sev-medium)', borderColor: 'oklch(0.80 0.16 70/0.3)', background: 'oklch(0.80 0.16 70/0.08)' }}>{f}</span>
            ))}
          </div>

          {s.description && (
            <p style={{ fontSize: 11.5, color: 'var(--text-2)', marginBottom: 8 }}>{s.description}</p>
          )}

          {/* Targets */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 8 }}>
            {s.targets.slice(0, 5).map((t, i) => (
              <span key={i} className="mono" style={{ fontSize: 10.5, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 6px', borderRadius: 4 }}>{t}</span>
            ))}
            {s.targets.length > 5 && (
              <span className="dimmer" style={{ fontSize: 10 }}>+{s.targets.length - 5} more</span>
            )}
          </div>

          {/* Profile summary row */}
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-3)', marginBottom: 8 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <Target size={10} /> <span style={{ color: 'var(--text-2)' }}>{portRange}</span>
            </span>
            <span>
              Plugins: <span style={{ color: 'var(--text-2)' }}>
                {plugins.includes('*') ? 'all' : plugins.join(', ')}
              </span>
            </span>
            {credentialName && (
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                🔑 <span style={{ color: 'var(--ok)' }}>{credentialName}</span>
              </span>
            )}
            {!credentialName && !profile.credential_id && (
              <span style={{ color: 'var(--text-3)', fontStyle: 'italic' }}>unauthenticated</span>
            )}
          </div>

          {/* Timing row */}
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-3)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span className="mono" style={{ background: 'var(--bg-2)', padding: '2px 6px', borderRadius: 4, color: 'var(--text-1)', fontSize: 11 }}>
                {s.cron_expr}
              </span>
            </div>
            <span>Next: <span style={{ color: 'var(--text-2)' }}>{fmtDate(s.next_run)}</span></span>
            <span>Last: <span style={{ color: 'var(--text-2)' }}>{fmtDate(s.last_run)}</span></span>
            {s.last_scan_id && (
              <span style={{ color: 'var(--accent)', cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => navigator.clipboard.writeText(s.last_scan_id!)}>
                Last scan ID copied
              </span>
            )}
          </div>
        </div>

        {/* Right: actions */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flexShrink: 0 }}>
          <button onClick={onEdit} className="btn btn-ghost btn-icon btn-sm" title="Edit schedule">
            <Pencil size={13} style={{ color: 'var(--accent)' }} />
          </button>
          <button onClick={onToggle} className="btn btn-ghost btn-icon btn-sm" title={s.enabled ? 'Pause' : 'Enable'}>
            {s.enabled
              ? <ToggleRight size={18} style={{ color: 'var(--ok)' }} />
              : <ToggleLeft size={18} style={{ color: 'var(--text-3)' }} />
            }
          </button>
          <button onClick={onDelete} className="btn btn-ghost btn-icon btn-sm" title="Delete"
            style={{ color: 'var(--sev-high)' }}>
            <Trash2 size={13} />
          </button>
        </div>
      </div>
    </div>
  )
}

/* ─── Main page ───────────────────────────────────────────────── */
export default function Schedules() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editId, setEditId]         = useState<string | null>(null)
  const [err, setErr]               = useState<string | null>(null)

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: schedulesApi.list,
  })

  const createMut = useMutation({
    mutationFn: (data: Parameters<typeof schedulesApi.create>[0]) => schedulesApi.create(data),
    onSuccess: () => { setShowCreate(false); setErr(null); qc.invalidateQueries({ queryKey: ['schedules'] }) },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : 'Error creating schedule'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Parameters<typeof schedulesApi.update>[1] }) =>
      schedulesApi.update(id, data),
    onSuccess: () => { setEditId(null); setErr(null); qc.invalidateQueries({ queryKey: ['schedules'] }) },
    onError: (e: unknown) => setErr(e instanceof Error ? e.message : 'Error updating schedule'),
  })

  const deleteMut = useMutation({
    mutationFn: schedulesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => schedulesApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const { data: allCredentials = [] } = useQuery({
    queryKey: ['credentials'],
    queryFn: credentialsApi.list,
  })
  const credMap = Object.fromEntries(allCredentials.map(c => [c.id, c.name]))

  const editingSchedule = editId ? schedules.find(s => s.id === editId) : null

  return (
    <div className="page-pad" style={{ maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Clock size={18} style={{ color: 'var(--accent)' }} />
          <div>
            <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Scheduled Scans</h1>
            <p style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 2 }}>Recurring scans run automatically on a cron schedule</p>
          </div>
        </div>
        {!showCreate && !editId && (
          <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
            <Plus size={13} /> New Schedule
          </button>
        )}
      </div>

      {err && (
        <div style={{ background: 'var(--sev-high)', color: '#fff', padding: '8px 12px', borderRadius: 6, fontSize: 12, marginBottom: 14 }}>
          {err}
        </div>
      )}

      {/* Create form */}
      {showCreate && (
        <div className="panel" style={{ marginBottom: 20, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Plus size={14} style={{ color: 'var(--accent)' }} /> New Schedule
          </div>
          <ScheduleForm
            onSubmit={data => createMut.mutate(data)}
            onCancel={() => { setShowCreate(false); setErr(null) }}
            loading={createMut.isPending}
            submitLabel="Create schedule"
          />
        </div>
      )}

      {/* Edit form */}
      {editId && editingSchedule && (
        <div className="panel" style={{ marginBottom: 20, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Pencil size={14} style={{ color: 'var(--accent)' }} /> Edit Schedule
          </div>
          <ScheduleForm
            initial={editingSchedule}
            onSubmit={data => updateMut.mutate({ id: editId, data })}
            onCancel={() => { setEditId(null); setErr(null) }}
            loading={updateMut.isPending}
            submitLabel="Save changes"
          />
        </div>
      )}

      {/* List */}
      {isLoading ? (
        <div className="dimmer" style={{ fontSize: 13, padding: '20px 0' }}>Loading…</div>
      ) : schedules.length === 0 && !showCreate ? (
        <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)' }}>
          <Calendar size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
          <p style={{ fontSize: 13 }}>No scheduled scans yet.</p>
          <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm" style={{ marginTop: 12 }}>
            <Plus size={13} /> Create your first schedule
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {schedules.map(s => (
            editId === s.id ? null : (
              <ScheduleCard
                key={s.id}
                schedule={s}
                onToggle={() => toggleMut.mutate({ id: s.id, enabled: !s.enabled })}
                onDelete={() => { if (confirm(`Delete schedule "${s.name}"?`)) deleteMut.mutate(s.id) }}
                onEdit={() => { setEditId(s.id); setShowCreate(false); setErr(null) }}
                credentialName={(() => {
                  try { const pj = JSON.parse(s.scan_profile_json || '{}'); return pj.credential_id ? credMap[pj.credential_id] : undefined } catch { return undefined }
                })()}
              />
            )
          ))}
        </div>
      )}
    </div>
  )
}
