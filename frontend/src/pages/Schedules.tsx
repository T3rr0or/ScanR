import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, ChevronDown, ChevronUp, Pencil, Settings2,
} from 'lucide-react'
import { schedulesApi, type Schedule } from '@/api/schedules'
import { credentialsApi } from '@/api/credentials'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ALL_CATEGORIES, PORT_RANGES, defaultProfileConfig, type ProfileConfig } from '@/components/ProfileEditor'
import './OperatorSetup.css'

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
  const profile = (() => { try { return JSON.parse(s.scan_profile_json || '{}') } catch { return {} } })()
  const plugins = Array.isArray(profile.plugins) ? profile.plugins : ['*']
  const flags = [profile.intrusive && 'intrusive', profile.stealth && 'stealth', profile.brute_force?.enabled && 'brute-force'].filter(Boolean)
  const fmtDate = (date: string | null) => date ? new Date(date).toLocaleString() : '-'
  return <div className={`schedule-row ${s.enabled ? '' : 'schedule-row-paused'}`}>
    <div className="schedule-row-top"><div><span className="schedule-state">{s.enabled ? 'Enabled' : 'Paused'}</span><strong>{s.name}</strong>{s.description && <p>{s.description}</p>}</div><div className="schedule-actions"><button className="setup-button" onClick={onEdit}><Pencil size={12}/> Edit</button><button className="setup-button" onClick={onToggle}>{s.enabled ? 'Pause' : 'Enable'}</button><button className="setup-icon-button" onClick={onDelete} title={`Delete ${s.name}`} aria-label={`Delete ${s.name}`}><Trash2 size={14}/></button></div></div>
    <div className="schedule-row-meta"><div><span>Targets</span><strong>{s.targets.slice(0,5).join(', ')}{s.targets.length>5?` +${s.targets.length-5} more`:''}</strong></div><div><span>Cron</span><code>{s.cron_expr}</code></div><div><span>Next run</span><strong>{fmtDate(s.next_run)}</strong></div><div><span>Last run</span><strong>{fmtDate(s.last_run)}</strong></div><div><span>Profile</span><strong>{profile.port_range??'-'} / {plugins.includes('*')?'all plugins':`${plugins.length} categories`}{credentialName?` / ${credentialName}`:''}</strong></div></div>
    {(flags.length>0 || s.last_scan_id) && <div className="schedule-row-foot">{flags.map(flag=><span key={String(flag)}>{flag}</span>)}{s.last_scan_id&&<button onClick={()=>navigator.clipboard.writeText(s.last_scan_id!)}>Copy last scan ID</button>}</div>}
  </div>
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

  return <main className="setup-page schedules-page page-pad">
    <header className="setup-header"><div><h1>Scheduled scans</h1><p>Manage targets, profiles, and scan cadence.</p></div>{!showCreate&&!editId&&<button className="setup-button setup-button-primary" onClick={()=>setShowCreate(true)}><Plus size={14}/> New schedule</button>}</header>
    <div className="setup-summary"><span>{schedules.length} schedules</span><span>{schedules.filter(s=>s.enabled).length} enabled</span><span>{schedules.filter(s=>!s.enabled).length} paused</span></div>
    {err&&<div className="setup-error" role="alert">{err}</div>}
    {showCreate&&<section className="setup-form schedule-form"><div className="setup-form-heading"><strong>New schedule</strong></div><ScheduleForm onSubmit={data=>createMut.mutate(data)} onCancel={()=>{setShowCreate(false);setErr(null)}} loading={createMut.isPending} submitLabel="Create schedule"/></section>}
    {editId&&editingSchedule&&<section className="setup-form schedule-form"><div className="setup-form-heading"><strong>Edit schedule / {editingSchedule.name}</strong></div><ScheduleForm initial={editingSchedule} onSubmit={data=>updateMut.mutate({id:editId,data})} onCancel={()=>{setEditId(null);setErr(null)}} loading={updateMut.isPending} submitLabel="Save changes"/></section>}
    <section className="setup-list"><div className="setup-list-heading"><span>Schedules</span><span>{schedules.length} records</span></div>{isLoading?<div className="setup-empty">Loading schedules...</div>:schedules.length===0?<div className="setup-empty">No schedules configured. Create one to run scans on a cadence.</div>:schedules.map(s=>editId===s.id?null:<ScheduleCard key={s.id} schedule={s} onToggle={()=>toggleMut.mutate({id:s.id,enabled:!s.enabled})} onDelete={()=>{if(confirm(`Delete schedule "${s.name}"?`))deleteMut.mutate(s.id)}} onEdit={()=>{setEditId(s.id);setShowCreate(false);setErr(null)}} credentialName={(()=>{try{const pj=JSON.parse(s.scan_profile_json||'{}');return pj.credential_id?credMap[pj.credential_id]:undefined}catch{return undefined}})()}/>)}</section>
  </main>
}
