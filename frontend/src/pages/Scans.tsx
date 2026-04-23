import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity, Scan, Plus, Download, Search, Filter,
  Terminal, Play, StopCircle, GitCompare, Trash2,
  Radar, Globe, Zap, SlidersHorizontal,
  X, FileText, AlertTriangle, Check,
} from 'lucide-react'
import { scansApi, type ScanCreate, type ScanCredentialIn } from '@/api/scans'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ALL_CATEGORIES, PORT_RANGES, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import ScanDelta from './ScanDelta'
import { StatusPill, SeverityBar, CHML, Meter, fmtDuration, relTime } from '@/components/ui'

interface Props {
  onOpenScan?: (id: string) => void
}

const PAGE_SIZE = 50

type FilterStatus = 'all' | 'running' | 'completed' | 'pending' | 'failed'

/* ── Inline credential state ─────────────────────────────────────── */
interface InlineCredential {
  id: string
  role: 'primary_domain' | 'local_admin' | 'ssh' | 'snmp' | 'generic'
  type: 'smb' | 'ssh' | 'snmp' | 'http_basic' | 'wmi'
  username: string
  domain: string
  password: string
  saveToVault: boolean
  vaultName: string
}

const ROLE_LABELS: Record<InlineCredential['role'], string> = {
  primary_domain: 'Primary Domain (AD)',
  local_admin: 'Local Admin',
  ssh: 'SSH',
  snmp: 'SNMP',
  generic: 'Generic',
}

const TYPE_LABELS: Record<InlineCredential['type'], string> = {
  smb: 'Windows/SMB',
  wmi: 'WMI',
  ssh: 'SSH',
  snmp: 'SNMP',
  http_basic: 'HTTP Basic',
}

/* ── Design reference template cards ─────────────────────────────── */
const DESIGN_TEMPLATES = [
  { id: 'quick',  name: 'Quick Scan',  desc: 'Top 1,000 ports · no brute-force', icon: 'zap'     },
  { id: 'full',   name: 'Full Scan',   desc: 'All 65,535 ports · all plugins',    icon: 'radar'   },
  { id: 'web',    name: 'Web Audit',   desc: '80,443,8080,8443 · web + TLS',      icon: 'globe'   },
  { id: 'custom', name: 'Custom',      desc: 'Pick ports & plugins',              icon: 'sliders' },
]

const PLUGIN_CATEGORIES = [
  { id: 'web',      label: 'Web',      count: 10   },
  { id: 'ssl',      label: 'SSL/TLS',  count: 5    },
  { id: 'ssh',      label: 'SSH',      count: 3    },
  { id: 'services', label: 'Services', count: 14   },
  { id: 'network',  label: 'Network',  count: 3    },
  { id: 'cve',      label: 'CVE',      count: 1    },
  { id: 'nuclei',   label: 'Nuclei',   count: 4821 },
]

function TemplateIcon({ name, size = 14 }: { name: string; size?: number }) {
  if (name === 'zap')     return <Zap size={size} />
  if (name === 'radar')   return <Radar size={size} />
  if (name === 'globe')   return <Globe size={size} />
  if (name === 'sliders') return <SlidersHorizontal size={size} />
  return <Scan size={size} />
}

/* ─────────────────────────────────────────────────────────────────
   Main page component
   ───────────────────────────────────────────────────────────────── */
export default function Scans({ onOpenScan }: Props) {
  const qc = useQueryClient()
  const [showForm, setShowForm]       = useState(false)
  const [deltaScan, setDeltaScan]     = useState<{ id: string; name: string } | null>(null)
  const [page, setPage]               = useState(0)
  const [filter, setFilter]           = useState<FilterStatus>('all')
  const [search, setSearch]           = useState('')
  const [lastUpdated]                 = useState<Date>(new Date())

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    refetchInterval: 3000,
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

  /* counts per status */
  const counts = useMemo(() => ({
    all:       scans.length,
    running:   scans.filter(s => s.status === 'running').length,
    completed: scans.filter(s => s.status === 'completed').length,
    pending:   scans.filter(s => s.status === 'pending').length,
    failed:    scans.filter(s => s.status === 'failed').length,
  }), [scans])

  /* filter + search */
  const filtered = useMemo(() => {
    let list = filter === 'all' ? scans : scans.filter(s => s.status === filter)
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(s =>
        s.name.toLowerCase().includes(q) ||
        (s.targets ?? []).some(t => t.toLowerCase().includes(q))
      )
    }
    return list
  }, [scans, filter, search])

  return (
    <div style={{ padding: 20, maxWidth: 1480, margin: '0 auto' }}>
      {/* Delta modal */}
      {deltaScan && (
        <ScanDelta
          scanId={deltaScan.id}
          scanName={deltaScan.name}
          onClose={() => setDeltaScan(null)}
        />
      )}

      {/* New Scan modal */}
      {showForm && (
        <NewScanModal
          onClose={() => setShowForm(false)}
          onCreate={body => createMut.mutate(body)}
          loading={createMut.isPending}
        />
      )}

      {/* ── Page header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-0)' }}>
            Scans
          </h1>
          <div className="mono" style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>
            {scans.length} total · last updated {relTime(lastUpdated.toISOString())}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="btn">
            <Download size={12} /> Export
          </button>
          <button className="btn btn-primary" onClick={() => setShowForm(true)}>
            <Plus size={12} /> New Scan
          </button>
        </div>
      </div>

      {/* ── Filter chips + search ── */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
        {(['all', 'running', 'completed', 'pending', 'failed'] as FilterStatus[]).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '5px 10px',
              borderRadius: 6,
              fontSize: 11.5,
              background: filter === f ? 'var(--bg-3)' : 'transparent',
              color: filter === f ? 'var(--text-0)' : 'var(--text-2)',
              border: '1px solid ' + (filter === f ? 'var(--border-strong)' : 'transparent'),
              textTransform: 'capitalize',
              cursor: 'pointer',
              transition: 'background 120ms ease, color 120ms ease, border-color 120ms ease',
            }}
          >
            {f}{' '}
            <span className="mono" style={{ color: 'var(--text-3)', marginLeft: 2 }}>
              {counts[f]}
            </span>
          </button>
        ))}

        <div style={{ flex: 1 }} />

        <div className="search" style={{ width: 260 }}>
          <Search size={13} color="var(--text-3)" strokeWidth={2} />
          <input
            placeholder="Search by name, target, CVE…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <span className="kbd">⌘K</span>
        </div>

        <button className="btn">
          <Filter size={12} /> Filters
        </button>
      </div>

      {/* ── Table ── */}
      <div className="panel" style={{ overflow: 'hidden' }}>
        <table className="tbl">
          <thead>
            <tr>
              <th style={{ width: 28 }}></th>
              <th>Name</th>
              <th>Targets</th>
              <th>Profile</th>
              <th>Status</th>
              <th>Hosts</th>
              <th>Findings (C/H/M/L)</th>
              <th>Severity</th>
              <th>Duration</th>
              <th>When</th>
              <th style={{ width: 120 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(s => (
              <tr key={s.id} onClick={() => onOpenScan?.(s.id)}>
                {/* Status icon */}
                <td>
                  {s.status === 'running'
                    ? <Activity size={13} color="var(--accent-2)" />
                    : <Scan size={13} color="var(--text-3)" />
                  }
                </td>

                {/* Name + ID */}
                <td>
                  <div style={{ fontWeight: 500, fontSize: 12.5, color: 'var(--text-0)' }}>{s.name}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 2 }}>{s.id}</div>
                </td>

                {/* Targets */}
                <td className="mono" style={{ fontSize: 11.5, color: 'var(--text-2)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {(s.targets ?? []).slice(0, 1).join(', ')}
                  {(s.targets ?? []).length > 1 && (
                    <span style={{ color: 'var(--text-3)' }}> +{(s.targets ?? []).length - 1}</span>
                  )}
                </td>

                {/* Profile */}
                <td className="dim" style={{ fontSize: 12.5 }}>{s.profile}</td>

                {/* Status pill + progress meter */}
                <td>
                  <StatusPill status={s.status} />
                  {s.status === 'running' && (
                    <div style={{ width: 80, marginTop: 4 }}>
                      <Meter value={s.progress ?? 0} color="var(--accent-2)" />
                    </div>
                  )}
                </td>

                {/* Hosts up/total */}
                <td className="mono">
                  <span style={{ color: 'var(--text-0)' }}>{s.hosts_up}</span>
                  <span style={{ color: 'var(--text-3)' }}>/{s.hosts_total}</span>
                </td>

                {/* C/H/M/L */}
                <td>
                  <CHML
                    c={s.findings_critical}
                    h={s.findings_high}
                    m={s.findings_medium}
                    l={s.findings_low}
                  />
                </td>

                {/* Severity bar */}
                <td style={{ width: 110 }}>
                  <SeverityBar
                    c={s.findings_critical}
                    h={s.findings_high}
                    m={s.findings_medium}
                    l={s.findings_low}
                    i={s.findings_info}
                  />
                </td>

                {/* Duration */}
                <td className="mono dim">{fmtDuration(s.duration_s)}</td>

                {/* When */}
                <td className="mono dim">{relTime(s.created_at)}</td>

                {/* Actions — stop propagation */}
                <td onClick={e => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 2 }}>
                    <button
                      className="btn btn-ghost btn-icon"
                      title="Open console"
                      onClick={() => onOpenScan?.(s.id)}
                    >
                      <Terminal size={13} />
                    </button>

                    {s.status === 'pending' && (
                      <button
                        className="btn btn-ghost btn-icon"
                        title="Launch"
                        onClick={() => launchMut.mutate(s.id)}
                        style={{ color: 'var(--ok)' }}
                      >
                        <Play size={11} />
                      </button>
                    )}

                    {s.status === 'running' && (
                      <button
                        className="btn btn-ghost btn-icon"
                        title="Cancel"
                        onClick={() => cancelMut.mutate(s.id)}
                        style={{ color: 'var(--sev-high)' }}
                      >
                        <StopCircle size={10} />
                      </button>
                    )}

                    {(s.status === 'completed' || s.status === 'failed') && (
                      <button
                        className="btn btn-ghost btn-icon"
                        title="Compare"
                        onClick={() => setDeltaScan({ id: s.id, name: s.name })}
                      >
                        <GitCompare size={13} />
                      </button>
                    )}

                    <button
                      className="btn btn-ghost btn-icon"
                      title="Delete"
                      onClick={() => { if (confirm('Delete this scan?')) deleteMut.mutate(s.id) }}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}

            {filtered.length === 0 && (
              <tr>
                <td colSpan={11} style={{ padding: '40px 16px', textAlign: 'center', color: 'var(--text-3)', fontSize: 13 }}>
                  {search ? 'No scans match your search.' : 'No scans yet — create one to get started.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ── */}
      {(page > 0 || scans.length === PAGE_SIZE) && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 16, justifyContent: 'flex-end' }}>
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            className="btn btn-ghost btn-sm"
          >
            Previous
          </button>
          <span className="dimmer" style={{ fontSize: 12 }}>Page {page + 1}</span>
          <button
            onClick={() => setPage(p => p + 1)}
            disabled={scans.length < PAGE_SIZE}
            className="btn btn-ghost btn-sm"
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   New Scan Modal
   ───────────────────────────────────────────────────────────────── */
function NewScanModal({
  onClose,
  onCreate,
  loading,
}: {
  onClose: () => void
  onCreate: (body: ScanCreate) => void
  loading: boolean
}) {
  const [selectedDesignTemplate, setSelectedDesignTemplate] = useState('quick')
  const [selectedApiTemplate, setSelectedApiTemplate]       = useState<ScanTemplate | null>(null)
  const [name, setName]       = useState('')
  const [targets, setTargets] = useState('')
  const [credentials, setCredentials] = useState<InlineCredential[]>([])

  const [profileConfig, setProfileConfig] = useState<ProfileConfig>({
    port_range: 'top-1000',
    categories: ALL_CATEGORIES.map(x => x.id),
  })
  const [enabledCategories, setEnabledCategories] = useState<Set<string>>(
    new Set(PLUGIN_CATEGORIES.map(c => c.id))
  )

  const { data: apiTemplates = [] } = useQuery({
    queryKey: ['templates'],
    queryFn: templatesApi.list,
  })
  const systemTemplates = apiTemplates.filter(t => t.is_system)

  function applyApiTemplate(t: ScanTemplate) {
    setSelectedApiTemplate(t)
    setProfileConfig(jsonToConfig(t.profile_json))
    if (!name) setName(t.name)
  }

  function toggleCategory(id: string) {
    setEnabledCategories(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function addCredential() {
    setCredentials(prev => [...prev, {
      id: Math.random().toString(36).slice(2),
      role: 'primary_domain',
      type: 'smb',
      username: '',
      domain: '',
      password: '',
      saveToVault: false,
      vaultName: '',
    }])
  }

  function updateCredential(id: string, patch: Partial<InlineCredential>) {
    setCredentials(prev => prev.map(c => c.id === id ? { ...c, ...patch } : c))
  }

  function removeCredential(id: string) {
    setCredentials(prev => prev.filter(c => c.id !== id))
  }

  function handleCreate() {
    const credPayload: ScanCredentialIn[] = credentials.map(c => ({
      role: c.role,
      type: c.type,
      username: c.username || undefined,
      domain: c.domain || undefined,
      password: c.password || undefined,
      save_to_vault: c.saveToVault,
      vault_name: c.vaultName || undefined,
    }))

    onCreate({
      name,
      targets: targets.split('\n').map(t => t.trim()).filter(Boolean),
      profile: 'custom',
      profile_json: JSON.stringify(configToJson(profileConfig)),
      credentials: credPayload.length > 0 ? credPayload : undefined,
    })
  }

  const canSubmit = name.trim() && targets.trim() && !loading

  return (
    <div
      style={{
        position: 'fixed', inset: 0,
        background: 'oklch(0.06 0.01 255 / 0.7)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        zIndex: 100, padding: 20,
      }}
      onClick={onClose}
    >
      <div
        className="panel"
        style={{ width: 640, maxHeight: '92vh', overflow: 'auto', background: 'var(--bg-1)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Modal header */}
        <div className="panel-head">
          <Radar size={14} color="var(--accent)" />
          <span style={{ fontSize: 13, fontWeight: 600 }}>New Scan</span>
          <button
            className="btn btn-ghost btn-icon"
            style={{ marginLeft: 'auto' }}
            onClick={onClose}
          >
            <X size={14} />
          </button>
        </div>

        {/* Modal body */}
        <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* 1. Template cards — use API templates if available, otherwise design defaults */}
          <div>
            <div className="label">Start from template</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
              {systemTemplates.length > 0
                ? systemTemplates.slice(0, 4).map(t => {
                    const active = selectedApiTemplate?.id === t.id
                    return (
                      <button
                        key={t.id}
                        onClick={() => applyApiTemplate(t)}
                        style={{
                          padding: 12, borderRadius: 8, textAlign: 'left', cursor: 'pointer',
                          background: active ? 'var(--accent-soft)' : 'var(--bg-0)',
                          border: '1px solid ' + (active ? 'var(--accent)' : 'var(--border)'),
                          display: 'flex', alignItems: 'flex-start', gap: 10,
                        }}
                      >
                        <span style={{
                          width: 28, height: 28, borderRadius: 6, background: 'var(--bg-2)',
                          color: active ? 'var(--accent)' : 'var(--text-1)',
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                          flexShrink: 0,
                        }}>
                          <Scan size={14} />
                        </span>
                        <div>
                          <div style={{ fontSize: 12.5, fontWeight: 600 }}>{t.name}</div>
                          <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 2 }}>
                            {t.description ?? PORT_RANGES.find(r => r.value === (t.profile_json as any)?.port_range)?.label.split(' —')[0]}
                          </div>
                        </div>
                      </button>
                    )
                  })
                : DESIGN_TEMPLATES.map(t => {
                    const active = selectedDesignTemplate === t.id
                    return (
                      <button
                        key={t.id}
                        onClick={() => setSelectedDesignTemplate(t.id)}
                        style={{
                          padding: 12, borderRadius: 8, textAlign: 'left', cursor: 'pointer',
                          background: active ? 'var(--accent-soft)' : 'var(--bg-0)',
                          border: '1px solid ' + (active ? 'var(--accent)' : 'var(--border)'),
                          display: 'flex', alignItems: 'flex-start', gap: 10,
                        }}
                      >
                        <span style={{
                          width: 28, height: 28, borderRadius: 6, background: 'var(--bg-2)',
                          color: active ? 'var(--accent)' : 'var(--text-1)',
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                          flexShrink: 0,
                        }}>
                          <TemplateIcon name={t.icon} size={14} />
                        </span>
                        <div>
                          <div style={{ fontSize: 12.5, fontWeight: 600 }}>{t.name}</div>
                          <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 2 }}>
                            {t.desc}
                          </div>
                        </div>
                      </button>
                    )
                  })
              }
            </div>
          </div>

          {/* 2. Scan name */}
          <div>
            <label className="label">Scan name</label>
            <input
              className="input"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="Internal Network — Q2 2026"
            />
          </div>

          {/* 3. Targets */}
          <div>
            <label className="label">
              Targets{' '}
              <span style={{ color: 'var(--text-3)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
                — one per line · IP, CIDR, hostname, range
              </span>
            </label>
            <textarea
              className="textarea"
              rows={3}
              value={targets}
              onChange={e => setTargets(e.target.value)}
              placeholder={'10.42.0.0/20\nedge.acme.corp'}
            />
          </div>

          {/* 4. Credentials */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <label className="label" style={{ margin: 0 }}>Credentials</label>
              <button className="btn btn-ghost btn-sm" onClick={addCredential} type="button">
                <Plus size={11} /> Add Credential
              </button>
            </div>

            {credentials.map(cred => (
              <CredentialCard
                key={cred.id}
                cred={cred}
                onChange={patch => updateCredential(cred.id, patch)}
                onRemove={() => removeCredential(cred.id)}
              />
            ))}
          </div>

          {/* 5. Plugin categories */}
          <div>
            <label className="label">Plugin categories</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {PLUGIN_CATEGORIES.map(c => {
                const on = enabledCategories.has(c.id)
                return (
                  <button
                    key={c.id}
                    onClick={() => toggleCategory(c.id)}
                    type="button"
                    style={{
                      padding: '6px 10px', borderRadius: 6, fontSize: 11.5, cursor: 'pointer',
                      background: on ? 'var(--accent-soft)' : 'var(--bg-0)',
                      border: '1px solid ' + (on ? 'oklch(0.78 0.14 200 / 0.4)' : 'var(--border)'),
                      color: on ? 'var(--accent)' : 'var(--text-1)',
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                      transition: 'background 100ms ease, border-color 100ms ease, color 100ms ease',
                    }}
                  >
                    {on && <Check size={11} />}
                    {c.label}
                    <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)' }}>{c.count}</span>
                  </button>
                )
              })}
            </div>
          </div>

          {/* 6. Legal notice */}
          <div style={{
            background: 'var(--bg-0)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            padding: 10,
            fontSize: 11.5,
            color: 'var(--text-2)',
            display: 'flex',
            gap: 8,
            alignItems: 'flex-start',
          }}>
            <AlertTriangle size={13} color="var(--sev-medium)" style={{ marginTop: 1, flexShrink: 0 }} />
            <div>
              <strong style={{ color: 'var(--text-1)' }}>Legal notice.</strong>{' '}
              Only scan networks and systems you own or have explicit written permission to test.
              Unauthorized scanning is illegal.
            </div>
          </div>
        </div>

        {/* Modal footer */}
        <div style={{
          padding: 14,
          borderTop: '1px solid var(--border)',
          display: 'flex',
          gap: 8,
          justifyContent: 'flex-end',
        }}>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn">
            <FileText size={12} /> Save as draft
          </button>
          <button
            className="btn btn-primary"
            onClick={handleCreate}
            disabled={!canSubmit}
          >
            <Play size={11} /> Create &amp; Launch
          </button>
        </div>
      </div>
    </div>
  )
}

/* ─────────────────────────────────────────────────────────────────
   Credential card
   ───────────────────────────────────────────────────────────────── */
function CredentialCard({
  cred,
  onChange,
  onRemove,
}: {
  cred: InlineCredential
  onChange: (patch: Partial<InlineCredential>) => void
  onRemove: () => void
}) {
  const inputStyle: React.CSSProperties = {
    flex: 1, background: 'var(--bg-0)', border: '1px solid var(--border)',
    borderRadius: 4, padding: '5px 8px', fontSize: 12, color: 'var(--text-0)',
    outline: 'none', minWidth: 0,
  }
  const labelStyle: React.CSSProperties = {
    fontSize: 10, color: 'var(--text-3)', textTransform: 'uppercase',
    letterSpacing: '0.06em', fontWeight: 600, flexShrink: 0,
  }
  const selectStyle: React.CSSProperties = {
    ...inputStyle, flex: 'none',
  }

  return (
    <div style={{
      border: '1px solid var(--border)',
      borderRadius: 6,
      padding: 10,
      marginBottom: 8,
      background: 'var(--bg-0)',
      display: 'flex',
      flexDirection: 'column',
      gap: 7,
    }}>
      {/* Row 1: Role + Type */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={labelStyle}>Role:</span>
        <select
          value={cred.role}
          onChange={e => onChange({ role: e.target.value as InlineCredential['role'] })}
          style={selectStyle}
        >
          {(Object.entries(ROLE_LABELS) as [InlineCredential['role'], string][]).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
        <span style={labelStyle}>Type:</span>
        <select
          value={cred.type}
          onChange={e => onChange({ type: e.target.value as InlineCredential['type'] })}
          style={selectStyle}
        >
          {(Object.entries(TYPE_LABELS) as [InlineCredential['type'], string][]).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>
      </div>

      {/* Row 2: Domain */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={labelStyle}>Domain:</span>
        <input
          style={inputStyle}
          value={cred.domain}
          onChange={e => onChange({ domain: e.target.value })}
          placeholder="e.g. ACME.LOCAL"
        />
      </div>

      {/* Row 3: Username */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={labelStyle}>Username:</span>
        <input
          style={inputStyle}
          value={cred.username}
          onChange={e => onChange({ username: e.target.value })}
        />
      </div>

      {/* Row 4: Password */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <span style={labelStyle}>Password:</span>
        <input
          type="password"
          style={inputStyle}
          value={cred.password}
          onChange={e => onChange({ password: e.target.value })}
        />
      </div>

      {/* Row 5: Save to vault + Remove */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 11.5, color: 'var(--text-1)' }}>
          <input
            type="checkbox"
            checked={cred.saveToVault}
            onChange={e => onChange({ saveToVault: e.target.checked })}
            style={{ accentColor: 'var(--accent)', width: 13, height: 13 }}
          />
          Save to credential vault
        </label>
        {cred.saveToVault && (
          <>
            <span style={labelStyle}>Name:</span>
            <input
              style={{ ...inputStyle, maxWidth: 140 }}
              value={cred.vaultName}
              onChange={e => onChange({ vaultName: e.target.value })}
              placeholder="Vault entry name"
            />
          </>
        )}
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={onRemove}
          style={{ marginLeft: 'auto', color: 'var(--sev-high)' }}
        >
          Remove
        </button>
      </div>
    </div>
  )
}
