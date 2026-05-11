import { useState, useMemo, type Dispatch, type ReactNode, type SetStateAction } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Activity, Scan, Plus, Download, Search,
  Terminal, Play, StopCircle, GitCompare, Trash2,
  Radar, Globe, Zap, SlidersHorizontal, RotateCcw,
  X, FileText, AlertTriangle, Check, Pencil,
} from 'lucide-react'
import { scansApi, type ScanCreate, type ScanCredentialIn } from '@/api/scans'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { wordlistsApi } from '@/api/wordlists'
import { ALL_CATEGORIES, PORT_RANGES, configToJson, defaultProfileConfig, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
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

function parseProfileJson(raw?: string | null): Record<string, unknown> | null {
  if (!raw) return null
  try {
    return JSON.parse(raw) as Record<string, unknown>
  } catch {
    return null
  }
}

/* ── Design reference template cards ─────────────────────────────── */
const DESIGN_TEMPLATES = [
  { id: 'external-attack-surface', name: 'External Attack Surface', desc: 'Domains · DNS · subdomains · web exposure', icon: 'globe' },
  { id: 'web-application-scan', name: 'Web Application Scan', desc: 'HTTP/HTTPS · headers · screenshots · Nuclei', icon: 'radar' },
  { id: 'external-vulnerability-scan', name: 'External Vulnerability Scan', desc: 'Internet-facing hosts · TCP discovery', icon: 'zap' },
  { id: 'internal-network-scan', name: 'Internal Network Scan', desc: 'CIDR · validated discovery · services', icon: 'radar' },
  { id: 'credentialed-scan', name: 'Credentialed Scan', desc: 'Internal scan prepared for supplied credentials', icon: 'sliders' },
  { id: 'active-directory-internal-audit', name: 'Active Directory / Internal Audit', desc: 'Windows and internal service audit', icon: 'radar' },
  { id: 'tls-crypto-audit', name: 'TLS / Crypto Audit', desc: 'Certificates · protocols · ciphers', icon: 'globe' },
  { id: 'advanced-scan', name: 'Advanced Scan', desc: 'No preset restrictions · full control', icon: 'sliders' },
]

const SAFETY_HELP: Record<ProfileConfig['safety_level'], { title: string; desc: string }> = {
  safe: {
    title: 'Safe',
    desc: 'Low-risk checks only. Skips brute force, default credential attempts, and disruptive probes.',
  },
  balanced: {
    title: 'Balanced',
    desc: 'Default active scanning. Runs normal vulnerability checks while avoiding obviously risky tests.',
  },
  aggressive: {
    title: 'Aggressive',
    desc: 'Intrusive checks allowed. Permits heavier fuzzing, default credential attempts, and brute force only when those capabilities are enabled.',
  },
}

const PERFORMANCE_HELP: Record<ProfileConfig['performance_profile'], { title: string; desc: string }> = {
  conservative: {
    title: 'Conservative',
    desc: 'Lower concurrency and rates, longer timeouts. Better for fragile networks, VPN, Tailscale, or small devices.',
  },
  normal: {
    title: 'Normal',
    desc: 'Balanced throughput and reliability. Good default for most internal or external scans.',
  },
  fast: {
    title: 'Fast',
    desc: 'Higher concurrency and shorter timeouts. Finishes sooner but may miss slow services or create more load.',
  },
  custom: {
    title: 'Custom',
    desc: 'Use the advanced numeric settings below instead of a preset.',
  },
}

function TemplateIcon({ name, size = 14 }: { name: string; size?: number }) {
  if (name === 'zap')     return <Zap size={size} />
  if (name === 'radar')   return <Radar size={size} />
  if (name === 'globe')   return <Globe size={size} />
  if (name === 'sliders') return <SlidersHorizontal size={size} />
  return <Scan size={size} />
}

type TargetPreviewType = 'ip' | 'cidr' | 'range' | 'hostname' | 'domain' | 'invalid'

interface TargetPreviewLine {
  input: string
  type: TargetPreviewType
  label: string
  count: number | null
  warning?: string
}

interface TargetPreview {
  lines: TargetPreviewLine[]
  totalKnownHosts: number
  hasUnknownCount: boolean
  warnings: string[]
}

function ipv4ToNumber(value: string): number | null {
  const parts = value.split('.')
  if (parts.length !== 4) return null
  let out = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const n = Number(part)
    if (n < 0 || n > 255) return null
    out = (out * 256) + n
  }
  return out
}

function classifyTargetInput(input: string, configured: ProfileConfig['target_type']): TargetPreviewLine {
  const value = input.trim()
  if (!value) return { input, type: 'invalid', label: 'Empty', count: 0 }
  if (configured !== 'auto') {
    if (configured === 'domain') return { input: value, type: 'domain', label: 'Domain seed', count: null, warning: 'DNS/subdomain enumeration can add more hosts after launch.' }
    if (configured === 'hostname') {
      return /^[a-zA-Z0-9.-]{1,253}$/.test(value)
        ? { input: value, type: 'hostname', label: 'Hostname', count: 1 }
        : { input: value, type: 'invalid', label: 'Invalid hostname', count: 0, warning: 'Hostname can only contain letters, numbers, dots, and hyphens.' }
    }
    if (configured === 'ip') {
      return ipv4ToNumber(value) !== null
        ? { input: value, type: 'ip', label: 'Exact IP host', count: 1 }
        : { input: value, type: 'invalid', label: 'Invalid IP address', count: 0, warning: 'IP address must look like 10.0.0.221.' }
    }
    if (configured === 'cidr') return cidrPreview(value)
    if (configured === 'range') return rangePreview(value)
  }
  if (value.includes('/')) return cidrPreview(value)
  if (/^[\d.]+-[\d.]+$/.test(value)) return rangePreview(value)
  if (ipv4ToNumber(value) !== null) return { input: value, type: 'ip', label: 'Exact IP host', count: 1 }
  if (/^[a-zA-Z0-9.-]{1,253}$/.test(value)) {
    return value.includes('.')
      ? { input: value, type: 'domain', label: 'Domain/hostname', count: null, warning: 'Choose Domain explicitly for subdomain enumeration defaults.' }
      : { input: value, type: 'hostname', label: 'Hostname', count: 1 }
  }
  return { input: value, type: 'invalid', label: 'Invalid target syntax', count: 0, warning: 'Use an IP, CIDR, IP range, hostname, or domain.' }
}

function cidrPreview(value: string): TargetPreviewLine {
  const [ip, prefixRaw] = value.split('/')
  const ipNum = ipv4ToNumber(ip)
  const prefix = Number(prefixRaw)
  if (ipNum === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return { input: value, type: 'invalid', label: 'Invalid CIDR', count: 0, warning: 'CIDR must look like 10.0.0.0/24.' }
  }
  const addresses = 2 ** (32 - prefix)
  const usable = prefix >= 31 ? addresses : Math.max(0, addresses - 2)
  return {
    input: value,
    type: 'cidr',
    label: 'CIDR subnet',
    count: usable,
    warning: usable > 65536 ? 'Very large target set. Backend rejects CIDR blocks larger than /16.' : undefined,
  }
}

function rangePreview(value: string): TargetPreviewLine {
  const match = value.match(/^([\d.]+)-([\d.]+)$/)
  if (!match) return { input: value, type: 'invalid', label: 'Invalid IP range', count: 0, warning: 'Range must look like 10.0.0.50-80 or 10.0.0.50-10.0.0.80.' }
  const start = match[1]
  let end = match[2]
  if (!end.includes('.')) end = `${start.split('.').slice(0, 3).join('.')}.${end}`
  const startNum = ipv4ToNumber(start)
  const endNum = ipv4ToNumber(end)
  if (startNum === null || endNum === null || endNum < startNum) {
    return { input: value, type: 'invalid', label: 'Invalid IP range', count: 0, warning: 'Range end must be a valid IP after the start.' }
  }
  return { input: value, type: 'range', label: 'Explicit IP range', count: endNum - startNum + 1 }
}

function buildTargetPreview(targets: string, configured: ProfileConfig['target_type']): TargetPreview {
  const lines = targets.split('\n').map(t => t.trim()).filter(Boolean).map(t => classifyTargetInput(t, configured))
  const warnings = lines.map(l => l.warning).filter(Boolean) as string[]
  return {
    lines,
    totalKnownHosts: lines.reduce((sum, line) => sum + (line.count ?? 0), 0),
    hasUnknownCount: lines.some(line => line.count === null),
    warnings,
  }
}

/* ─────────────────────────────────────────────────────────────────
   Main page component
   ───────────────────────────────────────────────────────────────── */
export default function Scans({ onOpenScan }: Props) {
  const qc = useQueryClient()
  const [showForm, setShowForm]       = useState(false)
  const [editScanId, setEditScanId]   = useState<string | null>(null)
  const [rerunScan, setRerunScan]     = useState<{ id: string; name: string; targets?: string[]; profile_json?: string | null } | null>(null)
  const [deltaScan, setDeltaScan]     = useState<{ id: string; name: string } | null>(null)
  const [page, setPage]               = useState(0)
  const [filter, setFilter]           = useState<FilterStatus>('all')
  const [search, setSearch]           = useState('')
  const [lastUpdated]                 = useState<Date>(new Date())

  const [mutError, setMutError] = useState<string | null>(null)
  const _onErr = (e: unknown) => setMutError(e instanceof Error ? e.message : String(e))

  const { data: scans = [] } = useQuery({
    queryKey: ['scans', page],
    queryFn: () => scansApi.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE }),
    refetchInterval: (query) =>
      query.state.data?.some((s: { status: string }) => s.status === 'running' || s.status === 'pending')
        ? 3000
        : false,
  })

  const createMut = useMutation({
    mutationFn: (body: ScanCreate) => scansApi.create(body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); setShowForm(false) },
    onError: _onErr,
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: ScanCreate }) =>
      scansApi.update(id, body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); setEditScanId(null) },
    onError: _onErr,
  })
  const launchMut = useMutation({
    mutationFn: (id: string) => scansApi.launch(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: _onErr,
  })
  const cancelMut = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: _onErr,
  })
  const deleteMut = useMutation({
    mutationFn: (id: string) => scansApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: _onErr,
  })
  const rerunMut = useMutation({
    mutationFn: (id: string) => scansApi.rerun(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
    onError: _onErr,
  })
  const cloneMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body?: ScanCreate }) =>
      body ? scansApi.create(body) : scansApi.clone(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); setRerunScan(null); setShowForm(false) },
    onError: _onErr,
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
    <div className="page-pad" style={{ maxWidth: 1480, margin: '0 auto' }}>
      {mutError && (
        <div style={{ background: 'var(--sev-high)', color: '#fff', borderRadius: 6, padding: '8px 14px', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
          <AlertTriangle size={14} />
          <span style={{ flex: 1 }}>{mutError}</span>
          <button onClick={() => setMutError(null)} style={{ background: 'none', border: 'none', color: '#fff', cursor: 'pointer', padding: 0 }}><X size={14} /></button>
        </div>
      )}

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
          onSaveAsDraft={body => createMut.mutate(body)}
          loading={createMut.isPending}
        />
      )}

      {/* ── Edit pending scan modal ── */}
      {editScanId && (() => {
        const s = scans.find(x => x.id === editScanId)
        if (!s) return null
        return (
          <NewScanModal
            key={editScanId}
            editMode
            initialScan={s}
            onClose={() => setEditScanId(null)}
            onSaveAsDraft={body => updateMut.mutate({ id: editScanId, body })}
            loading={updateMut.isPending}
          />
        )
      })()}

      {/* ── Rerun / Edit & Rerun modal ── */}
      {rerunScan && (
        <NewScanModal
          key={`rerun-${rerunScan.id}`}
          editMode
          initialScan={rerunScan}
          onClose={() => setRerunScan(null)}
          onSaveAsDraft={body => cloneMut.mutate({ id: rerunScan.id, body })}
          loading={cloneMut.isPending}
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
          <button className="btn" onClick={() => {
            const csvQ = (v: unknown) => {
              const s = String(v ?? '')
              const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s
              return `"${safe.replace(/"/g, '""')}"`
            }
            const csv = ['Name,Status,Hosts,Critical,High,Medium,Low,Created',
              ...filtered.map(s => [s.name, s.status, `${s.hosts_up}/${s.hosts_total}`,
                s.findings_critical, s.findings_high, s.findings_medium, s.findings_low,
                new Date(s.created_at).toISOString()].map(csvQ).join(','))
            ].join('\n')
            const a = document.createElement('a')
            a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
            a.download = 'scans.csv'; a.click()
          }}>
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
              <th style={{ width: 100, position: 'sticky', right: 0, background: 'var(--bg-1)', zIndex: 2 }}></th>
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

                {/* Status pill + progress meter / error */}
                <td>
                  <StatusPill status={s.status} />
                  {s.status === 'running' && (
                    <div style={{ width: 80, marginTop: 4 }}>
                      <Meter value={s.progress ?? 0} color="var(--accent-2)" />
                    </div>
                  )}
                  {s.status === 'failed' && s.error_message && (
                    <div className="mono" style={{ fontSize: 10, color: 'var(--sev-high)', marginTop: 3, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.error_message}>
                      {s.error_message}
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

                {/* Actions — sticky right so always visible on narrow screens */}
                <td onClick={e => e.stopPropagation()}
                  style={{ position: 'sticky', right: 0, background: 'var(--bg-1)', zIndex: 1 }}>
                  <div style={{ display: 'flex', gap: 2 }}>
                    <button
                      className="btn btn-ghost btn-icon"
                      title="Open console"
                      onClick={() => onOpenScan?.(s.id)}
                    >
                      <Terminal size={13} />
                    </button>

                    {s.status === 'pending' && (
                      <>
                        <button
                          className="btn btn-ghost btn-icon"
                          title="Edit scan settings"
                          onClick={() => setEditScanId(s.id)}
                          style={{ color: 'var(--accent)' }}
                        >
                          <Pencil size={11} />
                        </button>
                        <button
                          className="btn btn-ghost btn-icon"
                          title="Launch"
                          onClick={() => launchMut.mutate(s.id)}
                          style={{ color: 'var(--ok)' }}
                        >
                          <Play size={11} />
                        </button>
                      </>
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

                    {(s.status === 'completed' || s.status === 'failed' || s.status === 'cancelled') && (
                      <>
                        <button
                          className="btn btn-ghost btn-icon"
                          title="Rerun with same config"
                          onClick={() => { if (confirm('Rerun this scan with the same config?')) rerunMut.mutate(s.id) }}
                          style={{ color: 'var(--ok)' }}
                        >
                          <RotateCcw size={13} />
                        </button>
                        <button
                          className="btn btn-ghost btn-icon"
                          title="Edit config & rerun"
                          onClick={() => setRerunScan({ id: s.id, name: s.name, targets: s.targets, profile_json: s.profile_json })}
                          style={{ color: 'var(--accent)' }}
                        >
                          <Pencil size={11} />
                        </button>
                        <button
                          className="btn btn-ghost btn-icon"
                          title="Compare"
                          onClick={() => setDeltaScan({ id: s.id, name: s.name })}
                        >
                          <GitCompare size={13} />
                        </button>
                      </>
                    )}

                    <button
                      className="btn btn-ghost btn-icon"
                      title="Delete"
                      onClick={() => { if (confirm('Delete this scan?')) deleteMut.mutate(s.id) }}
                      style={{ marginLeft: 4, paddingLeft: 8, borderLeft: '1px solid var(--border)' }}
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
  onSaveAsDraft,
  loading,
  editMode = false,
  initialScan,
}: {
  onClose: () => void
  onSaveAsDraft: (body: ScanCreate) => void
  loading: boolean
  editMode?: boolean
  initialScan?: { id: string; name: string; targets?: string[]; profile_json?: string | null }
}) {
  const [step, setStep] = useState(1)
  const [selectedDesignTemplate, setSelectedDesignTemplate] = useState('advanced-scan')
  const [selectedApiTemplate, setSelectedApiTemplate]       = useState<ScanTemplate | null>(null)
  const [baseProfileJson, setBaseProfileJson]               = useState<Record<string, unknown>>({})
  const [name, setName]       = useState(initialScan?.name ?? '')
  const [targets, setTargets] = useState((initialScan?.targets ?? []).join('\n'))
  const [credentials, setCredentials] = useState<InlineCredential[]>([])
  const [showAdvanced, setShowAdvanced] = useState(false)

  const [profileConfig, setProfileConfig] = useState<ProfileConfig>(
    initialScan?.profile_json ? jsonToConfig(parseProfileJson(initialScan.profile_json)) : defaultProfileConfig()
  )
  const [bruteForce, setBruteForce] = useState({
    enabled: false,
    credential_wordlist_id: '',
    username_wordlist_id: '',
    password_wordlist_id: '',
    max_concurrent: 3,
    delay_ms: 500,
    stop_on_success: false,
  })

  const { data: apiTemplates = [] } = useQuery({
    queryKey: ['templates'],
    queryFn: templatesApi.list,
  })
  const systemTemplates = apiTemplates.filter(t => t.is_system)

  const { data: wordlists = [] } = useQuery({ queryKey: ['wordlists'], queryFn: wordlistsApi.list })
  const credWordlists = wordlists.filter(w => w.type === 'credentials')
  const userWordlists = wordlists.filter(w => w.type === 'usernames')
  const passWordlists = wordlists.filter(w => w.type === 'passwords')
  const targetPreview = useMemo(() => buildTargetPreview(targets, profileConfig.target_type), [targets, profileConfig.target_type])

  function applyApiTemplate(t: ScanTemplate) {
    setSelectedApiTemplate(t)
    setSelectedDesignTemplate(t.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''))
    setBaseProfileJson(t.profile_json ?? {})
    setProfileConfig(jsonToConfig(t.profile_json))
    if (!name) setName(t.name)
  }

  function applyFallbackTemplate(t: typeof DESIGN_TEMPLATES[number]) {
    setSelectedApiTemplate(null)
    setSelectedDesignTemplate(t.id)
    const external = t.id.includes('external') || t.id.includes('web') || t.id.includes('tls')
    const domain = t.id === 'external-attack-surface'
    const profile = defaultProfileConfig({
      scan_context: t.id.includes('internal') || t.id.includes('credentialed') ? 'internal' : external ? 'external' : 'custom',
      target_type: domain ? 'domain' : 'auto',
      safety_level: t.id.includes('advanced') ? 'balanced' : 'safe',
      depth_level: t.id.includes('credentialed') || t.id.includes('active-directory') ? 'deep' : 'balanced',
      performance_profile: t.id.includes('tls') ? 'normal' : 'normal',
      port_range: domain || t.id.includes('web') ? '80,443,8080,8443,8000,8888,3000,5000,9000' : t.id.includes('tls') ? '443,8443,9443,10443,993,995,465,636,3389' : 'top-1000',
      categories: domain ? ['network', 'web', 'ssl_tls', 'nuclei'] : t.id.includes('tls') ? ['ssl_tls', 'web'] : ALL_CATEGORIES.map(x => x.id),
      discovery: external ? { icmp: false, tcp: true, arp: false, udp: false, retries: 1, strategy: 'fast', assume_up: false } : undefined,
      enumeration: {
        service_detection: true,
        http_probing: true,
        tls_checks: true,
        security_headers: true,
        screenshots: !t.id.includes('active-directory') && !t.id.includes('tls'),
        nuclei: external,
        directory_enum: t.id.includes('web'),
        subdomain_enum: domain,
        dns_recon: domain,
      },
    })
    setBaseProfileJson({})
    setProfileConfig(profile)
    if (!name) setName(t.name)
  }

  function toggleCategory(id: string) {
    setProfileConfig(p => ({
      ...p,
      categories: p.categories.includes(id)
        ? p.categories.filter(cat => cat !== id)
        : [...p.categories, id],
    }))
  }

  function setTargetType(target_type: ProfileConfig['target_type']) {
    const isDomain = target_type === 'domain'
    setProfileConfig(p => ({
      ...p,
      target_type,
      scan_context: isDomain && p.scan_context === 'internal' ? 'external' : p.scan_context,
      discovery: isDomain
        ? { ...p.discovery, icmp: false, tcp: true, arp: false, strategy: 'fast' }
        : p.discovery,
      enumeration: {
        ...p.enumeration,
        subdomain_enum: isDomain ? true : p.enumeration.subdomain_enum,
        dns_recon: isDomain ? true : p.enumeration.dns_recon,
      },
      categories: isDomain
        ? Array.from(new Set([...p.categories, 'network', 'web', 'ssl_tls']))
        : p.categories,
    }))
  }

  function applyDepth(depth_level: ProfileConfig['depth_level']) {
    setProfileConfig(p => ({
      ...p,
      depth_level,
      port_range: depth_level === 'light'
        ? 'top-1000'
        : depth_level === 'deep'
          ? (p.scan_context === 'external' ? '80,443,8080,8443,8000,8001,8888,3000,5000,9000,9443,10443,32400' : 'top-10000')
          : p.port_range,
      enumeration: {
        ...p.enumeration,
        directory_enum: depth_level === 'deep' ? true : depth_level === 'light' ? false : p.enumeration.directory_enum,
        nuclei: depth_level === 'light' ? false : p.enumeration.nuclei,
      },
      performance: {
        ...p.performance,
        timeout: depth_level === 'deep' ? 120 : depth_level === 'light' ? 45 : p.performance.timeout,
      },
    }))
  }

  function applyPerformance(performance_profile: ProfileConfig['performance_profile']) {
    const presets = {
      conservative: { max_concurrent_hosts: 8, max_concurrent_plugins: 10, timeout: 90, masscan_rate: 5000, nuclei_rate: 15 },
      normal: { max_concurrent_hosts: 20, max_concurrent_plugins: 20, timeout: 60, masscan_rate: 10000, nuclei_rate: 25 },
      fast: { max_concurrent_hosts: 40, max_concurrent_plugins: 30, timeout: 45, masscan_rate: 25000, nuclei_rate: 50 },
      custom: null,
    } as const
    setProfileConfig(p => ({
      ...p,
      performance_profile,
      performance: presets[performance_profile]
        ? { ...p.performance, ...presets[performance_profile] }
        : p.performance,
    }))
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

  function buildPayload(): ScanCreate {
    const credPayload: ScanCredentialIn[] = credentials.map(c => ({
      role: c.role,
      type: c.type,
      username: c.username || undefined,
      domain: c.domain || undefined,
      password: c.password || undefined,
      save_to_vault: c.saveToVault,
      vault_name: c.vaultName || undefined,
    }))
    const pj: Record<string, unknown> = { ...baseProfileJson, ...configToJson(profileConfig) }
    if (bruteForce.enabled) {
      pj.brute_force = {
        enabled: true,
        credential_wordlist_id: bruteForce.credential_wordlist_id || null,
        username_wordlist_id: bruteForce.username_wordlist_id || null,
        password_wordlist_id: bruteForce.password_wordlist_id || null,
        max_concurrent: bruteForce.max_concurrent,
        delay_ms: bruteForce.delay_ms,
        stop_on_success: bruteForce.stop_on_success,
      }
    }
    return {
      name,
      targets: targets.split('\n').map(t => t.trim()).filter(Boolean),
      profile: 'custom',
      profile_json: JSON.stringify(pj),
      credentials: credPayload.length > 0 ? credPayload : undefined,
    }
  }

  const canSubmit = Boolean(name.trim() && targets.trim() && !loading && targetPreview.lines.every(line => line.type !== 'invalid'))

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
          <span style={{ fontSize: 13, fontWeight: 600 }}>{editMode ? 'Edit Scan' : 'New Scan'}</span>
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
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
            {['Template', 'Context', 'Targets', 'Capabilities', 'Review'].map((label, idx) => (
              <button
                key={label}
                type="button"
                onClick={() => setStep(idx + 1)}
                className={`btn btn-sm ${step === idx + 1 ? 'btn-primary' : 'btn-ghost'}`}
              >
                {idx + 1}. {label}
              </button>
            ))}
          </div>

          {step === 1 && (
            <div>
              <div className="label">Start from template</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                {(systemTemplates.length > 0 ? systemTemplates : DESIGN_TEMPLATES).map(t => {
                  const isApi = 'profile_json' in t
                  const active = isApi
                    ? selectedApiTemplate?.id === (t as ScanTemplate).id
                    : selectedDesignTemplate === (t as typeof DESIGN_TEMPLATES[number]).id
                  return (
                    <button
                      key={isApi ? (t as ScanTemplate).id : (t as typeof DESIGN_TEMPLATES[number]).id}
                      type="button"
                      onClick={() => isApi ? applyApiTemplate(t as ScanTemplate) : applyFallbackTemplate(t as typeof DESIGN_TEMPLATES[number])}
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
                        {isApi ? <Scan size={14} /> : <TemplateIcon name={(t as typeof DESIGN_TEMPLATES[number]).icon} size={14} />}
                      </span>
                      <div>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}>{t.name}</div>
                        <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 2 }}>
                          {isApi ? ((t as ScanTemplate).description ?? 'Capability preset') : (t as typeof DESIGN_TEMPLATES[number]).desc}
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          )}

          {step === 2 && (
            <>
              <div>
                <label className="label">Scan name</label>
                <input className="input" value={name} onChange={e => setName(e.target.value)} placeholder="Internal Network - Q2 2026" />
              </div>
              <div>
                <label className="label">Scan context</label>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {[
                    ['internal', 'Internal', 'Validated discovery, ARP/ICMP options, internal protocols.'],
                    ['external', 'External', 'TCP discovery, no ICMP reliance, web and DNS defaults.'],
                    ['custom', 'Custom', 'Neutral defaults with every capability editable.'],
                  ].map(([value, label, desc]) => (
                    <button
                      key={value}
                      type="button"
                      onClick={() => setProfileConfig(p => ({ ...p, scan_context: value as ProfileConfig['scan_context'] }))}
                      style={{
                        padding: 12, borderRadius: 8, textAlign: 'left', cursor: 'pointer',
                        background: profileConfig.scan_context === value ? 'var(--accent-soft)' : 'var(--bg-0)',
                        border: '1px solid ' + (profileConfig.scan_context === value ? 'var(--accent)' : 'var(--border)'),
                      }}
                    >
                      <div style={{ fontSize: 12.5, fontWeight: 600 }}>{label}</div>
                      <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 3 }}>{desc}</div>
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}

          {step === 3 && (
            <>
              <div>
                <label className="label">Target handling</label>
                <select className="select-field" value={profileConfig.target_type} onChange={e => setTargetType(e.target.value as ProfileConfig['target_type'])}>
                  <option value="auto">Auto detect from each line</option>
                  <option value="domain">Domain - DNS and subdomain workflow</option>
                  <option value="hostname">Hostname - resolve one named host</option>
                  <option value="ip">IP address - one or more exact hosts</option>
                  <option value="cidr">CIDR subnet - example 10.0.0.0/24</option>
                  <option value="range">IP range - example 10.0.0.50-80</option>
                </select>
                <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', marginTop: 5 }}>
                  Auto detects each line: 10.0.0.221 scans that host, 10.0.0.0/24 expands the subnet, and 10.0.0.50-80 scans that explicit range.
                  Choose Domain when you want DNS and subdomain enumeration.
                </p>
              </div>
              <div>
                <label className="label">Targets <span style={{ color: 'var(--text-3)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>- one per line</span></label>
                <textarea className="textarea" rows={4} value={targets} onChange={e => setTargets(e.target.value)} placeholder={'10.42.0.0/20\nexample.com'} />
              </div>
              <TargetPreviewPanel preview={targetPreview} />
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                  <div>
                    <label className="label" style={{ margin: 0 }}>Known credentials</label>
                    <p className="mono" style={{ margin: '4px 0 0', fontSize: 10.5, color: 'var(--text-3)' }}>
                      Used for authenticated checks. This is different from brute force wordlists.
                    </p>
                  </div>
                  <button className="btn btn-ghost btn-sm" onClick={addCredential} type="button"><Plus size={11} /> Add Credential</button>
                </div>
                {credentials.map(cred => (
                  <CredentialCard key={cred.id} cred={cred} onChange={patch => updateCredential(cred.id, patch)} onRemove={() => removeCredential(cred.id)} />
                ))}
              </div>
            </>
          )}

          {step === 4 && (
            <>
              <CapabilityGroup title="Host Discovery">
                <Toggle label="ICMP" checked={profileConfig.discovery.icmp} onChange={icmp => setProfileConfig(p => ({ ...p, discovery: { ...p.discovery, icmp } }))} />
                <Toggle label="TCP probes" checked={profileConfig.discovery.tcp} onChange={tcp => setProfileConfig(p => ({ ...p, discovery: { ...p.discovery, tcp } }))} />
                <Toggle label="ARP (local L2 only / limited support)" checked={profileConfig.discovery.arp} onChange={arp => setProfileConfig(p => ({ ...p, discovery: { ...p.discovery, arp } }))} />
                <div style={{ marginTop: 4 }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', marginBottom: 4, display: 'block' }}>Discovery mode:</span>
                  <select
                    className="select-field"
                    value={profileConfig.discovery.mode}
                    onChange={e => {
                      const mode = e.target.value as ProfileConfig['discovery']['mode']
                      setProfileConfig(p => ({
                        ...p,
                        discovery: {
                          ...p.discovery,
                          mode,
                          ...(mode === 'skip' ? { assume_up: true } : {}),
                        },
                        port_scanning: {
                          ...p.port_scanning,
                          ...(mode === 'skip' ? { firewall_strategy: 'skip_ping' as const } : {}),
                        },
                      }))
                    }}
                  >
                    <option value="fast">Fast (ICMP + TCP probe)</option>
                    <option value="aggressive">Aggressive (SYN + ACK + UDP ping)</option>
                    <option value="skip">Skip (assume hosts are up)</option>
                  </select>
                </div>
                <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', margin: 0 }}>
                  Aggressive mode adds SYN + ACK + UDP nmap probes for better detection. Skip mode bypasses discovery and scans all targets with -Pn.
                </p>
              </CapabilityGroup>

              <CapabilityGroup title="Ports">
                <select className="select-field" value={profileConfig.port_range} onChange={e => setProfileConfig(p => ({ ...p, port_range: e.target.value }))}>
                  {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
                </select>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
                  <span className="mono" style={{ fontSize: 11, color: 'var(--text-3)', width: '100%', marginBottom: 2 }}>Scan protocols:</span>
                  {(['tcp_connect', 'syn', 'udp'] as const).map(scanner => (
                    <Toggle
                      key={scanner}
                      label={scanner === 'tcp_connect' ? 'TCP connect' : scanner === 'syn' ? 'SYN / masscan' : 'UDP'}
                      checked={profileConfig.port_scanning.scanners.includes(scanner)}
                      onChange={checked => setProfileConfig(p => ({
                        ...p,
                        port_scanning: {
                          ...p.port_scanning,
                          scanners: checked
                            ? [...p.port_scanning.scanners, scanner]
                            : p.port_scanning.scanners.filter(s => s !== scanner),
                        },
                      }))}
                    />
                  ))}
                </div>
              </CapabilityGroup>

              <CapabilityGroup title="Enumeration">
                <Segmented value={profileConfig.depth_level} options={['light', 'balanced', 'deep']} onChange={depth_level => applyDepth(depth_level as ProfileConfig['depth_level'])} />
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {ALL_CATEGORIES.map(cat => {
                    const on = profileConfig.categories.includes(cat.id)
                    return (
                      <button key={cat.id} type="button" onClick={() => toggleCategory(cat.id)}
                        style={{ padding: '6px 10px', borderRadius: 6, fontSize: 11.5, cursor: 'pointer', background: on ? 'var(--accent-soft)' : 'var(--bg-0)', border: '1px solid ' + (on ? 'var(--accent)' : 'var(--border)'), color: on ? 'var(--accent)' : 'var(--text-1)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        {on && <Check size={11} />}{cat.label}
                      </button>
                    )
                  })}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8 }}>
                  {[
                    ['service_detection', 'Service detection'],
                    ['http_probing', 'HTTP probing'],
                    ['tls_checks', 'TLS checks'],
                    ['security_headers', 'Security headers'],
                    ['screenshots', 'Screenshots'],
                    ['nuclei', 'Nuclei'],
                    ['directory_enum', 'Directory/file enum'],
                    ['subdomain_enum', 'Subdomain enum'],
                    ['dns_recon', 'DNS recon'],
                  ].map(([key, label]) => (
                    <Toggle key={key} label={label} checked={Boolean(profileConfig.enumeration[key as keyof ProfileConfig['enumeration']])} onChange={value => setProfileConfig(p => ({ ...p, enumeration: { ...p.enumeration, [key]: value } }))} />
                  ))}
                </div>
              </CapabilityGroup>

              <CapabilityGroup title="Safety">
                <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', margin: 0 }}>
                  Controls what ScanR is allowed to try against the target.
                </p>
                <Segmented value={profileConfig.safety_level} options={['safe', 'balanced', 'aggressive']} onChange={safety_level => setProfileConfig(p => ({ ...p, safety_level: safety_level as ProfileConfig['safety_level'] }))} />
                <PresetHelp selected={profileConfig.safety_level} items={SAFETY_HELP} />
              </CapabilityGroup>

              <CapabilityGroup title="Performance">
                <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', margin: 0 }}>
                  Controls how hard ScanR runs: concurrency, rates, and timeout pressure.
                </p>
                <Segmented value={profileConfig.performance_profile} options={['conservative', 'normal', 'fast', 'custom']} onChange={performance_profile => applyPerformance(performance_profile as ProfileConfig['performance_profile'])} />
                <PresetHelp selected={profileConfig.performance_profile} items={PERFORMANCE_HELP} />
                <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShowAdvanced(v => !v)}>
                  <SlidersHorizontal size={12} /> {showAdvanced ? 'Hide advanced' : 'Show advanced'}
                </button>
                {showAdvanced && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                    <NumberField label="Hosts" value={profileConfig.performance.max_concurrent_hosts} onChange={max_concurrent_hosts => setProfileConfig(p => ({ ...p, performance: { ...p.performance, max_concurrent_hosts } }))} />
                    <NumberField label="Plugins" value={profileConfig.performance.max_concurrent_plugins} onChange={max_concurrent_plugins => setProfileConfig(p => ({ ...p, performance: { ...p.performance, max_concurrent_plugins } }))} />
                    <NumberField label="Timeout" value={profileConfig.performance.timeout} onChange={timeout => setProfileConfig(p => ({ ...p, performance: { ...p.performance, timeout } }))} />
                    <NumberField label="Masscan rate" value={profileConfig.performance.masscan_rate} onChange={masscan_rate => setProfileConfig(p => ({ ...p, performance: { ...p.performance, masscan_rate } }))} />
                    <NumberField label="Nuclei rate" value={profileConfig.performance.nuclei_rate} onChange={nuclei_rate => setProfileConfig(p => ({ ...p, performance: { ...p.performance, nuclei_rate } }))} />
                    <NumberField label="Retries" value={profileConfig.discovery.retries} onChange={retries => setProfileConfig(p => ({ ...p, discovery: { ...p.discovery, retries } }))} />
                  </div>
                )}
              </CapabilityGroup>

              <BruteForceSection bruteForce={bruteForce} setBruteForce={setBruteForce} credWordlists={credWordlists} userWordlists={userWordlists} passWordlists={passWordlists} />
            </>
          )}

          {step === 5 && (
            <ReviewStep
              name={name}
              targets={targets}
              profileConfig={profileConfig}
              targetPreview={targetPreview}
              credentialCount={credentials.length}
              bruteForce={bruteForce}
            />
          )}

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
            <div><strong style={{ color: 'var(--text-1)' }}>Legal notice.</strong> Only scan systems you own or have permission to test.</div>
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
          {step > 1 && (
            <button className="btn" onClick={() => setStep(s => Math.max(1, s - 1))}>Back</button>
          )}
          {step < 5 && (
            <button className="btn btn-primary" onClick={() => setStep(s => Math.min(5, s + 1))}>Next</button>
          )}
          {step === 5 && (
            <button
              className="btn btn-primary"
              onClick={() => canSubmit && onSaveAsDraft(buildPayload())}
              disabled={!canSubmit}
            >
              <FileText size={12} /> {editMode ? 'Save changes' : 'Create pending scan'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function TargetPreviewPanel({ preview }: { preview: TargetPreview }) {
  if (preview.lines.length === 0) {
    return (
      <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 10, background: 'var(--bg-0)' }}>
        <div className="label" style={{ margin: 0 }}>Target preview</div>
        <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', margin: '6px 0 0' }}>
          Examples: 10.0.0.221 is one host, 10.0.0.0/24 is a subnet, 10.0.0.50-80 is an explicit range.
        </p>
      </div>
    )
  }
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 10, background: 'var(--bg-0)', display: 'grid', gap: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
        <div className="label" style={{ margin: 0 }}>Target preview</div>
        <div className="mono" style={{ fontSize: 10.5, color: 'var(--text-2)' }}>
          {preview.totalKnownHosts.toLocaleString()}{preview.hasUnknownCount ? '+' : ''} estimated host{preview.totalKnownHosts === 1 && !preview.hasUnknownCount ? '' : 's'}
        </div>
      </div>
      <div style={{ display: 'grid', gap: 5 }}>
        {preview.lines.map((line, idx) => (
          <div key={`${line.input}-${idx}`} className="mono" style={{ display: 'grid', gridTemplateColumns: '1fr 130px 86px', gap: 8, fontSize: 10.5, color: line.type === 'invalid' ? 'var(--sev-high)' : 'var(--text-2)' }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{line.input}</span>
            <span>{line.label}</span>
            <span style={{ textAlign: 'right' }}>{line.count === null ? 'DNS' : line.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
      {preview.warnings.length > 0 && (
        <div style={{ display: 'grid', gap: 4 }}>
          {Array.from(new Set(preview.warnings)).map(warning => (
            <div key={warning} className="mono" style={{ fontSize: 10.5, color: 'var(--sev-medium)' }}>{warning}</div>
          ))}
        </div>
      )}
    </div>
  )
}

function ReviewStep({
  name,
  targets,
  profileConfig,
  targetPreview,
  credentialCount,
  bruteForce,
}: {
  name: string
  targets: string
  profileConfig: ProfileConfig
  targetPreview: TargetPreview
  credentialCount: number
  bruteForce: {
    enabled: boolean
    credential_wordlist_id: string
    username_wordlist_id: string
    password_wordlist_id: string
    max_concurrent: number
    delay_ms: number
    stop_on_success: boolean
  }
}) {
  const portLabel = PORT_RANGES.find(p => p.value === profileConfig.port_range)?.label ?? profileConfig.port_range
  const targetLines = targets.split('\n').map(t => t.trim()).filter(Boolean)
  const warnings = [
    profileConfig.scan_context === 'internal' && profileConfig.port_range === 'top-1000'
      ? 'Top 1000 ports can miss internal web apps on high ports such as 30050, 30051, 8000-9999, or NodePort 30000-32767.'
      : null,
    profileConfig.discovery.arp
      ? 'ARP is shown as a local-network intent, but backend discovery support is limited.'
      : null,
    profileConfig.enumeration.screenshots
      ? 'Screenshots require Playwright/Chromium in the worker container; missing browser binaries will skip or fail screenshot capture.'
      : null,
    profileConfig.port_scanning.scanners.length === 1 && profileConfig.port_scanning.scanners[0] === 'tcp_connect'
      ? 'Masscan/SYN discovery is skipped because only TCP connect is selected.'
      : null,
    credentialCount === 0
      ? 'Authenticated checks will be skipped unless credentials are supplied.'
      : null,
    profileConfig.safety_level === 'aggressive' && !bruteForce.enabled
      ? 'Aggressive allows intrusive checks, but brute force wordlists are still disabled.'
      : null,
    ...targetPreview.warnings,
  ].filter(Boolean) as string[]

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <CapabilityGroup title="Review">
        <ReviewRow label="Name" value={name || 'Untitled scan'} />
        <ReviewRow label="Targets" value={`${targetLines.length} input line${targetLines.length === 1 ? '' : 's'} · ${targetPreview.totalKnownHosts.toLocaleString()}${targetPreview.hasUnknownCount ? '+' : ''} estimated host${targetPreview.totalKnownHosts === 1 && !targetPreview.hasUnknownCount ? '' : 's'}`} />
        <ReviewRow label="Context" value={profileConfig.scan_context} />
        <ReviewRow label="Target handling" value={profileConfig.target_type === 'auto' ? 'Auto detect per line' : profileConfig.target_type} />
        <ReviewRow label="Ports" value={portLabel} />
        <ReviewRow label="Discovery" value={[
          profileConfig.discovery.icmp ? 'ICMP' : null,
          profileConfig.discovery.tcp ? 'TCP probes' : null,
          profileConfig.discovery.arp ? 'ARP intent' : null,
          profileConfig.discovery.mode === 'aggressive' ? 'Aggressive mode' : profileConfig.discovery.mode === 'skip' ? 'Skip (assume up)' : 'Fast',
        ].filter(Boolean).join(', ') || 'No discovery probes'} />
        <ReviewRow label="Scan type" value={profileConfig.port_scanning.scanners.map(s => s === 'tcp_connect' ? 'TCP' : s === 'syn' ? 'SYN' : 'UDP').join(' + ') || 'TCP'} />
        <ReviewRow label="Safety / depth" value={`${profileConfig.safety_level} / ${profileConfig.depth_level}`} />
        <ReviewRow label="Performance" value={profileConfig.performance_profile} />
        <ReviewRow label="Credentials" value={`${credentialCount} known credential set${credentialCount === 1 ? '' : 's'} · brute force ${bruteForce.enabled ? 'enabled' : 'disabled'}`} />
      </CapabilityGroup>

      <TargetPreviewPanel preview={targetPreview} />

      <CapabilityGroup title="Execution Preview">
        <div style={{ display: 'grid', gap: 6 }}>
          {ALL_CATEGORIES.map(cat => {
            const enabled = profileConfig.categories.includes(cat.id)
            return (
              <div key={cat.id} className="mono" style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 8, fontSize: 10.5, color: enabled ? 'var(--text-1)' : 'var(--text-3)' }}>
                <span>{enabled ? 'Will run' : 'Disabled'}</span>
                <span>{cat.label} - {cat.desc}</span>
              </div>
            )
          })}
          <div className="mono" style={{ fontSize: 10.5, color: profileConfig.enumeration.subdomain_enum ? 'var(--text-1)' : 'var(--text-3)' }}>
            {profileConfig.enumeration.subdomain_enum ? 'Will run' : 'Skipped'} - Subdomain enumeration {profileConfig.enumeration.subdomain_enum ? 'enabled' : 'disabled'}
          </div>
          <div className="mono" style={{ fontSize: 10.5, color: bruteForce.enabled ? 'var(--sev-medium)' : 'var(--text-3)' }}>
            {bruteForce.enabled ? 'Will run' : 'Skipped'} - Brute force wordlist checks
          </div>
        </div>
      </CapabilityGroup>

      {warnings.length > 0 && (
        <CapabilityGroup title="Warnings / Skipped Reasons">
          {Array.from(new Set(warnings)).map(warning => (
            <div key={warning} className="mono" style={{ display: 'flex', gap: 7, fontSize: 10.5, color: 'var(--sev-medium)', lineHeight: 1.45 }}>
              <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
              <span>{warning}</span>
            </div>
          ))}
        </CapabilityGroup>
      )}
    </div>
  )
}

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 10, alignItems: 'start' }}>
      <span className="label" style={{ margin: 0 }}>{label}</span>
      <span className="mono" style={{ fontSize: 11, color: 'var(--text-1)', lineHeight: 1.4 }}>{value}</span>
    </div>
  )
}

function CapabilityGroup({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-0)', padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="label" style={{ margin: 0 }}>{title}</div>
      {children}
    </div>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer', fontSize: 12, color: 'var(--text-1)' }}>
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ accentColor: 'var(--accent)' }} />
      {label}
    </label>
  )
}

function Segmented({ value, options, onChange }: { value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {options.map(option => (
        <button key={option} type="button" className={`btn btn-sm ${value === option ? 'btn-primary' : 'btn-ghost'}`} onClick={() => onChange(option)}>
          {option}
        </button>
      ))}
    </div>
  )
}

function PresetHelp<T extends string>({
  selected,
  items,
}: {
  selected: T
  items: Record<T, { title: string; desc: string }>
}) {
  return (
    <div style={{ display: 'grid', gap: 6 }}>
      {(Object.entries(items) as [T, { title: string; desc: string }][]).map(([key, item]) => {
        const active = key === selected
        return (
          <div
            key={key}
            style={{
              display: 'grid',
              gridTemplateColumns: '110px 1fr',
              gap: 10,
              alignItems: 'start',
              padding: '6px 0',
              borderTop: '1px solid var(--border)',
              color: active ? 'var(--text-0)' : 'var(--text-2)',
            }}
          >
            <span
              style={{
                fontSize: 11.5,
                fontWeight: 600,
                color: active ? 'var(--accent)' : 'var(--text-2)',
                textTransform: 'capitalize',
              }}
            >
              {item.title}
            </span>
            <span className="mono" style={{ fontSize: 10.5, color: active ? 'var(--text-1)' : 'var(--text-3)', lineHeight: 1.45 }}>
              {item.desc}
            </span>
          </div>
        )
      })}
    </div>
  )
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <div>
      <label className="label">{label}</label>
      <input className="input" type="number" min={0} value={value} onChange={e => onChange(Number(e.target.value))} />
    </div>
  )
}

function BruteForceSection({
  bruteForce,
  setBruteForce,
  credWordlists,
  userWordlists,
  passWordlists,
}: {
  bruteForce: {
    enabled: boolean
    credential_wordlist_id: string
    username_wordlist_id: string
    password_wordlist_id: string
    max_concurrent: number
    delay_ms: number
    stop_on_success: boolean
  }
  setBruteForce: Dispatch<SetStateAction<{
    enabled: boolean
    credential_wordlist_id: string
    username_wordlist_id: string
    password_wordlist_id: string
    max_concurrent: number
    delay_ms: number
    stop_on_success: boolean
  }>>
  credWordlists: { id: string; name: string; entry_count: number }[]
  userWordlists: { id: string; name: string; entry_count: number }[]
  passWordlists: { id: string; name: string; entry_count: number }[]
}) {
  return (
    <CapabilityGroup title="Brute Force">
      <p className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)', margin: 0 }}>
        Actively tries username/password lists against detected services. Known credentials above are for authenticated checks.
      </p>
      <Toggle label="Enable credential checks from wordlists" checked={bruteForce.enabled} onChange={enabled => setBruteForce(b => ({ ...b, enabled }))} />
      {bruteForce.enabled && (
        <>
          <div>
            <label className="label">Credential pairs list <span className="dimmer" style={{ fontWeight: 400 }}>(user:password)</span></label>
            <select className="select-field" value={bruteForce.credential_wordlist_id} onChange={e => setBruteForce(b => ({ ...b, credential_wordlist_id: e.target.value }))}>
              <option value="">None - use separate lists below</option>
              {credWordlists.map(w => <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()} pairs)</option>)}
            </select>
          </div>
          {!bruteForce.credential_wordlist_id && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <div>
                <label className="label">Username list</label>
                <select className="select-field" value={bruteForce.username_wordlist_id} onChange={e => setBruteForce(b => ({ ...b, username_wordlist_id: e.target.value }))}>
                  <option value="">Built-in defaults</option>
                  {userWordlists.map(w => <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()})</option>)}
                </select>
              </div>
              <div>
                <label className="label">Password list</label>
                <select className="select-field" value={bruteForce.password_wordlist_id} onChange={e => setBruteForce(b => ({ ...b, password_wordlist_id: e.target.value }))}>
                  <option value="">Built-in defaults</option>
                  {passWordlists.map(w => <option key={w.id} value={w.id}>{w.name} ({w.entry_count.toLocaleString()})</option>)}
                </select>
              </div>
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            <NumberField label="Max concurrent" value={bruteForce.max_concurrent} onChange={max_concurrent => setBruteForce(b => ({ ...b, max_concurrent }))} />
            <NumberField label="Delay ms" value={bruteForce.delay_ms} onChange={delay_ms => setBruteForce(b => ({ ...b, delay_ms }))} />
            <Toggle label="Stop on success" checked={bruteForce.stop_on_success} onChange={stop_on_success => setBruteForce(b => ({ ...b, stop_on_success }))} />
          </div>
        </>
      )}
    </CapabilityGroup>
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
