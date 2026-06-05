import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Server, Search, X, Plus, AlertTriangle } from 'lucide-react'
import { assetsApi, type AssetItem } from '@/api/assets'
import type { Finding } from '@/api/findings'
import { SevTag, CHML, relTime } from '@/components/ui'
import FindingDetailPanel from '@/components/FindingDetailPanel'
import SortableTh from '@/components/SortableTh'
import { useSortableFindings } from '@/hooks/useSortableFindings'

type AssetSortKey = 'ip' | 'hostname' | 'risk' | 'findings' | 'last_seen' | 'scans'


function AssetTh({ label, sortKey, active, dir, onSort }: { label: string; sortKey: AssetSortKey; active: AssetSortKey; dir: 'asc' | 'desc'; onSort: (k: AssetSortKey) => void }) {
  const isActive = active === sortKey
  return (
    <th onClick={() => onSort(sortKey)} style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap', color: isActive ? 'var(--accent)' : undefined }}>
      {label}<span style={{ marginLeft: 4, opacity: isActive ? 1 : 0.25, fontSize: 9 }}>{isActive ? (dir === 'asc' ? '▲' : '▼') : '⇅'}</span>
    </th>
  )
}

function VprBadge({ score }: { score: number | null }) {
  if (score == null) return <span className="dimmer" style={{ fontSize: 11 }}>—</span>
  const color = score >= 8 ? 'var(--sev-critical)' : score >= 5 ? 'var(--sev-high)' : 'var(--sev-medium)'
  return (
    <span className="mono" style={{ fontSize: 11, fontWeight: 700, color, background: `${color}20`, padding: '1px 5px', borderRadius: 3 }}>
      {score.toFixed(1)}
    </span>
  )
}

function TagChips({ tags, onAdd, onRemove }: { ip?: string; tags: string[]; onAdd: (t: string) => void; onRemove: (t: string) => void }) {
  const [adding, setAdding] = useState(false)
  const [draft, setDraft] = useState('')
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
      {tags.map(t => (
        <span key={t} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 10, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 6px', borderRadius: 999, fontWeight: 600 }}>
          {t}
          <button onClick={() => onRemove(t)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'inherit', padding: 0, lineHeight: 1 }}><X size={9} /></button>
        </span>
      ))}
      {adding ? (
        <input
          autoFocus value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' && draft.trim()) { onAdd(draft.trim()); setDraft(''); setAdding(false) }
            if (e.key === 'Escape') { setAdding(false); setDraft('') }
          }}
          onBlur={() => { if (!draft.trim()) setAdding(false) }}
          style={{ width: 80, fontSize: 10, padding: '2px 6px', borderRadius: 999, border: '1px solid var(--accent)', background: 'var(--bg-0)', color: 'var(--text-0)' }}
          placeholder="tag…"
        />
      ) : (
        <button onClick={() => setAdding(true)} style={{ background: 'none', border: '1px dashed var(--border)', cursor: 'pointer', color: 'var(--text-3)', padding: '2px 5px', borderRadius: 999, fontSize: 10 }}>
          <Plus size={9} />
        </button>
      )}
    </div>
  )
}

function FindingRow({ f, onClick }: { f: Finding; onClick: () => void }) {
  const sev = f.severity as 'critical' | 'high' | 'medium' | 'low' | 'info'
  return (
    <tr onClick={onClick} style={{ cursor: 'pointer' }} title="Click for details">
      <td><SevTag severity={sev} /></td>
      <td style={{ fontSize: 12, color: 'var(--text-0)' }}>{f.title}</td>
      <td className="mono dimmer" style={{ fontSize: 11 }}>{f.port_number ? `${f.port_number}/${f.protocol}` : '—'}</td>
      <td><VprBadge score={f.vpr_score} /></td>
      <td className="mono dimmer" style={{ fontSize: 11 }}>{f.cvss_score?.toFixed(1) ?? '—'}</td>
      <td><span className={`pill pill-${f.remediation_status === 'resolved' ? 'completed' : f.false_positive ? 'cancelled' : 'pending'}`} style={{ fontSize: 10 }}>{f.false_positive ? 'FP' : f.remediation_status}</span></td>
    </tr>
  )
}

/* Full-screen modal for a host's findings */
function HostFindingsModal({
  asset,
  findings,
  onClose,
  onSelectFinding,
}: {
  asset: AssetItem
  findings: Finding[]
  onClose: () => void
  onSelectFinding: (f: Finding) => void
}) {
  const { sorted, sortKey, sortDir, toggleSort } = useSortableFindings(findings)
  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 50,
        background: 'oklch(0.05 0.01 255 / 0.75)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: 24,
        animation: 'fadeIn 0.18s ease',
      }}
      onClick={onClose}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          width: '100%', maxWidth: 1100,
          maxHeight: 'calc(100vh - 48px)',
          background: 'var(--bg-1)',
          border: '1px solid var(--border)',
          borderRadius: 12,
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
          boxShadow: '0 24px 80px #0010',
          animation: 'slideUp 0.22s cubic-bezier(0.32, 0.72, 0, 1)',
        }}
      >
        {/* Modal header */}
        <div className="panel-head" style={{ padding: '14px 20px', gap: 12, flexShrink: 0 }}>
          <AlertTriangle size={15} style={{ color: 'var(--accent)' }} />
          <div style={{ flex: 1 }}>
            <span className="panel-title mono" style={{ fontSize: 15 }}>{asset.ip}</span>
            {asset.hostname && <span className="dimmer" style={{ fontSize: 11, marginLeft: 8 }}>{asset.hostname}</span>}
          </div>
          <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)', alignItems: 'center' }}>
            <CHML c={asset.findings_critical} h={asset.findings_high} m={asset.findings_medium} l={asset.findings_low} />
            <span>{findings.length} findings</span>
          </div>
          <button onClick={onClose} className="btn btn-ghost btn-icon btn-sm"><X size={14} /></button>
        </div>

        {/* Findings table */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {findings.length === 0 ? (
            <div className="dimmer" style={{ padding: 40, textAlign: 'center', fontSize: 13 }}>No findings for this host</div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <SortableTh label="Sev" sortKey="severity" active={sortKey} dir={sortDir} onSort={toggleSort} />
                  <SortableTh label="Title" sortKey="title" active={sortKey} dir={sortDir} onSort={toggleSort} />
                  <SortableTh label="Port" sortKey="port" active={sortKey} dir={sortDir} onSort={toggleSort} />
                  <SortableTh label="VPR" sortKey="vpr" active={sortKey} dir={sortDir} onSort={toggleSort} />
                  <SortableTh label="CVSS" sortKey="cvss" active={sortKey} dir={sortDir} onSort={toggleSort} />
                  <SortableTh label="Status" sortKey="status" active={sortKey} dir={sortDir} onSort={toggleSort} />
                </tr>
              </thead>
              <tbody>
                {sorted.map(f => (
                  <FindingRow key={f.id} f={f} onClick={() => onSelectFinding(f)} />
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}

export default function Assets() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<AssetItem | null>(null)
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null)
  const [assetSortKey, setAssetSortKey] = useState<AssetSortKey>('risk')
  const [assetSortDir, setAssetSortDir] = useState<'asc' | 'desc'>('desc')

  function toggleAssetSort(k: AssetSortKey) {
    if (assetSortKey === k) {
      setAssetSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setAssetSortKey(k)
      setAssetSortDir(k === 'risk' || k === 'findings' || k === 'last_seen' ? 'desc' : 'asc')
    }
  }

  const { data: rawAssets = [], isLoading } = useQuery({
    queryKey: ['assets', search],
    queryFn: () => assetsApi.list({ search: search || undefined, limit: 200 }),
  })

  const assets = useMemo(() => {
    const m = assetSortDir === 'asc' ? 1 : -1
    return [...rawAssets].sort((a, b) => {
      switch (assetSortKey) {
        case 'ip':        return m * a.ip.localeCompare(b.ip, undefined, { numeric: true, sensitivity: 'base' })
        case 'hostname':  return m * (a.hostname ?? '').localeCompare(b.hostname ?? '')
        case 'risk':      return m * (a.risk_score - b.risk_score)
        case 'findings':  return m * ((a.findings_critical * 1000 + a.findings_high * 100 + a.findings_medium * 10 + a.findings_low) - (b.findings_critical * 1000 + b.findings_high * 100 + b.findings_medium * 10 + b.findings_low))
        case 'last_seen': return m * ((a.last_seen_at ?? '').localeCompare(b.last_seen_at ?? ''))
        case 'scans':     return m * (a.scan_count - b.scan_count)
        default: return 0
      }
    })
  }, [rawAssets, assetSortKey, assetSortDir])

  const { data: tagMap = {} } = useQuery({
    queryKey: ['host-tags-all'],
    queryFn: assetsApi.allTags,
  })

  const { data: selectedFindings = [] } = useQuery({
    queryKey: ['asset-findings', selected?.ip],
    queryFn: () => assetsApi.findings(selected!.ip),
    enabled: !!selected,
  })

  const addTagMut = useMutation({
    mutationFn: ({ ip, tag }: { ip: string; tag: string }) => assetsApi.addTag(ip, tag),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-tags-all'] }),
  })
  const removeTagMut = useMutation({
    mutationFn: ({ ip, tag }: { ip: string; tag: string }) => assetsApi.removeTag(ip, tag),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['host-tags-all'] }),
  })

  return (
    <>
      <style>{`
        @keyframes fadeIn { from { opacity: 0 } to { opacity: 1 } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(16px) scale(0.98) } to { opacity: 1; transform: translateY(0) scale(1) } }
      `}</style>

      <div className="page-pad" style={{ maxWidth: 1480, margin: '0 auto' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Server size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Assets</h1>
              <p style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 2 }}>All discovered hosts across all scans, aggregated by IP</p>
            </div>
          </div>
          <div className="search" style={{ width: 260 }}>
            <Search size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search IP or hostname…" style={{ minWidth: 0 }} />
          </div>
        </div>

        {/* Full-width asset table */}
        <div className="panel" style={{ overflow: 'auto', maxHeight: 'calc(100vh - 180px)' }}>
          {isLoading ? (
            <div className="dimmer" style={{ padding: 24, fontSize: 13 }}>Loading…</div>
          ) : assets.length === 0 ? (
            <div style={{ padding: 48, textAlign: 'center', color: 'var(--text-3)' }}>
              <Server size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
              <p style={{ fontSize: 13 }}>No assets discovered yet. Run a scan first.</p>
            </div>
          ) : (
            <table className="tbl">
              <thead>
                <tr>
                  <AssetTh label="IP" sortKey="ip" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <AssetTh label="Hostname" sortKey="hostname" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <th>OS</th>
                  <AssetTh label="Scans" sortKey="scans" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <AssetTh label="Findings (C/H/M/L)" sortKey="findings" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <AssetTh label="Risk" sortKey="risk" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <AssetTh label="Last seen" sortKey="last_seen" active={assetSortKey} dir={assetSortDir} onSort={toggleAssetSort} />
                  <th>Tags</th>
                </tr>
              </thead>
              <tbody>
                {assets.map(a => {
                  const tags = tagMap[a.ip] ?? []
                  return (
                    <tr key={a.ip} onClick={() => setSelected(a)} style={{ cursor: 'pointer' }}>
                      <td className="mono" style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent)' }}>{a.ip}</td>
                      <td className="mono dimmer" style={{ fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.hostname ?? '—'}</td>
                      <td style={{ fontSize: 11, color: 'var(--text-2)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.os_name ?? '—'}</td>
                      <td style={{ fontSize: 11 }}>{a.scan_count}</td>
                      <td><CHML c={a.findings_critical} h={a.findings_high} m={a.findings_medium} l={a.findings_low} /></td>
                      <td>
                        {a.risk_score > 0 ? (
                          <span className="mono" style={{ fontSize: 11, fontWeight: 700, color: a.risk_score >= 80 ? 'var(--sev-critical)' : a.risk_score >= 30 ? 'var(--sev-high)' : 'var(--sev-medium)' }}>
                            {a.risk_score}
                          </span>
                        ) : <span className="dimmer" style={{ fontSize: 11 }}>0</span>}
                      </td>
                      <td className="dimmer" style={{ fontSize: 11 }}>{a.last_seen_at ? relTime(a.last_seen_at) : '—'}</td>
                      <td>
                        <TagChips ip={a.ip} tags={tags}
                          onAdd={tag => addTagMut.mutate({ ip: a.ip, tag })}
                          onRemove={tag => removeTagMut.mutate({ ip: a.ip, tag })}
                        />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Host findings full-screen modal */}
      {selected && (
        <HostFindingsModal
          asset={selected}
          findings={selectedFindings}
          onClose={() => { setSelected(null); setDetailFinding(null) }}
          onSelectFinding={setDetailFinding}
        />
      )}

      {/* Finding detail panel (slides in on top of modal) */}
      <FindingDetailPanel finding={detailFinding} onClose={() => setDetailFinding(null)} />
    </>
  )
}
