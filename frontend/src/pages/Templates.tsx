import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, Lock, User, FileText, Pencil, Check, X, Rocket } from 'lucide-react'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ProfileEditor, PORT_RANGES, configToJson, defaultProfileConfig, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import { scansApi } from '@/api/scans'

interface Props {
  onSelectTemplate?: (template: ScanTemplate) => void
}

export default function Templates({ onSelectTemplate }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })
  const [useTemplate, setUseTemplate] = useState<ScanTemplate | null>(null)
  const [scanName, setScanName] = useState('')
  const [targets, setTargets] = useState('')
  const [createdScanId, setCreatedScanId] = useState<string | null>(null)

  const { data: templates = [], isLoading } = useQuery({ queryKey: ['templates'], queryFn: templatesApi.list })

  const createMut = useMutation({
    mutationFn: () => templatesApi.create({
      name: form.name,
      description: form.description || undefined,
      profile_json: configToJson(defaultProfileConfig()),
    }),
    onSuccess: () => {
      setShowCreate(false)
      setForm({ name: '', description: '' })
      qc.invalidateQueries({ queryKey: ['templates'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: templatesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['templates'] }),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Parameters<typeof templatesApi.update>[1] }) =>
      templatesApi.update(id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['templates'] }),
  })

  const launchScanMut = useMutation({
    mutationFn: () => {
      if (!useTemplate) throw new Error('No template selected')
      return scansApi.create({
        name: scanName,
        targets: targets.split('\n').filter(Boolean).map(t => t.trim()),
        profile: 'custom',
        profile_json: JSON.stringify(useTemplate.profile_json ?? {}),
      })
    },
    onSuccess: (scan) => {
      setCreatedScanId(scan.id)
      qc.invalidateQueries({ queryKey: ['scans', 0] })
    },
  })

  function openUseTemplate(t: ScanTemplate) {
    setUseTemplate(t)
    setScanName(`${t.name} — ${new Date().toLocaleDateString()}`)
    setTargets('')
    setCreatedScanId(null)
    launchScanMut.reset()
  }

  function closeUseTemplate() {
    setUseTemplate(null)
    setScanName('')
    setTargets('')
    setCreatedScanId(null)
    launchScanMut.reset()
  }

  const systemTemplates = templates.filter(t => t.is_system)
  const userTemplates = templates.filter(t => !t.is_system)

  return (
    <div className="page-pad" style={{ maxWidth: 960 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Scan Templates</h1>
        <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
          <Plus size={14} /> New Template
        </button>
      </div>

      {showCreate && (
        <div className="panel" style={{ padding: 16, marginBottom: 20 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>New Template</div>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Template name"
            className="input"
            style={{ marginBottom: 8 }}
          />
          <textarea
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            rows={2}
            className="textarea"
            style={{ marginBottom: 10 }}
          />
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => createMut.mutate()} disabled={!form.name || createMut.isPending} className="btn btn-primary btn-sm">
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="dimmer" style={{ fontSize: 13, padding: '20px 0' }}>Loading…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
          {systemTemplates.length > 0 && (
            <section>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Lock size={11} /> System Templates
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
                {systemTemplates.map(t => (
                  <TemplateCard key={t.id} template={t} onSelect={onSelectTemplate} canEdit={false} canDelete={false} onUse={() => openUseTemplate(t)} />
                ))}
              </div>
            </section>
          )}

          {userTemplates.length > 0 && (
            <section>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-3)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
                <User size={11} /> My Templates
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
                {userTemplates.map(t => (
                  <TemplateCard
                    key={t.id} template={t} onSelect={onSelectTemplate}
                    canEdit canDelete
                    onDelete={() => deleteMut.mutate(t.id)}
                    onSave={body => updateMut.mutate({ id: t.id, body })}
                    isSaving={updateMut.isPending}
                    onUse={() => openUseTemplate(t)}
                  />
                ))}
              </div>
            </section>
          )}

          {templates.length === 0 && (
            <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)', fontSize: 13 }}>No templates yet</div>
          )}
        </div>
      )}

      {/* Use Template Modal */}
      {useTemplate && (
        <div
          style={{ position: 'fixed', inset: 0, zIndex: 50, background: 'oklch(0.05 0.01 255 / 0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}
          onClick={e => { if (e.target === e.currentTarget) closeUseTemplate() }}
        >
          <div className="panel" style={{ maxWidth: 520, width: '100%', padding: 0, overflow: 'hidden', boxShadow: '0 24px 80px #0009' }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 18px', borderBottom: '1px solid var(--border)', background: 'var(--bg-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Rocket size={15} style={{ color: 'var(--accent)' }} />
                <span style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-0)' }}>
                  Use Template: <span style={{ color: 'var(--accent)' }}>{useTemplate.name}</span>
                </span>
              </div>
              <button onClick={closeUseTemplate} className="btn btn-ghost btn-icon btn-sm"><X size={15} /></button>
            </div>

            <div style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
              {createdScanId ? (
                <>
                  <div style={{ padding: 14, borderRadius: 8, background: 'oklch(0.22 0.05 145 / 0.3)', border: '1px solid var(--ok)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--ok)', fontWeight: 600, fontSize: 13, marginBottom: 4 }}>
                      <Check size={14} /> Scan created successfully
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--ok)' }}>ID: {createdScanId}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>Navigate to the Scans page to view and launch it.</div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                    <button onClick={closeUseTemplate} className="btn btn-ghost btn-sm">Close</button>
                  </div>
                </>
              ) : (
                <>
                  <div>
                    <label className="label">Scan Name</label>
                    <input value={scanName} onChange={e => setScanName(e.target.value)} className="input" placeholder="My scan" />
                  </div>
                  <div>
                    <label className="label">Targets <span className="dimmer" style={{ fontWeight: 400 }}>(one per line: IP, CIDR, hostname)</span></label>
                    <textarea
                      value={targets}
                      onChange={e => setTargets(e.target.value)}
                      rows={4}
                      className="textarea"
                      style={{ fontFamily: 'var(--font-mono)', fontSize: 12, resize: 'none' }}
                      placeholder={"192.168.1.0/24\nexample.com"}
                    />
                  </div>
                  <ProfilePreview profileJson={useTemplate.profile_json} />
                  {launchScanMut.isError && (
                    <div style={{ padding: '8px 12px', borderRadius: 6, background: 'oklch(0.22 0.08 25 / 0.3)', border: '1px solid var(--sev-high)', fontSize: 12, color: 'var(--sev-high)' }}>
                      {launchScanMut.error instanceof Error ? launchScanMut.error.message : 'Failed to create scan'}
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4 }}>
                    <button onClick={closeUseTemplate} className="btn btn-ghost btn-sm">Cancel</button>
                    <button
                      onClick={() => launchScanMut.mutate()}
                      disabled={!scanName.trim() || !targets.trim() || launchScanMut.isPending}
                      className="btn btn-primary btn-sm"
                    >
                      <Rocket size={13} /> {launchScanMut.isPending ? 'Creating…' : 'Launch Scan'}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ProfilePreview({ profileJson }: { profileJson: Record<string, unknown> | null }) {
  if (!profileJson) return null
  const pj = typeof profileJson === 'string' ? JSON.parse(profileJson) : profileJson
  const config = jsonToConfig(pj)
  const portLabel = PORT_RANGES.find(r => r.value === config.port_range)?.label ?? config.port_range
  const plugins = (pj.plugins as string[] | undefined) ?? ['*']
  const pluginDisplay = plugins.includes('*') ? 'All categories' : plugins.join(', ')

  return (
    <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
      <div className="dimmer" style={{ fontSize: 11, fontWeight: 600, marginBottom: 8 }}>Template profile</div>
      {[
        { label: 'Context', value: `${config.scan_context} / ${config.target_type === 'auto' ? 'auto target handling' : config.target_type}` },
        { label: 'Port range', value: portLabel },
        { label: 'Depth', value: config.depth_level },
        { label: 'Safety', value: config.safety_level },
        { label: 'Performance', value: config.performance_profile },
        { label: 'Plugins', value: pluginDisplay },
        { label: 'Enumeration', value: [
          config.enumeration.http_probing ? 'HTTP' : null,
          config.enumeration.tls_checks ? 'TLS' : null,
          config.enumeration.screenshots ? 'screenshots' : null,
          config.enumeration.nuclei ? 'Nuclei' : null,
          config.enumeration.directory_enum ? 'dirs' : null,
          config.enumeration.subdomain_enum ? 'subdomains' : null,
        ].filter(Boolean).join(', ') || 'none' },
        ...(typeof pj.max_concurrent === 'number' ? [{ label: 'Concurrency', value: String(pj.max_concurrent) }] : []),
      ].map(row => (
        <div key={row.label} style={{ display: 'flex', gap: 8, fontSize: 12, marginBottom: 4 }}>
          <span className="dimmer" style={{ width: 90, flexShrink: 0 }}>{row.label}</span>
          <span className="mono" style={{ color: 'var(--text-1)', wordBreak: 'break-all' }}>{row.value}</span>
        </div>
      ))}
    </div>
  )
}

function TemplateCard({
  template, onSelect, canEdit, canDelete, onDelete, onSave, isSaving, onUse,
}: {
  template: ScanTemplate
  onSelect?: (t: ScanTemplate) => void
  canEdit: boolean
  canDelete: boolean
  onDelete?: () => void
  onSave?: (body: { name?: string; description?: string; profile_json?: Record<string, unknown> }) => void
  isSaving?: boolean
  onUse?: () => void
}) {
  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState(template.name)
  const [editDesc, setEditDesc] = useState(template.description ?? '')
  const [editProfile, setEditProfile] = useState<ProfileConfig>(jsonToConfig(template.profile_json as Record<string, unknown> | null))

  function startEdit() {
    setEditName(template.name)
    setEditDesc(template.description ?? '')
    setEditProfile(jsonToConfig(template.profile_json as Record<string, unknown> | null))
    setEditing(true)
  }

  function handleSave() {
    onSave?.({ name: editName || undefined, description: editDesc || undefined, profile_json: configToJson(editProfile) })
    setEditing(false)
  }

  const pj = template.profile_json
  const portLabel = pj
    ? PORT_RANGES.find(r => r.value === (pj as any).port_range)?.label.split(' —')[0] ?? (pj as any).port_range ?? 'default'
    : 'default'

  if (editing) {
    return (
      <div className="panel" style={{ padding: 14, border: '1px solid var(--accent)', gridColumn: '1 / -1' }}>
        <input value={editName} onChange={e => setEditName(e.target.value)} className="input" placeholder="Template name" style={{ marginBottom: 8 }} />
        <textarea
          value={editDesc}
          onChange={e => setEditDesc(e.target.value)}
          placeholder="Description (optional)"
          rows={2}
          className="textarea"
          style={{ marginBottom: 10 }}
        />
        <div style={{ background: 'var(--bg-2)', border: '1px solid var(--border)', borderRadius: 6, padding: 12, marginBottom: 12 }}>
          <ProfileEditor config={editProfile} onChange={setEditProfile} />
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={handleSave} disabled={!editName || isSaving} className="btn btn-primary btn-sm">
            <Check size={12} /> {isSaving ? 'Saving…' : 'Save'}
          </button>
          <button onClick={() => setEditing(false)} className="btn btn-ghost btn-sm">
            <X size={12} /> Cancel
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="panel" style={{ padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <FileText size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
            <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {template.name}
            </span>
            {template.is_system && (
              <span className="mono" style={{ fontSize: 10, padding: '1px 5px', borderRadius: 4, background: 'var(--bg-3)', color: 'var(--text-3)', display: 'inline-flex', alignItems: 'center', gap: 3, flexShrink: 0 }}>
                <Lock size={8} /> system
              </span>
            )}
          </div>
          {template.description && (
            <p style={{ fontSize: 12, color: 'var(--text-2)', marginBottom: 6, lineHeight: 1.5 }}>{template.description}</p>
          )}
          <div className="mono dimmer" style={{ fontSize: 10 }}>ports: {portLabel}</div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
          <button onClick={onUse} className="btn btn-primary btn-sm" style={{ fontSize: 11 }} title="Use this template">
            <Rocket size={11} /> Use
          </button>
          {onSelect && (
            <button onClick={() => onSelect(template)} className="btn btn-ghost btn-sm" style={{ fontSize: 11 }}>Select</button>
          )}
          {canEdit && (
            <button onClick={startEdit} className="btn btn-ghost btn-icon btn-sm" title="Edit"><Pencil size={12} /></button>
          )}
          {canDelete && onDelete && (
            <button onClick={onDelete} className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: 'var(--sev-high)' }}><Trash2 size={12} /></button>
          )}
        </div>
      </div>
    </div>
  )
}
