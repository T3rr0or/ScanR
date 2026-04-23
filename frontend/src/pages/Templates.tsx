import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, Lock, User, LayoutTemplate, Pencil, Check, X } from 'lucide-react'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ProfileEditor, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'

interface Props {
  onSelectTemplate?: (template: ScanTemplate) => void
}

export default function Templates({ onSelectTemplate }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })

  const { data: templates = [], isLoading } = useQuery({
    queryKey: ['templates'],
    queryFn: templatesApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => templatesApi.create({ name: form.name, description: form.description || undefined }),
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

  const systemTemplates = templates.filter(t => t.is_system)
  const userTemplates = templates.filter(t => !t.is_system)

  return (
    <div style={{ padding: '24px 28px', maxWidth: 900 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <LayoutTemplate size={18} style={{ color: 'var(--accent)' }} />
          <h1 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-0)' }}>Scan Templates</h1>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
          <Plus size={13} /> New Template
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="panel" style={{ marginBottom: 20, padding: 16 }}>
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
                  <TemplateCard key={t.id} template={t} onSelect={onSelectTemplate} canEdit={false} canDelete={false} />
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
                    onSave={(body) => updateMut.mutate({ id: t.id, body })}
                    isSaving={updateMut.isPending}
                  />
                ))}
              </div>
            </section>
          )}

          {templates.length === 0 && (
            <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)', fontSize: 13 }}>
              <LayoutTemplate size={32} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
              No templates yet
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function TemplateCard({
  template, onSelect, canEdit, canDelete, onDelete, onSave, isSaving,
}: {
  template: ScanTemplate
  onSelect?: (t: ScanTemplate) => void
  canEdit: boolean
  canDelete: boolean
  onDelete?: () => void
  onSave?: (body: { name?: string; description?: string; profile_json?: Record<string, unknown> }) => void
  isSaving?: boolean
}) {
  const [editing, setEditing] = useState(false)
  const [editName, setEditName] = useState(template.name)
  const [editDesc, setEditDesc] = useState(template.description ?? '')
  const [editProfile, setEditProfile] = useState<ProfileConfig>(
    jsonToConfig(template.profile_json as Record<string, unknown> | null)
  )

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

  if (editing) {
    return (
      <div className="panel" style={{ padding: 14, border: '1px solid var(--accent)' }}>
        <input
          value={editName}
          onChange={e => setEditName(e.target.value)}
          className="input"
          placeholder="Template name"
          style={{ marginBottom: 8 }}
        />
        <textarea
          value={editDesc}
          onChange={e => setEditDesc(e.target.value)}
          placeholder="Description (optional)"
          rows={2}
          className="textarea"
          style={{ marginBottom: 10 }}
        />
        <div style={{ borderRadius: 6, border: '1px solid var(--border)', padding: 10, marginBottom: 10 }}>
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

  const portRange = (template.profile_json as any)?.port_range

  return (
    <div className="panel" style={{ padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 8 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <LayoutTemplate size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {template.name}
            </span>
            {template.is_system && <Lock size={10} style={{ color: 'var(--text-3)', flexShrink: 0 }} />}
          </div>
          {template.description && (
            <p style={{ fontSize: 11.5, color: 'var(--text-2)', lineHeight: 1.5 }}>{template.description}</p>
          )}
          {portRange && (
            <div className="mono dimmer" style={{ fontSize: 10, marginTop: 6 }}>ports: {portRange}</div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
          {onSelect && (
            <button onClick={() => onSelect(template)} className="btn btn-ghost btn-sm" style={{ fontSize: 11 }}>Use</button>
          )}
          {canEdit && (
            <button onClick={startEdit} className="btn btn-ghost btn-icon btn-sm" title="Edit">
              <Pencil size={12} />
            </button>
          )}
          {canDelete && onDelete && (
            <button onClick={onDelete} className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: 'var(--sev-high)' }}>
              <Trash2 size={12} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
