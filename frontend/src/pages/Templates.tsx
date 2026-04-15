import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, Lock, User, FileText, Pencil, Check, X } from 'lucide-react'
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
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Scan Templates</h1>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
        >
          <Plus size={14} /> New Template
        </button>
      </div>

      {showCreate && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-3 mb-6">
          <h3 className="font-medium text-sm">New Template</h3>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Template name"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <textarea
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            rows={2}
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <div className="flex gap-2">
            <button
              onClick={() => createMut.mutate()}
              disabled={!form.name || createMut.isPending}
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Creating...' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-gray-600 text-sm">Cancel</button>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-gray-500 text-sm p-4">Loading...</div>
      ) : (
        <div className="space-y-6">
          {systemTemplates.length > 0 && (
            <section>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Lock size={12} /> System Templates
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {systemTemplates.map(t => (
                  <TemplateCard
                    key={t.id}
                    template={t}
                    onSelect={onSelectTemplate}
                    canEdit={false}
                    canDelete={false}
                  />
                ))}
              </div>
            </section>
          )}

          {userTemplates.length > 0 && (
            <section>
              <h2 className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-3 flex items-center gap-2">
                <User size={12} /> My Templates
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {userTemplates.map(t => (
                  <TemplateCard
                    key={t.id}
                    template={t}
                    onSelect={onSelectTemplate}
                    canEdit={true}
                    canDelete={true}
                    onDelete={() => deleteMut.mutate(t.id)}
                    onSave={(body) => updateMut.mutate({ id: t.id, body })}
                    isSaving={updateMut.isPending}
                  />
                ))}
              </div>
            </section>
          )}

          {templates.length === 0 && (
            <div className="text-center py-12 text-gray-400 text-sm">No templates yet</div>
          )}
        </div>
      )}
    </div>
  )
}

function TemplateCard({
  template,
  onSelect,
  canEdit,
  canDelete,
  onDelete,
  onSave,
  isSaving,
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
    onSave?.({
      name: editName || undefined,
      description: editDesc || undefined,
      profile_json: configToJson(editProfile),
    })
    setEditing(false)
  }

  if (editing) {
    return (
      <div className="bg-white border border-blue-300 rounded-lg p-4 space-y-3">
        <input
          value={editName}
          onChange={e => setEditName(e.target.value)}
          className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm font-medium"
          placeholder="Template name"
        />
        <textarea
          value={editDesc}
          onChange={e => setEditDesc(e.target.value)}
          placeholder="Description (optional)"
          rows={2}
          className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm text-gray-600 resize-none"
        />
        <div className="border border-gray-200 rounded-lg p-3 bg-gray-50">
          <ProfileEditor config={editProfile} onChange={setEditProfile} />
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleSave}
            disabled={!editName || isSaving}
            className="flex items-center gap-1 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
          >
            <Check size={13} /> {isSaving ? 'Saving...' : 'Save'}
          </button>
          <button
            onClick={() => setEditing(false)}
            className="flex items-center gap-1 px-3 py-1.5 text-gray-600 rounded text-sm hover:bg-gray-100"
          >
            <X size={13} /> Cancel
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 hover:border-gray-300 transition-colors">
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <FileText size={14} className="text-blue-500 flex-shrink-0" />
            <span className="font-medium text-sm truncate">{template.name}</span>
            {template.is_system && (
              <Lock size={11} className="text-gray-400 flex-shrink-0" />
            )}
          </div>
          {template.description && (
            <p className="text-xs text-gray-500 mt-1 line-clamp-2">{template.description}</p>
          )}
          {template.profile_json && (
            <div className="mt-2 text-xs text-gray-400 font-mono">
              {(template.profile_json as any).port_range && (
                <span className="mr-2">ports: {(template.profile_json as any).port_range}</span>
              )}
            </div>
          )}
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {onSelect && (
            <button
              onClick={() => onSelect(template)}
              className="px-2 py-1 text-xs bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
            >
              Use
            </button>
          )}
          {canEdit && (
            <button
              onClick={startEdit}
              className="p-1 text-gray-400 hover:text-blue-500 rounded"
              title="Edit"
            >
              <Pencil size={13} />
            </button>
          )}
          {canDelete && onDelete && (
            <button
              onClick={onDelete}
              className="p-1 text-gray-400 hover:text-red-500 rounded"
              title="Delete"
            >
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
