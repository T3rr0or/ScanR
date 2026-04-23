import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus, Lock, User, FileText, Pencil, Check, X, Rocket } from 'lucide-react'
import { templatesApi, type ScanTemplate } from '@/api/templates'
import { ProfileEditor, PORT_RANGES, configToJson, jsonToConfig, type ProfileConfig } from '@/components/ProfileEditor'
import { scansApi } from '@/api/scans'

interface Props {
  onSelectTemplate?: (template: ScanTemplate) => void
}

export default function Templates({ onSelectTemplate }: Props) {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ name: '', description: '' })

  // "Use Template" modal state
  const [useTemplate, setUseTemplate] = useState<ScanTemplate | null>(null)
  const [scanName, setScanName] = useState('')
  const [targets, setTargets] = useState('')
  const [createdScanId, setCreatedScanId] = useState<string | null>(null)

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

  const launchScanMut = useMutation({
    mutationFn: () => {
      if (!useTemplate) throw new Error('No template selected')
      const pj = useTemplate.profile_json ?? {}
      return scansApi.create({
        name: scanName,
        targets: targets.split('\n').filter(Boolean).map(t => t.trim()),
        profile: 'custom',
        profile_json: JSON.stringify(pj),
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
                    onUse={() => openUseTemplate(t)}
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
                    onUse={() => openUseTemplate(t)}
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

      {/* ── Use Template Modal ─────────────────────────────────────────────── */}
      {useTemplate && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            zIndex: 50,
            background: 'rgba(0,0,0,0.55)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '16px',
          }}
          onClick={(e) => { if (e.target === e.currentTarget) closeUseTemplate() }}
        >
          <div
            className="bg-white rounded-xl shadow-2xl w-full"
            style={{ maxWidth: 520 }}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
              <div className="flex items-center gap-2">
                <Rocket size={16} className="text-blue-600" />
                <h2 className="font-semibold text-gray-900">
                  Use Template: <span className="text-blue-600">{useTemplate.name}</span>
                </h2>
              </div>
              <button
                onClick={closeUseTemplate}
                className="p-1 text-gray-400 hover:text-gray-600 rounded"
              >
                <X size={18} />
              </button>
            </div>

            <div className="px-6 py-5 space-y-4">
              {/* Success state */}
              {createdScanId ? (
                <div className="space-y-4">
                  <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-green-700 font-medium text-sm mb-1">
                      <Check size={15} /> Scan created successfully
                    </div>
                    <p className="text-xs text-green-600 font-mono">ID: {createdScanId}</p>
                    <p className="text-xs text-green-600 mt-1">
                      Navigate to the <strong>Scans</strong> page to view and launch it.
                    </p>
                  </div>
                  <div className="flex justify-end">
                    <button
                      onClick={closeUseTemplate}
                      className="px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg text-sm font-medium"
                    >
                      Close
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  {/* Scan name */}
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1.5">Scan Name</label>
                    <input
                      value={scanName}
                      onChange={e => setScanName(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
                      placeholder="My scan"
                    />
                  </div>

                  {/* Targets */}
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1.5">
                      Targets <span className="text-gray-400 font-normal">(one per line: IP, CIDR, hostname)</span>
                    </label>
                    <textarea
                      value={targets}
                      onChange={e => setTargets(e.target.value)}
                      rows={4}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm font-mono resize-none"
                      placeholder={"192.168.1.0/24\nexample.com"}
                    />
                  </div>

                  {/* Profile preview */}
                  <ProfilePreview profileJson={useTemplate.profile_json} />

                  {/* Error */}
                  {launchScanMut.isError && (
                    <div className="bg-red-50 border border-red-200 rounded-lg px-3 py-2 text-xs text-red-600">
                      {launchScanMut.error instanceof Error
                        ? launchScanMut.error.message
                        : 'Failed to create scan. Please try again.'}
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex gap-2 justify-end pt-1">
                    <button
                      onClick={closeUseTemplate}
                      className="px-4 py-2 text-sm text-gray-600 rounded-lg hover:bg-gray-100"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => launchScanMut.mutate()}
                      disabled={!scanName.trim() || !targets.trim() || launchScanMut.isPending}
                      className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <Rocket size={14} />
                      {launchScanMut.isPending ? 'Creating...' : 'Launch Scan'}
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

// ── Profile Preview ──────────────────────────────────────────────────────────

function ProfilePreview({ profileJson }: { profileJson: Record<string, unknown> | null }) {
  if (!profileJson) return null

  const pj = typeof profileJson === 'string' ? JSON.parse(profileJson) : profileJson
  const config = jsonToConfig(pj)

  const portLabel = PORT_RANGES.find(r => r.value === config.port_range)?.label ?? config.port_range
  const plugins = (pj.plugins as string[] | undefined) ?? ['*']
  const pluginDisplay = plugins.includes('*') ? 'All categories' : plugins.join(', ')

  return (
    <div className="bg-gray-50 border border-gray-200 rounded-lg p-3 space-y-1.5">
      <p className="text-xs font-medium text-gray-500 mb-2">Template profile</p>
      <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-400 w-24 flex-shrink-0">Port range</span>
        <span className="font-mono text-gray-700">{portLabel}</span>
      </div>
      <div className="flex items-start gap-2 text-xs">
        <span className="text-gray-400 w-24 flex-shrink-0">Plugins</span>
        <span className="font-mono text-gray-700 break-all">{pluginDisplay}</span>
      </div>
      {typeof pj.max_concurrent === 'number' && (
        <div className="flex items-center gap-2 text-xs">
          <span className="text-gray-400 w-24 flex-shrink-0">Concurrency</span>
          <span className="font-mono text-gray-700">{pj.max_concurrent}</span>
        </div>
      )}
    </div>
  )
}

// ── Template Card ────────────────────────────────────────────────────────────

function TemplateCard({
  template,
  onSelect,
  canEdit,
  canDelete,
  onDelete,
  onSave,
  isSaving,
  onUse,
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

  // Profile summary for card
  const pj = template.profile_json
  const portLabel = pj
    ? PORT_RANGES.find(r => r.value === (pj as any).port_range)?.label.split(' —')[0]
      ?? (pj as any).port_range ?? 'default'
    : 'default'

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
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-500 font-medium flex-shrink-0">
                <Lock size={9} /> system
              </span>
            )}
          </div>
          {template.description && (
            <p className="text-xs text-gray-500 mt-1 line-clamp-2">{template.description}</p>
          )}
          {/* Profile summary */}
          <div className="mt-2 text-xs text-gray-400 font-mono flex items-center gap-3">
            <span>ports: {portLabel}</span>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          {/* Use Template button — always visible */}
          <button
            onClick={onUse}
            className="flex items-center gap-1 px-2.5 py-1 text-xs bg-blue-600 text-white rounded hover:bg-blue-700 font-medium"
            title="Use this template to create a scan"
          >
            <Rocket size={11} /> Use
          </button>
          {onSelect && (
            <button
              onClick={() => onSelect(template)}
              className="px-2 py-1 text-xs bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
            >
              Select
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
