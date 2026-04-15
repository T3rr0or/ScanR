import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Calendar } from 'lucide-react'
import { schedulesApi, type Schedule } from '@/api/schedules'

const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every day at 2am', value: '0 2 * * *' },
  { label: 'Every Monday at 2am', value: '0 2 * * 1' },
  { label: 'Every Sunday at midnight', value: '0 0 * * 0' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'First day of month', value: '0 2 1 * *' },
]

export default function Schedules() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    name: '',
    description: '',
    targets: '',
    cron_expr: '0 2 * * *',
    scan_profile_json: '{}',
    enabled: true,
  })

  const { data: schedules = [], isLoading } = useQuery({
    queryKey: ['schedules'],
    queryFn: schedulesApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => schedulesApi.create({
      name: form.name,
      description: form.description || undefined,
      targets: form.targets.split('\n').map(t => t.trim()).filter(Boolean),
      cron_expr: form.cron_expr,
      scan_profile_json: form.scan_profile_json,
      enabled: form.enabled,
    }),
    onSuccess: () => {
      setShowCreate(false)
      setForm({ name: '', description: '', targets: '', cron_expr: '0 2 * * *', scan_profile_json: '{}', enabled: true })
      qc.invalidateQueries({ queryKey: ['schedules'] })
    },
  })

  const deleteMut = useMutation({
    mutationFn: schedulesApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      schedulesApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  function fmtDate(d: string | null) {
    if (!d) return '—'
    return new Date(d).toLocaleString()
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scheduled Scans</h1>
          <p className="text-sm text-gray-500 mt-1">Recurring scans run automatically on a cron schedule</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
        >
          <Plus size={14} /> New Schedule
        </button>
      </div>

      {showCreate && (
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 space-y-3 mb-6">
          <h3 className="font-medium text-sm">New Schedule</h3>
          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Schedule name"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <input
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            className="w-full border border-gray-300 rounded px-3 py-2 text-sm"
          />
          <div>
            <label className="block text-xs text-gray-500 mb-1">Targets (one per line — IPs, CIDRs, or domains)</label>
            <textarea
              value={form.targets}
              onChange={e => setForm(f => ({ ...f, targets: e.target.value }))}
              placeholder={"192.168.1.0/24\nexample.com"}
              rows={3}
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-500 mb-1">Cron expression</label>
            <div className="flex gap-2 items-center flex-wrap mb-1">
              {CRON_PRESETS.map(p => (
                <button
                  key={p.value}
                  onClick={() => setForm(f => ({ ...f, cron_expr: p.value }))}
                  className={`text-xs px-2 py-1 rounded border transition-colors ${form.cron_expr === p.value ? 'border-blue-500 bg-blue-50 text-blue-700' : 'border-gray-200 text-gray-500 hover:border-gray-400'}`}
                >
                  {p.label}
                </button>
              ))}
            </div>
            <input
              value={form.cron_expr}
              onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))}
              placeholder="0 2 * * *"
              className="w-full border border-gray-300 rounded px-3 py-2 text-sm font-mono"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => createMut.mutate()}
              disabled={!form.name || !form.targets.trim() || createMut.isPending}
              className="px-3 py-1.5 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 disabled:opacity-50"
            >
              {createMut.isPending ? 'Creating...' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="px-3 py-1.5 text-gray-600 text-sm">Cancel</button>
          </div>
          {createMut.isError && (
            <p className="text-red-500 text-xs">{(createMut.error as any)?.response?.data?.detail || 'Error creating schedule'}</p>
          )}
        </div>
      )}

      {isLoading ? (
        <div className="text-gray-500 text-sm">Loading...</div>
      ) : schedules.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <Calendar size={40} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">No scheduled scans yet</p>
        </div>
      ) : (
        <div className="space-y-3">
          {schedules.map(s => (
            <ScheduleCard
              key={s.id}
              schedule={s}
              onToggle={() => toggleMut.mutate({ id: s.id, enabled: !s.enabled })}
              onDelete={() => deleteMut.mutate(s.id)}
              fmtDate={fmtDate}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function ScheduleCard({ schedule: s, onToggle, onDelete, fmtDate }: {
  schedule: Schedule
  onToggle: () => void
  onDelete: () => void
  fmtDate: (d: string | null) => string
}) {
  return (
    <div className={`bg-white border rounded-lg p-4 ${s.enabled ? 'border-gray-200' : 'border-gray-100 opacity-70'}`}>
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Clock size={14} className="text-blue-500 flex-shrink-0" />
            <span className="font-medium text-sm">{s.name}</span>
            <span className={`text-xs px-1.5 py-0.5 rounded font-mono ${s.enabled ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
              {s.enabled ? 'enabled' : 'paused'}
            </span>
          </div>
          {s.description && <p className="text-xs text-gray-500 mb-2">{s.description}</p>}
          <div className="font-mono text-xs bg-gray-50 px-2 py-1 rounded inline-block text-gray-700 mb-2">
            {s.cron_expr}
          </div>
          <div className="flex flex-wrap gap-1 mb-2">
            {s.targets.slice(0, 6).map((t, i) => (
              <span key={i} className="text-xs bg-blue-50 text-blue-700 px-1.5 py-0.5 rounded font-mono">{t}</span>
            ))}
            {s.targets.length > 6 && <span className="text-xs text-gray-400">+{s.targets.length - 6} more</span>}
          </div>
          <div className="flex gap-4 text-xs text-gray-400">
            <span>Next: <span className="text-gray-600">{fmtDate(s.next_run)}</span></span>
            <span>Last: <span className="text-gray-600">{fmtDate(s.last_run)}</span></span>
          </div>
        </div>
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={onToggle}
            className={`p-1 rounded ${s.enabled ? 'text-green-600 hover:text-gray-500' : 'text-gray-400 hover:text-green-600'}`}
            title={s.enabled ? 'Pause' : 'Enable'}
          >
            {s.enabled ? <ToggleRight size={20} /> : <ToggleLeft size={20} />}
          </button>
          <button
            onClick={onDelete}
            className="p-1 text-gray-400 hover:text-red-500 rounded"
            title="Delete"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>
    </div>
  )
}
