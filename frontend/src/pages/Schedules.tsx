import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Clock, Plus, Trash2, ToggleLeft, ToggleRight, Calendar } from 'lucide-react'
import { schedulesApi, type Schedule } from '@/api/schedules'

const CRON_PRESETS = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Daily 2am', value: '0 2 * * *' },
  { label: 'Mon 2am', value: '0 2 * * 1' },
  { label: 'Sun midnight', value: '0 0 * * 0' },
  { label: 'Every 6h', value: '0 */6 * * *' },
  { label: '1st of month', value: '0 2 1 * *' },
]

export default function Schedules() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({
    name: '', description: '', targets: '', cron_expr: '0 2 * * *', scan_profile_json: '{}', enabled: true,
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
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => schedulesApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['schedules'] }),
  })

  function fmtDate(d: string | null) {
    if (!d) return '—'
    return new Date(d).toLocaleString()
  }

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
        <button onClick={() => setShowCreate(true)} className="btn btn-primary btn-sm">
          <Plus size={13} /> New Schedule
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="panel" style={{ marginBottom: 20, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', marginBottom: 12 }}>New Schedule</div>

          <input
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Schedule name"
            className="input"
            style={{ marginBottom: 8 }}
          />
          <input
            value={form.description}
            onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            placeholder="Description (optional)"
            className="input"
            style={{ marginBottom: 10 }}
          />

          <label className="label" style={{ marginBottom: 4 }}>Targets (one per line — IPs, CIDRs, or domains)</label>
          <textarea
            value={form.targets}
            onChange={e => setForm(f => ({ ...f, targets: e.target.value }))}
            placeholder={"192.168.1.0/24\nexample.com"}
            rows={3}
            className="textarea"
            style={{ marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 12 }}
          />

          <label className="label" style={{ marginBottom: 6 }}>Cron expression</label>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
            {CRON_PRESETS.map(p => (
              <button
                key={p.value}
                onClick={() => setForm(f => ({ ...f, cron_expr: p.value }))}
                className={`btn btn-sm ${form.cron_expr === p.value ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: 11 }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <input
            value={form.cron_expr}
            onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))}
            placeholder="0 2 * * *"
            className="input"
            style={{ fontFamily: 'var(--font-mono)', fontSize: 12, marginBottom: 12 }}
          />

          <div style={{ display: 'flex', gap: 8 }}>
            <button
              onClick={() => createMut.mutate()}
              disabled={!form.name || !form.targets.trim() || createMut.isPending}
              className="btn btn-primary btn-sm"
            >
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setShowCreate(false)} className="btn btn-ghost btn-sm">Cancel</button>
          </div>

          {createMut.isError && (
            <p style={{ color: 'var(--sev-high)', fontSize: 11, marginTop: 8 }}>
              {(createMut.error as any)?.response?.data?.detail || 'Error creating schedule'}
            </p>
          )}
        </div>
      )}

      {/* List */}
      {isLoading ? (
        <div className="dimmer" style={{ fontSize: 13, padding: '20px 0' }}>Loading…</div>
      ) : schedules.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)' }}>
          <Calendar size={36} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
          <p style={{ fontSize: 13 }}>No scheduled scans yet</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {schedules.map(s => (
            <ScheduleCard key={s.id} schedule={s}
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
    <div className="panel" style={{ padding: 14, opacity: s.enabled ? 1 : 0.6 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <Clock size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
            <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)' }}>{s.name}</span>
            <span className={`pill ${s.enabled ? 'pill-completed' : 'pill-cancelled'}`} style={{ fontSize: 10 }}>
              {s.enabled ? 'enabled' : 'paused'}
            </span>
          </div>
          {s.description && <p style={{ fontSize: 11.5, color: 'var(--text-2)', marginBottom: 8 }}>{s.description}</p>}

          <div className="mono" style={{ fontSize: 11, background: 'var(--bg-2)', display: 'inline-block', padding: '3px 8px', borderRadius: 4, color: 'var(--text-1)', marginBottom: 8 }}>
            {s.cron_expr}
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 8 }}>
            {s.targets.slice(0, 6).map((t, i) => (
              <span key={i} className="mono" style={{ fontSize: 10, background: 'var(--accent-soft)', color: 'var(--accent)', padding: '2px 6px', borderRadius: 4 }}>{t}</span>
            ))}
            {s.targets.length > 6 && <span className="dimmer" style={{ fontSize: 10 }}>+{s.targets.length - 6} more</span>}
          </div>

          <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-3)' }}>
            <span>Next: <span style={{ color: 'var(--text-2)' }}>{fmtDate(s.next_run)}</span></span>
            <span>Last: <span style={{ color: 'var(--text-2)' }}>{fmtDate(s.last_run)}</span></span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
          <button onClick={onToggle} className="btn btn-ghost btn-icon btn-sm" title={s.enabled ? 'Pause' : 'Enable'}>
            {s.enabled
              ? <ToggleRight size={18} style={{ color: 'var(--ok)' }} />
              : <ToggleLeft size={18} style={{ color: 'var(--text-3)' }} />
            }
          </button>
          <button onClick={onDelete} className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: 'var(--sev-high)' }}>
            <Trash2 size={14} />
          </button>
        </div>
      </div>
    </div>
  )
}
