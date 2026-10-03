export interface TestingWindowValue {
  timezone: string
  days: number[]
  start: string
  end: string
  not_before?: string | null
  not_after?: string | null
}

const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

/** All IANA zones where the browser can list them (Intl.supportedValuesOf). */
function timeZones(current?: string): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] }
  const zones = intl.supportedValuesOf ? intl.supportedValuesOf('timeZone') : ['UTC']
  return current && !zones.includes(current) ? [current, ...zones] : zones
}

export function defaultWindow(): TestingWindowValue {
  return { timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC', days: [0, 1, 2, 3, 4], start: '09:00', end: '17:00', not_before: null, not_after: null }
}

/** Optional rules of engagement: when this scan may send traffic. */
export default function TestingWindowEditor({ value, onChange }: { value: TestingWindowValue | null; onChange: (v: TestingWindowValue | null) => void }) {
  const zones = timeZones(value?.timezone)
  const set = (patch: Partial<TestingWindowValue>) => value && onChange({ ...value, ...patch })
  return (
    <div className="testing-window">
      <label className="testing-window-toggle">
        <input type="checkbox" checked={value !== null} onChange={e => onChange(e.target.checked ? defaultWindow() : null)} />
        <span><strong>Restrict when this scan may run</strong> (agreed testing window)</span>
      </label>
      {value && (
        <>
          <div className="testing-window-days" role="group" aria-label="Allowed days">
            {DAYS.map((d, i) => (
              <button key={d} type="button" aria-pressed={value.days.includes(i)} className={value.days.includes(i) ? 'is-active' : ''}
                      onClick={() => set({ days: value.days.includes(i) ? value.days.filter(x => x !== i) : [...value.days, i].sort() })}>{d}</button>
            ))}
          </div>
          <div className="testing-window-row">
            <label>From<input className="input" type="time" value={value.start} onChange={e => set({ start: e.target.value })} /></label>
            <label>Until<input className="input" type="time" value={value.end === '24:00' ? '23:59' : value.end} onChange={e => set({ end: e.target.value })} /></label>
            <label style={{ flex: 2 }}>Time zone
              <select className="select-field" value={value.timezone} onChange={e => set({ timezone: e.target.value })}>
                {zones.map(z => <option key={z} value={z}>{z}</option>)}
              </select>
            </label>
          </div>
          <div className="testing-window-row">
            <label>First testing day<input className="input" type="date" value={value.not_before ?? ''} onChange={e => set({ not_before: e.target.value || null })} /></label>
            <label>Last testing day<input className="input" type="date" value={value.not_after ?? ''} onChange={e => set({ not_after: e.target.value || null })} /></label>
          </div>
          <p className="testing-window-note">
            Outside this window ScanR refuses to launch, schedules skip, and a running scan pauses by itself until the window
            reopens. A time range like 22:00 until 06:00 runs overnight. Every start, pause and resume is recorded in the scan's
            activity log.
          </p>
          {value.days.length === 0 && <p className="testing-window-error">Choose at least one day.</p>}
        </>
      )}
    </div>
  )
}
