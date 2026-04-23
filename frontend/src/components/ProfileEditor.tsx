import { Check } from 'lucide-react'

export const ALL_CATEGORIES = [
  { id: 'network',  label: 'Network',  desc: 'Port inventory, ICMP' },
  { id: 'web',      label: 'Web',      desc: 'Headers, CORS, redirects, sensitive files, dir brute-force' },
  { id: 'ssl_tls',  label: 'SSL/TLS',  desc: 'Certs, ciphers, protocols, Heartbleed, POODLE' },
  { id: 'services', label: 'Services', desc: 'FTP, SMTP, RDP, Redis, MongoDB, Docker, Kubernetes' },
  { id: 'ssh',      label: 'SSH',      desc: 'Algorithms, version check, default credentials' },
  { id: 'cve',      label: 'CVE',      desc: 'Match service versions against NVD CVE database' },
  { id: 'nuclei',   label: 'Nuclei',   desc: 'Template-based CVE & misconfiguration scanner' },
]

export const PORT_RANGES = [
  { value: 'top-1000',  label: 'Top 1000 ports — fast initial scan' },
  { value: 'top-10000', label: 'Top 10000 ports — standard coverage' },
  { value: '1-65535',   label: 'All 65535 ports — thorough but slow' },
  { value: '80,443,8080,8443,8000,8888,3000,5000,9000', label: 'Web ports only' },
]

export interface ProfileConfig { port_range: string; categories: string[] }

export function configToJson(c: ProfileConfig): Record<string, unknown> {
  const all = ALL_CATEGORIES.map(x => x.id)
  const plugins = c.categories.length === all.length ? ['*'] : c.categories.map(cat => `${cat}.*`)
  return { port_range: c.port_range, plugins }
}

export function jsonToConfig(pj: Record<string, unknown> | null | undefined): ProfileConfig {
  const allIds = ALL_CATEGORIES.map(x => x.id)
  if (!pj) return { port_range: 'top-1000', categories: allIds }
  const plugins = (pj.plugins as string[] | undefined) ?? ['*']
  const categories = plugins.includes('*')
    ? allIds
    : allIds.filter(cat => plugins.some(p => p === `${cat}.*` || p === cat || p.startsWith(`${cat}.`)))
  return { port_range: (pj.port_range as string) ?? 'top-1000', categories }
}

export function ProfileEditor({
  config,
  onChange,
  hidePortRange = false,
}: {
  config: ProfileConfig
  onChange: (c: ProfileConfig) => void
  hidePortRange?: boolean
}) {
  const isCustomPort = !PORT_RANGES.find(r => r.value === config.port_range)
  const allSelected = config.categories.length === ALL_CATEGORIES.length

  function toggleCat(id: string) {
    const next = config.categories.includes(id)
      ? config.categories.filter(c => c !== id)
      : [...config.categories, id]
    onChange({ ...config, categories: next })
  }

  function handlePortRange(e: React.ChangeEvent<HTMLSelectElement>) {
    const val = e.target.value
    if (val === '__custom__') return
    onChange({ ...config, port_range: val })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {!hidePortRange && (
        <div>
          <label className="label" style={{ marginBottom: 6 }}>Port Range</label>
          <select
            value={isCustomPort ? '__custom__' : config.port_range}
            onChange={handlePortRange}
            className="select-field"
          >
            {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
            <option value="__custom__" disabled={!isCustomPort}>
              {isCustomPort ? `Custom: ${config.port_range}` : 'Custom (set via template)'}
            </option>
          </select>
          {isCustomPort && (
            <p style={{ marginTop: 4, fontSize: 11, color: 'var(--text-3)' }}>
              Custom range from template: <code style={{ fontFamily: 'var(--font-mono)' }}>{config.port_range}</code> — pick a preset above to override
            </p>
          )}
        </div>
      )}

      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <span className="label">Plugin Categories</span>
          <button
            type="button"
            onClick={() => onChange({ ...config, categories: allSelected ? [] : ALL_CATEGORIES.map(x => x.id) })}
            style={{ fontSize: 11, color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer' }}
          >
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {ALL_CATEGORIES.map(cat => {
            const on = config.categories.includes(cat.id)
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => toggleCat(cat.id)}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 10,
                  padding: '10px 12px', borderRadius: 8, border: `1px solid ${on ? 'var(--accent)' : 'var(--border)'}`,
                  background: on ? 'var(--accent-soft)' : 'var(--bg-2)',
                  textAlign: 'left', cursor: 'pointer', transition: 'border-color 0.12s, background 0.12s',
                }}
              >
                <span style={{
                  marginTop: 1, width: 16, height: 16, flexShrink: 0, borderRadius: 4,
                  border: `1.5px solid ${on ? 'var(--accent)' : 'var(--border)'}`,
                  background: on ? 'var(--accent)' : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'background 0.12s, border-color 0.12s',
                }}>
                  {on && <Check size={10} color="oklch(0.14 0.01 255)" strokeWidth={3} />}
                </span>
                <div>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-0)', marginBottom: 2 }}>{cat.label}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-3)', lineHeight: 1.4 }}>{cat.desc}</div>
                </div>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
