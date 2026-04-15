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
    <div className="space-y-4">
      {!hidePortRange && (
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1.5">Port Range</label>
        <select
          value={isCustomPort ? '__custom__' : config.port_range}
          onChange={handlePortRange}
          className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm"
        >
          {PORT_RANGES.map(r => <option key={r.value} value={r.value}>{r.label}</option>)}
          <option value="__custom__" disabled={!isCustomPort}>
            {isCustomPort ? `Custom: ${config.port_range}` : 'Custom (set via template)'}
          </option>
        </select>
        {isCustomPort && (
          <p className="mt-1 text-xs text-gray-400">Custom range from template: <code className="font-mono">{config.port_range}</code> — pick a preset above to override</p>
        )}
      </div>
      )}
      <div>
        <div className="flex items-center justify-between mb-2">
          <label className="text-xs font-medium text-gray-600">Plugin Categories</label>
          <button
            type="button"
            onClick={() => onChange({ ...config, categories: allSelected ? [] : ALL_CATEGORIES.map(x => x.id) })}
            className="text-xs text-blue-600 hover:underline"
          >
            {allSelected ? 'Deselect all' : 'Select all'}
          </button>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {ALL_CATEGORIES.map(cat => {
            const on = config.categories.includes(cat.id)
            return (
              <button
                key={cat.id}
                type="button"
                onClick={() => toggleCat(cat.id)}
                className={`flex items-start gap-2 p-2.5 rounded-lg border text-left transition-colors ${
                  on ? 'border-blue-300 bg-blue-50' : 'border-gray-200 bg-white hover:border-gray-300'
                }`}
              >
                <span className={`mt-0.5 w-4 h-4 flex-shrink-0 rounded border flex items-center justify-center ${
                  on ? 'bg-blue-600 border-blue-600' : 'border-gray-300'
                }`}>
                  {on && <Check size={10} className="text-white" />}
                </span>
                <div>
                  <div className="text-xs font-medium text-gray-800">{cat.label}</div>
                  <div className="text-xs text-gray-400 leading-tight mt-0.5">{cat.desc}</div>
                </div>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
