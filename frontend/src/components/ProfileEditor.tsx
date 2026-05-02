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
  { value: '80,443,3000-3999,5000-5999,8000-9999,30000-32767', label: 'Internal web apps / NodePort — high app ports' },
]

export type ScanContextValue = 'internal' | 'external' | 'custom'
export type TargetTypeValue = 'auto' | 'ip' | 'cidr' | 'range' | 'hostname' | 'domain'
export type SafetyLevel = 'safe' | 'balanced' | 'aggressive'
export type DepthLevel = 'light' | 'balanced' | 'deep'
export type PerformanceProfile = 'conservative' | 'normal' | 'fast' | 'custom'

export interface ProfileConfig {
  scan_context: ScanContextValue
  target_type: TargetTypeValue
  safety_level: SafetyLevel
  depth_level: DepthLevel
  performance_profile: PerformanceProfile
  port_range: string
  categories: string[]
  discovery: {
    icmp: boolean
    tcp: boolean
    arp: boolean
    udp: boolean
    retries: number
    strategy: 'fast' | 'validated'
    assume_up: boolean
  }
  port_scanning: {
    scanner: 'tcp_connect' | 'syn' | 'udp'
    firewall_strategy: 'default' | 'skip_ping'
  }
  enumeration: {
    service_detection: boolean
    http_probing: boolean
    tls_checks: boolean
    security_headers: boolean
    screenshots: boolean
    nuclei: boolean
    directory_enum: boolean
    subdomain_enum: boolean
    dns_recon: boolean
  }
  performance: {
    max_concurrent_hosts: number
    max_concurrent_plugins: number
    timeout: number
    masscan_rate: number
    nuclei_rate: number
    max_hosts: number | null
    max_checks: number | null
  }
}

const DEFAULT_PROFILE: ProfileConfig = {
  scan_context: 'internal',
  target_type: 'auto',
  safety_level: 'balanced',
  depth_level: 'balanced',
  performance_profile: 'normal',
  port_range: 'top-1000',
  categories: ALL_CATEGORIES.map(x => x.id),
  discovery: {
    icmp: true,
    tcp: true,
    arp: true,
    udp: false,
    retries: 1,
    strategy: 'validated',
    assume_up: false,
  },
  port_scanning: {
    scanner: 'tcp_connect',
    firewall_strategy: 'default',
  },
  enumeration: {
    service_detection: true,
    http_probing: true,
    tls_checks: true,
    security_headers: true,
    screenshots: true,
    nuclei: true,
    directory_enum: false,
    subdomain_enum: false,
    dns_recon: false,
  },
  performance: {
    max_concurrent_hosts: 20,
    max_concurrent_plugins: 20,
    timeout: 60,
    masscan_rate: 10000,
    nuclei_rate: 25,
    max_hosts: null,
    max_checks: null,
  },
}

type ProfileConfigPatch = Omit<Partial<ProfileConfig>, 'discovery' | 'port_scanning' | 'enumeration' | 'performance'> & {
  discovery?: Partial<ProfileConfig['discovery']>
  port_scanning?: Partial<ProfileConfig['port_scanning']>
  enumeration?: Partial<ProfileConfig['enumeration']>
  performance?: Partial<ProfileConfig['performance']>
}

export function defaultProfileConfig(patch: ProfileConfigPatch = {}): ProfileConfig {
  return {
    ...DEFAULT_PROFILE,
    ...patch,
    discovery: { ...DEFAULT_PROFILE.discovery, ...(patch.discovery ?? {}) },
    port_scanning: { ...DEFAULT_PROFILE.port_scanning, ...(patch.port_scanning ?? {}) },
    enumeration: { ...DEFAULT_PROFILE.enumeration, ...(patch.enumeration ?? {}) },
    performance: { ...DEFAULT_PROFILE.performance, ...(patch.performance ?? {}) },
  }
}

export function configToJson(c: ProfileConfig): Record<string, unknown> {
  const all = ALL_CATEGORIES.map(x => x.id)
  const plugins = c.categories.length === all.length ? ['*'] : c.categories.map(cat => `${cat}.*`)
  const targetType = c.target_type === 'auto' ? undefined : c.target_type
  return {
    scan_context: c.scan_context,
    ...(targetType ? { target_type: targetType } : {}),
    safety_level: c.safety_level,
    depth_level: c.depth_level,
    performance_profile: c.performance_profile,
    port_range: c.port_range,
    plugins,
    discovery: c.discovery,
    port_scanning: c.port_scanning,
    enumeration: c.enumeration,
    performance: c.performance,
    external_recon: c.scan_context === 'external',
    subdomain_enum: c.enumeration.subdomain_enum,
    disable_masscan: c.scan_context === 'external' && targetType === 'domain',
    intrusive: c.safety_level === 'aggressive',
    masscan_rate: c.performance.masscan_rate,
    max_concurrent: c.performance.max_concurrent_hosts,
    timeout: c.performance.timeout,
  }
}

export function jsonToConfig(pj: Record<string, unknown> | null | undefined): ProfileConfig {
  const allIds = ALL_CATEGORIES.map(x => x.id)
  if (!pj) return defaultProfileConfig({ categories: allIds })
  const plugins = (pj.plugins as string[] | undefined) ?? ['*']
  const categories = plugins.includes('*')
    ? allIds
    : allIds.filter(cat => plugins.some(p => p === `${cat}.*` || p === cat || p.startsWith(`${cat}.`)))
  const discovery = (pj.discovery ?? {}) as Partial<ProfileConfig['discovery']>
  const portScanning = (pj.port_scanning ?? {}) as Partial<ProfileConfig['port_scanning']>
  const enumeration = (pj.enumeration ?? {}) as Partial<ProfileConfig['enumeration']>
  const performance = (pj.performance ?? {}) as Partial<ProfileConfig['performance']>
  const rawContext = pj.scan_context ?? pj.target_mode ?? (pj.external_recon ? 'external' : undefined)
  const scanContext = rawContext === 'domain' || rawContext === 'bug_bounty'
    ? 'external'
    : rawContext as ProfileConfig['scan_context'] | undefined
  return defaultProfileConfig({
    scan_context: scanContext ?? DEFAULT_PROFILE.scan_context,
    target_type: (pj.target_type as ProfileConfig['target_type'] | undefined) ?? (pj.target_mode === 'domain' || pj.target_mode === 'bug_bounty' ? 'domain' : DEFAULT_PROFILE.target_type),
    safety_level: (pj.safety_level as ProfileConfig['safety_level']) ?? (pj.intrusive ? 'aggressive' : DEFAULT_PROFILE.safety_level),
    depth_level: (pj.depth_level as ProfileConfig['depth_level']) ?? DEFAULT_PROFILE.depth_level,
    performance_profile: (pj.performance_profile as ProfileConfig['performance_profile']) ?? DEFAULT_PROFILE.performance_profile,
    port_range: (pj.port_range as string) ?? DEFAULT_PROFILE.port_range,
    categories,
    discovery,
    port_scanning: portScanning,
    enumeration: {
      ...enumeration,
      subdomain_enum: Boolean(pj.subdomain_enum ?? enumeration.subdomain_enum ?? DEFAULT_PROFILE.enumeration.subdomain_enum),
      dns_recon: Boolean(enumeration.dns_recon ?? plugins.some(p => p === 'network.dns_recon' || p === 'network.*' || p === '*')),
    },
    performance: {
      ...performance,
      masscan_rate: Number(pj.masscan_rate ?? performance.masscan_rate ?? DEFAULT_PROFILE.performance.masscan_rate),
      max_concurrent_hosts: Number(pj.max_concurrent ?? performance.max_concurrent_hosts ?? DEFAULT_PROFILE.performance.max_concurrent_hosts),
      timeout: Number(pj.timeout ?? performance.timeout ?? DEFAULT_PROFILE.performance.timeout),
    },
  })
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
  const isDomain = config.target_type === 'domain'

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

  function setTargetType(target_type: ProfileConfig['target_type']) {
    const domain = target_type === 'domain'
    onChange({
      ...config,
      target_type,
      scan_context: domain && config.scan_context === 'internal' ? 'external' : config.scan_context,
      discovery: domain
        ? { ...config.discovery, icmp: false, tcp: true, arp: false, strategy: 'fast' }
        : config.discovery,
      enumeration: {
        ...config.enumeration,
        subdomain_enum: domain ? true : config.enumeration.subdomain_enum,
        dns_recon: domain ? true : config.enumeration.dns_recon,
      },
      categories: domain
        ? Array.from(new Set([...config.categories, 'network', 'web', 'ssl_tls']))
        : config.categories,
    })
  }

  function applyDepth(depth_level: ProfileConfig['depth_level']) {
    onChange({
      ...config,
      depth_level,
      port_range: depth_level === 'light'
        ? 'top-1000'
        : depth_level === 'deep'
          ? (config.scan_context === 'external' ? '80,443,8080,8443,8000,8001,8888,3000,5000,9000,9443,10443,32400' : 'top-10000')
          : config.port_range,
      enumeration: {
        ...config.enumeration,
        directory_enum: depth_level === 'deep' ? true : depth_level === 'light' ? false : config.enumeration.directory_enum,
        nuclei: depth_level === 'light' ? false : config.enumeration.nuclei,
      },
      performance: {
        ...config.performance,
        timeout: depth_level === 'deep' ? 120 : depth_level === 'light' ? 45 : config.performance.timeout,
      },
    })
  }

  function applyPerformance(performance_profile: ProfileConfig['performance_profile']) {
    const presets = {
      conservative: { max_concurrent_hosts: 8, max_concurrent_plugins: 10, timeout: 90, masscan_rate: 5000, nuclei_rate: 15 },
      normal: { max_concurrent_hosts: 20, max_concurrent_plugins: 20, timeout: 60, masscan_rate: 10000, nuclei_rate: 25 },
      fast: { max_concurrent_hosts: 40, max_concurrent_plugins: 30, timeout: 45, masscan_rate: 25000, nuclei_rate: 50 },
      custom: null,
    } as const
    onChange({
      ...config,
      performance_profile,
      performance: presets[performance_profile]
        ? { ...config.performance, ...presets[performance_profile] }
        : config.performance,
    })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <EditorGroup title="Context">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Scan context">
            <select
              className="select-field"
              value={config.scan_context}
              onChange={e => onChange({ ...config, scan_context: e.target.value as ProfileConfig['scan_context'] })}
            >
              <option value="internal">Internal - ARP/ICMP/internal protocols</option>
              <option value="external">External - TCP/DNS/web defaults</option>
              <option value="custom">Custom - neutral defaults</option>
            </select>
          </Field>
          <Field label="Target handling">
            <select
              className="select-field"
              value={config.target_type}
              onChange={e => setTargetType(e.target.value as ProfileConfig['target_type'])}
            >
              <option value="auto">Auto detect per line</option>
              <option value="domain">Domain - DNS/subdomains</option>
              <option value="hostname">Hostname</option>
              <option value="ip">IP address</option>
              <option value="cidr">CIDR subnet</option>
              <option value="range">IP range</option>
            </select>
          </Field>
        </div>
        <p className="mono" style={{ margin: 0, fontSize: 10.5, color: 'var(--text-3)' }}>
          Templates set defaults only. Users can still override these options when creating a scan.
        </p>
      </EditorGroup>

      {!hidePortRange && (
        <EditorGroup title="Ports">
          <Field label="Port range">
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
          </Field>
          {isCustomPort && (
            <p style={{ margin: 0, fontSize: 11, color: 'var(--text-3)' }}>
              Custom range from template: <code style={{ fontFamily: 'var(--font-mono)' }}>{config.port_range}</code> - pick a preset above to override
            </p>
          )}
          <Field label="Scanner">
            <select
              className="select-field"
              value={config.port_scanning.scanner}
              onChange={e => onChange({ ...config, port_scanning: { ...config.port_scanning, scanner: e.target.value as ProfileConfig['port_scanning']['scanner'] } })}
            >
              <option value="tcp_connect">TCP connect</option>
              <option value="syn">SYN / masscan where available</option>
              <option value="udp">UDP</option>
            </select>
          </Field>
        </EditorGroup>
      )}

      <EditorGroup title="Discovery">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Toggle label="ICMP" checked={config.discovery.icmp} onChange={icmp => onChange({ ...config, discovery: { ...config.discovery, icmp } })} />
          <Toggle label="TCP probes" checked={config.discovery.tcp} onChange={tcp => onChange({ ...config, discovery: { ...config.discovery, tcp } })} />
          <Toggle label="ARP (limited/local)" checked={config.discovery.arp} onChange={arp => onChange({ ...config, discovery: { ...config.discovery, arp } })} />
          <Toggle label="Assume up" checked={config.discovery.assume_up} onChange={assume_up => onChange({ ...config, discovery: { ...config.discovery, assume_up } })} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Field label="Discovery strategy">
            <select
              className="select-field"
              value={config.discovery.strategy}
              onChange={e => onChange({ ...config, discovery: { ...config.discovery, strategy: e.target.value as ProfileConfig['discovery']['strategy'] } })}
            >
              <option value="fast">Fast</option>
              <option value="validated">Validated</option>
            </select>
          </Field>
          <NumberField label="Retries" value={config.discovery.retries} onChange={retries => onChange({ ...config, discovery: { ...config.discovery, retries } })} />
        </div>
      </EditorGroup>

      <EditorGroup title="Enumeration">
        <Segmented value={config.depth_level} options={['light', 'balanced', 'deep']} onChange={depth => applyDepth(depth as ProfileConfig['depth_level'])} />
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
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <Toggle label="Service detection" checked={config.enumeration.service_detection} onChange={service_detection => onChange({ ...config, enumeration: { ...config.enumeration, service_detection } })} />
          <Toggle label="HTTP probing" checked={config.enumeration.http_probing} onChange={http_probing => onChange({ ...config, enumeration: { ...config.enumeration, http_probing } })} />
          <Toggle label="TLS checks" checked={config.enumeration.tls_checks} onChange={tls_checks => onChange({ ...config, enumeration: { ...config.enumeration, tls_checks } })} />
          <Toggle label="Security headers" checked={config.enumeration.security_headers} onChange={security_headers => onChange({ ...config, enumeration: { ...config.enumeration, security_headers } })} />
          <Toggle label="Screenshots" checked={config.enumeration.screenshots} onChange={screenshots => onChange({ ...config, enumeration: { ...config.enumeration, screenshots } })} />
          <Toggle label="Nuclei" checked={config.enumeration.nuclei} onChange={nuclei => onChange({ ...config, enumeration: { ...config.enumeration, nuclei } })} />
          <Toggle label="Directory/file enum" checked={config.enumeration.directory_enum} onChange={directory_enum => onChange({ ...config, enumeration: { ...config.enumeration, directory_enum } })} />
          <Toggle label="Subdomain enum" checked={config.enumeration.subdomain_enum || isDomain} onChange={subdomain_enum => onChange({ ...config, enumeration: { ...config.enumeration, subdomain_enum } })} />
          <Toggle label="DNS recon" checked={config.enumeration.dns_recon || isDomain} onChange={dns_recon => onChange({ ...config, enumeration: { ...config.enumeration, dns_recon } })} />
        </div>
      </EditorGroup>

      <EditorGroup title="Safety & Performance">
        <Field label="Safety">
          <Segmented value={config.safety_level} options={['safe', 'balanced', 'aggressive']} onChange={safety_level => onChange({ ...config, safety_level: safety_level as ProfileConfig['safety_level'] })} />
        </Field>
        <Field label="Performance">
          <Segmented value={config.performance_profile} options={['conservative', 'normal', 'fast', 'custom']} onChange={performance => applyPerformance(performance as ProfileConfig['performance_profile'])} />
        </Field>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
          <NumberField label="Hosts" value={config.performance.max_concurrent_hosts} onChange={max_concurrent_hosts => onChange({ ...config, performance: { ...config.performance, max_concurrent_hosts } })} />
          <NumberField label="Plugins" value={config.performance.max_concurrent_plugins} onChange={max_concurrent_plugins => onChange({ ...config, performance: { ...config.performance, max_concurrent_plugins } })} />
          <NumberField label="Timeout" value={config.performance.timeout} onChange={timeout => onChange({ ...config, performance: { ...config.performance, timeout } })} />
          <NumberField label="Masscan rate" value={config.performance.masscan_rate} onChange={masscan_rate => onChange({ ...config, performance: { ...config.performance, masscan_rate } })} />
          <NumberField label="Nuclei rate" value={config.performance.nuclei_rate} onChange={nuclei_rate => onChange({ ...config, performance: { ...config.performance, nuclei_rate } })} />
        </div>
      </EditorGroup>
    </div>
  )
}

function EditorGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg-2)', padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="label" style={{ margin: 0 }}>{title}</div>
      {children}
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="label" style={{ marginBottom: 6 }}>{label}</label>
      {children}
    </div>
  )
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return (
    <label style={{ display: 'flex', alignItems: 'center', gap: 7, cursor: 'pointer', fontSize: 12, color: 'var(--text-1)' }}>
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)} style={{ accentColor: 'var(--accent)' }} />
      {label}
    </label>
  )
}

function Segmented({ value, options, onChange }: { value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
      {options.map(option => (
        <button key={option} type="button" className={`btn btn-sm ${value === option ? 'btn-primary' : 'btn-ghost'}`} onClick={() => onChange(option)}>
          {option}
        </button>
      ))}
    </div>
  )
}

function NumberField({ label, value, onChange }: { label: string; value: number; onChange: (value: number) => void }) {
  return (
    <Field label={label}>
      <input className="input" type="number" min={0} value={value} onChange={e => onChange(Number(e.target.value))} />
    </Field>
  )
}
