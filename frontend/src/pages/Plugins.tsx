import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { pluginsApi, type Plugin } from '@/api/plugins'
import { SevTag } from '@/components/ui'
import './ConfigCatalog.css'

const CATEGORY_LABEL: Record<string, string> = { ssl_tls: 'SSL/TLS', cve: 'CVE', ssh: 'SSH' }
const categoryLabel = (cat: string) =>
  CATEGORY_LABEL[cat] ?? cat.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())

export default function Plugins() {
  const qc = useQueryClient()
  const { data: plugins = [] } = useQuery({ queryKey: ['plugins'], queryFn: pluginsApi.list })
  const { data: health = [] } = useQuery({ queryKey: ['plugins-health'], queryFn: () => pluginsApi.health() })
  const [activeCategory, setActiveCategory] = useState<string | null>(null)
  const healthByPlugin = new Map(health.map(h => [h.plugin_id, h]))

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => pluginsApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['plugins'] }),
  })

  const grouped = plugins.reduce<Record<string, Plugin[]>>((acc, p) => {
    acc[p.category] ??= []
    acc[p.category].push(p)
    return acc
  }, {})

  const catOrder = ['web', 'ssl_tls', 'services', 'network', 'auth', 'nuclei']
  const sortedCats = [
    ...catOrder.filter(c => grouped[c]),
    ...Object.keys(grouped).filter(c => !catOrder.includes(c)).sort(),
  ]

  const selectedCat = activeCategory ?? sortedCats[0] ?? null
  const visiblePlugins = selectedCat ? (grouped[selectedCat] ?? []) : []
  const enabledCount = (selectedCat ? visiblePlugins : plugins).filter(p => p.enabled).length

  return (
    <div className="catalog-page plugins-page">
      <header className="catalog-header">
        <div><h1>Plugins</h1></div>
        <div className="catalog-header-stat"><strong>{plugins.length}</strong><span>AVAILABLE</span></div>
      </header>

      {plugins.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)', fontSize: 13 }}>
          No plugins found
        </div>
      ) : (
        <div className="plugins-shell" style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          {/* Category sidebar */}
          <nav className="plugins-categories" aria-label="Plugin categories">
            {sortedCats.map(cat => {
              const active = cat === selectedCat
              const count = grouped[cat]?.length ?? 0
              const enabledCnt = (grouped[cat] ?? []).filter(p => p.enabled).length
              return (
                <button
                  key={cat}
                  className="plugins-category"
                  aria-current={active ? "page" : undefined}
                  onClick={() => setActiveCategory(cat)}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    width: '100%', padding: '7px 10px',
                    background: active ? 'var(--bg-3)' : 'transparent',
                    border: 'none', cursor: 'pointer', textAlign: 'left',
                    color: active ? 'var(--text-0)' : 'var(--text-2)',
                    marginBottom: 2,
                  }}
                >
                  <span style={{ fontSize: 12, fontWeight: active ? 600 : 400 }}>
                    {categoryLabel(cat)}
                  </span>
                  <span className="mono" style={{
                    fontSize: 10, padding: '1px 5px',
                    background: active ? 'var(--accent-soft)' : 'var(--bg-3)',
                    color: active ? 'var(--accent)' : 'var(--text-3)',
                  }}>
                    {enabledCnt}/{count}
                  </span>
                </button>
              )
            })}
          </nav>

          {/* Plugin list */}
          <div className="plugins-list" style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                <span style={{ fontWeight: 500, color: 'var(--text-1)' }}>
                  {selectedCat && categoryLabel(selectedCat)}
                </span>
                {' · '}{enabledCount} of {visiblePlugins.length} enabled
              </div>
            </div>

            <div className="plugins-rows" style={{ padding: 0, overflow: 'hidden' }}>
              {visiblePlugins.map((p, i) => (
                <div
                  key={p.id}
                  className="plugins-row"
                  style={{
                    display: 'flex', alignItems: 'center', padding: '10px 14px', gap: 12,
                    borderBottom: i < visiblePlugins.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                    opacity: p.enabled ? 1 : 0.55,
                  }}
                >
                  {/* Toggle */}
                  <button
                    role="switch"
                    className="plugins-toggle"
                    aria-label={`${p.enabled ? "Disable" : "Enable"} ${p.name}`}
                    aria-checked={p.enabled}
                    onClick={() => toggleMut.mutate({ id: p.id, enabled: !p.enabled })}
                    style={{
                      width: 36, height: 20,  border: 'none', cursor: 'pointer',
                      background: p.enabled ? 'var(--accent)' : 'var(--bg-3)',
                      position: 'relative', flexShrink: 0, transition: 'background 0.15s',
                    }}
                  >
                    <span style={{
                      position: 'absolute', top: 3, left: p.enabled ? 19 : 3,
                      width: 14, height: 14,  background: '#fff',
                      transition: 'left 0.15s',
                    }} />
                  </button>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
                      <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-0)' }}>{p.name}</span>
                      <SevTag severity={p.default_severity} />
                      {p.requires_auth && (
                        <span className="mono" style={{ fontSize: 10, color: 'var(--accent-2)', background: 'var(--accent-soft)', padding: '1px 5px', borderRadius: 4 }}>
                          auth
                        </span>
                      )}
                    </div>
                    <div className="mono dimmer" style={{ fontSize: 10 }}>{p.id}</div>
                  </div>

                  {healthByPlugin.has(p.id) && (
                    <div
                      className="mono"
                      style={{
                        display: 'flex',
                        gap: 6,
                        alignItems: 'center',
                        color: 'var(--text-3)',
                        fontSize: 10,
                        flexShrink: 0,
                      }}
                      title="Runtime health across recorded scans"
                    >
                      <span>{healthByPlugin.get(p.id)!.total_runs} runs</span>
                      <span style={{ color: 'var(--ok)' }}>{healthByPlugin.get(p.id)!.success_count} ok</span>
                      {healthByPlugin.get(p.id)!.timeout_count > 0 && (
                        <span style={{ color: 'var(--sev-medium)' }}>{healthByPlugin.get(p.id)!.timeout_count} timeout</span>
                      )}
                      {healthByPlugin.get(p.id)!.error_count > 0 && (
                        <span style={{ color: 'var(--sev-high)' }}>{healthByPlugin.get(p.id)!.error_count} error</span>
                      )}
                      <span>{healthByPlugin.get(p.id)!.avg_duration_ms}ms avg</span>
                    </div>
                  )}
                </div>
              ))}

              {visiblePlugins.length === 0 && (
                <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-3)', fontSize: 12 }}>
                  No plugins in this category
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
