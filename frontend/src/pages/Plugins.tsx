import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Puzzle } from 'lucide-react'
import { pluginsApi, type Plugin } from '@/api/plugins'
import { SevTag } from '@/components/ui'

export default function Plugins() {
  const qc = useQueryClient()
  const { data: plugins = [] } = useQuery({ queryKey: ['plugins'], queryFn: pluginsApi.list })
  const [activeCategory, setActiveCategory] = useState<string | null>(null)

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
    <div className="page-pad" style={{ maxWidth: 1000 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <Puzzle size={18} style={{ color: 'var(--accent)' }} />
        <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-0)' }}>Plugins</h1>
        <span className="mono dimmer" style={{ fontSize: 11 }}>({plugins.length} total)</span>
      </div>

      {plugins.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '48px 20px', color: 'var(--text-3)', fontSize: 13 }}>
          <Puzzle size={32} style={{ margin: '0 auto 12px', opacity: 0.3 }} />
          No plugins found
        </div>
      ) : (
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          {/* Category sidebar */}
          <div className="panel" style={{ width: 180, flexShrink: 0, padding: 6, overflow: 'hidden' }}>
            {sortedCats.map(cat => {
              const active = cat === selectedCat
              const count = grouped[cat]?.length ?? 0
              const enabledCnt = (grouped[cat] ?? []).filter(p => p.enabled).length
              return (
                <button
                  key={cat}
                  onClick={() => setActiveCategory(cat)}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    width: '100%', padding: '7px 10px', borderRadius: 6,
                    background: active ? 'var(--bg-3)' : 'transparent',
                    border: 'none', cursor: 'pointer', textAlign: 'left',
                    color: active ? 'var(--text-0)' : 'var(--text-2)',
                    marginBottom: 2,
                  }}
                >
                  <span style={{ fontSize: 12, fontWeight: active ? 600 : 400, textTransform: 'capitalize' }}>
                    {cat.replace(/_/g, ' ')}
                  </span>
                  <span className="mono" style={{
                    fontSize: 10, padding: '1px 5px', borderRadius: 4,
                    background: active ? 'var(--accent-soft)' : 'var(--bg-3)',
                    color: active ? 'var(--accent)' : 'var(--text-3)',
                  }}>
                    {enabledCnt}/{count}
                  </span>
                </button>
              )
            })}
          </div>

          {/* Plugin list */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
                <span style={{ textTransform: 'capitalize', fontWeight: 500, color: 'var(--text-1)' }}>
                  {selectedCat?.replace(/_/g, ' ')}
                </span>
                {' · '}{enabledCount} of {visiblePlugins.length} enabled
              </div>
            </div>

            <div className="panel" style={{ padding: 0, overflow: 'hidden' }}>
              {visiblePlugins.map((p, i) => (
                <div
                  key={p.id}
                  style={{
                    display: 'flex', alignItems: 'center', padding: '10px 14px', gap: 12,
                    borderBottom: i < visiblePlugins.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                    opacity: p.enabled ? 1 : 0.55,
                  }}
                >
                  {/* Toggle */}
                  <button
                    role="switch"
                    aria-checked={p.enabled}
                    onClick={() => toggleMut.mutate({ id: p.id, enabled: !p.enabled })}
                    style={{
                      width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                      background: p.enabled ? 'var(--accent)' : 'var(--bg-3)',
                      position: 'relative', flexShrink: 0, transition: 'background 0.15s',
                    }}
                  >
                    <span style={{
                      position: 'absolute', top: 3, left: p.enabled ? 19 : 3,
                      width: 14, height: 14, borderRadius: '50%', background: '#fff',
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
