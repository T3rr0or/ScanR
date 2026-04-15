import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { pluginsApi, type Plugin } from '@/api/plugins'

export default function Plugins() {
  const qc = useQueryClient()
  const { data: plugins = [] } = useQuery({ queryKey: ['plugins'], queryFn: pluginsApi.list })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => pluginsApi.update(id, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['plugins'] }),
  })

  const grouped = plugins.reduce<Record<string, Plugin[]>>((acc, p) => {
    acc[p.category] ??= []
    acc[p.category].push(p)
    return acc
  }, {})

  return (
    <div className="p-8">
      <h1 className="text-2xl font-bold mb-6">Plugins ({plugins.length})</h1>
      <div className="space-y-6">
        {Object.entries(grouped).map(([cat, catPlugins]) => (
          <div key={cat}>
            <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-2">{cat.replace('_', ' ')}</h2>
            <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
              {catPlugins.map((p, i) => (
                <div key={p.id} className={`flex items-center px-4 py-3 ${i < catPlugins.length - 1 ? 'border-b border-gray-100' : ''}`}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{p.name}</span>
                      <SevDot sev={p.default_severity} />
                      {p.requires_auth && <span className="text-xs bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">auth</span>}
                    </div>
                    <p className="text-xs text-gray-400 truncate">{p.id}</p>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer ml-4">
                    <input type="checkbox" checked={p.enabled} onChange={() => toggleMut.mutate({ id: p.id, enabled: !p.enabled })} className="sr-only peer" />
                    <div className="w-9 h-5 bg-gray-200 peer-checked:bg-blue-600 rounded-full transition-colors after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-4" />
                  </label>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function SevDot({ sev }: { sev: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500', info: 'bg-blue-400'
  }
  return <span className={`w-2 h-2 rounded-full inline-block ${colors[sev] ?? 'bg-gray-400'}`} title={sev} />
}
