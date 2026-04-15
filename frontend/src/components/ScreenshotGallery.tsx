import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, X } from 'lucide-react'
import { screenshotsApi, type Screenshot } from '@/api/screenshots'

interface Props {
  scanId: string
}

function statusColor(code: number | null) {
  if (!code) return 'bg-gray-100 text-gray-500'
  if (code < 300) return 'bg-green-100 text-green-700'
  if (code < 400) return 'bg-yellow-100 text-yellow-700'
  return 'bg-red-100 text-red-700'
}

export default function ScreenshotGallery({ scanId }: Props) {
  const { data: shots = [], isLoading } = useQuery({
    queryKey: ['screenshots', scanId],
    queryFn: () => screenshotsApi.list(scanId),
    refetchInterval: 10_000,
  })

  const [lightbox, setLightbox] = useState<Screenshot | null>(null)

  if (isLoading) {
    return <div className="text-gray-500 text-sm p-4">Loading screenshots...</div>
  }

  if (shots.length === 0) {
    return (
      <div className="text-gray-600 text-sm p-8 text-center">
        No screenshots captured yet.
        <div className="text-xs text-gray-500 mt-1">
          Enable the <span className="font-mono">web.screenshot</span> plugin and run a scan with HTTP/HTTPS ports.
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="grid grid-cols-2 xl:grid-cols-3 gap-4 p-4">
        {shots.map(shot => (
          <div
            key={shot.id}
            className="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden cursor-pointer hover:border-gray-500 transition-colors group"
            onClick={() => setLightbox(shot)}
          >
            <div className="relative h-40 bg-gray-800 overflow-hidden">
              <AuthImage
                src={screenshotsApi.imageUrl(shot.id)}
                alt={shot.url}
                className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform duration-300"
              />
            </div>
            <div className="p-3">
              <div className="flex items-start gap-2">
                <div className="flex-1 min-w-0">
                  <div className="text-white text-xs font-medium truncate" title={shot.title ?? shot.url}>
                    {shot.title || shot.url}
                  </div>
                  <div className="text-gray-400 text-xs truncate mt-0.5 font-mono" title={shot.url}>
                    {shot.url}
                  </div>
                </div>
                {shot.status_code && (
                  <span className={`flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold ${statusColor(shot.status_code)}`}>
                    {shot.status_code}
                  </span>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div
          className="fixed inset-0 z-50 bg-black/90 flex items-center justify-center p-4"
          onClick={() => setLightbox(null)}
        >
          <div
            className="max-w-5xl w-full bg-gray-900 rounded-xl overflow-hidden shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center gap-3 px-4 py-3 bg-gray-800 border-b border-gray-700">
              <div className="flex-1 min-w-0">
                <div className="text-white text-sm font-medium truncate">{lightbox.title || lightbox.url}</div>
                <div className="text-gray-400 text-xs font-mono truncate">{lightbox.url}</div>
              </div>
              {lightbox.status_code && (
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${statusColor(lightbox.status_code)}`}>
                  {lightbox.status_code}
                </span>
              )}
              <a
                href={lightbox.url}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1.5 text-gray-400 hover:text-white rounded"
                title="Open URL"
              >
                <ExternalLink size={15} />
              </a>
              <button onClick={() => setLightbox(null)} className="p-1.5 text-gray-400 hover:text-white rounded">
                <X size={16} />
              </button>
            </div>
            <AuthImage
              src={screenshotsApi.imageUrl(lightbox.id)}
              alt={lightbox.url}
              className="w-full max-h-[75vh] object-contain object-top"
            />
          </div>
        </div>
      )}
    </>
  )
}

/** Authenticated image component — fetches via axios token and renders as blob URL */
function AuthImage({ src, alt, className }: { src: string; alt: string; className: string }) {
  const { data: blobUrl } = useQuery({
    queryKey: ['img', src],
    queryFn: async () => {
      const { default: api } = await import('@/api/client')
      const resp = await api.get(src.replace('/api/v1', ''), { responseType: 'blob' })
      return URL.createObjectURL(resp.data)
    },
    staleTime: Infinity,
  })

  if (!blobUrl) {
    return <div className={`${className} bg-gray-800 flex items-center justify-center`}>
      <span className="text-gray-600 text-xs">Loading...</span>
    </div>
  }

  return <img src={blobUrl} alt={alt} className={className} />
}
