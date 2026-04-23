import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, X } from 'lucide-react'
import { screenshotsApi, type Screenshot } from '@/api/screenshots'

interface Props {
  scanId: string
}

function statusColor(code: number | null): string {
  if (!code) return 'var(--text-3)'
  if (code < 300) return 'var(--ok)'
  if (code < 400) return 'var(--sev-medium)'
  return 'var(--sev-high)'
}

function statusBg(code: number | null): string {
  if (!code) return 'var(--bg-3)'
  if (code < 300) return 'oklch(0.22 0.05 145 / 0.3)'
  if (code < 400) return 'oklch(0.24 0.08 85 / 0.3)'
  return 'oklch(0.24 0.08 30 / 0.3)'
}

export default function ScreenshotGallery({ scanId }: Props) {
  const { data: shots = [], isLoading } = useQuery({
    queryKey: ['screenshots', scanId],
    queryFn: () => screenshotsApi.list(scanId),
    refetchInterval: 10_000,
  })
  const [lightbox, setLightbox] = useState<Screenshot | null>(null)

  if (isLoading) {
    return <div className="dimmer" style={{ fontSize: 13, padding: 16 }}>Loading screenshots…</div>
  }

  if (shots.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-3)' }}>
        <div style={{ fontSize: 13, marginBottom: 6 }}>No screenshots captured yet.</div>
        <div className="mono" style={{ fontSize: 11 }}>Enable the <span style={{ color: 'var(--accent)' }}>web.screenshot</span> plugin and run a scan with HTTP/HTTPS ports.</div>
      </div>
    )
  }

  return (
    <>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
        gap: 12,
        padding: 16,
      }}>
        {shots.map(shot => (
          <div
            key={shot.id}
            onClick={() => setLightbox(shot)}
            style={{
              background: 'var(--bg-2)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              overflow: 'hidden',
              cursor: 'pointer',
              transition: 'border-color 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-strong)')}
            onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
          >
            {/* 16:9 thumbnail */}
            <div style={{ position: 'relative', paddingTop: '56.25%', background: 'var(--bg-1)', overflow: 'hidden' }}>
              <div style={{ position: 'absolute', inset: 0 }}>
                <AuthImage
                  src={screenshotsApi.imageUrl(shot.id)}
                  alt={shot.url}
                  style={{ width: '100%', height: '100%', objectFit: 'cover', objectPosition: 'top', display: 'block' }}
                />
              </div>
            </div>

            {/* Caption */}
            <div style={{ padding: '8px 10px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {shot.title || extractHostPort(shot.url)}
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                    {extractHostPort(shot.url)}
                  </div>
                </div>
                {shot.status_code && (
                  <span className="mono" style={{
                    fontSize: 10, fontWeight: 700, flexShrink: 0,
                    padding: '2px 5px', borderRadius: 4,
                    background: statusBg(shot.status_code),
                    color: statusColor(shot.status_code),
                  }}>
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
          onClick={() => setLightbox(null)}
          style={{
            position: 'fixed', inset: 0, zIndex: 50,
            background: 'rgba(0,0,0,0.88)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: 16,
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              maxWidth: 1000, width: '100%',
              background: 'var(--bg-2)', borderRadius: 10,
              overflow: 'hidden',
              boxShadow: '0 24px 80px #0009',
              border: '1px solid var(--border)',
            }}
          >
            {/* Lightbox header */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '10px 14px',
              background: 'var(--bg-3)', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-0)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {lightbox.title || extractHostPort(lightbox.url)}
                </div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {lightbox.url}
                </div>
              </div>
              {lightbox.status_code && (
                <span className="mono" style={{
                  fontSize: 11, fontWeight: 700, flexShrink: 0,
                  padding: '2px 7px', borderRadius: 4,
                  background: statusBg(lightbox.status_code),
                  color: statusColor(lightbox.status_code),
                }}>
                  {lightbox.status_code}
                </span>
              )}
              <a
                href={lightbox.url}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-ghost btn-icon btn-sm"
                title="Open URL"
              >
                <ExternalLink size={14} />
              </a>
              <button onClick={() => setLightbox(null)} className="btn btn-ghost btn-icon btn-sm">
                <X size={15} />
              </button>
            </div>

            <AuthImage
              src={screenshotsApi.imageUrl(lightbox.id)}
              alt={lightbox.url}
              style={{ width: '100%', maxHeight: '75vh', objectFit: 'contain', objectPosition: 'top', display: 'block' }}
            />
          </div>
        </div>
      )}
    </>
  )
}

function extractHostPort(url: string): string {
  try {
    const u = new URL(url)
    return u.host
  } catch {
    return url
  }
}

function AuthImage({ src, alt, style }: { src: string; alt: string; style: React.CSSProperties }) {
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
    return (
      <div style={{ ...style, background: 'var(--bg-1)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <span className="dimmer" style={{ fontSize: 11 }}>Loading…</span>
      </div>
    )
  }

  return <img src={blobUrl} alt={alt} style={style} />
}
