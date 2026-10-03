import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, FileText, Paperclip, Trash2 } from 'lucide-react'
import { attachmentsApi, type Attachment } from '@/api/attachments'
import { apiErrorMessage } from '@/utils/apiError'

const IMAGE = /^image\//

function formatSize(bytes: number) {
  return bytes < 1024 ? `${bytes} B` : bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(0)} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function useBlobUrl(attachment: Attachment, enabled: boolean) {
  const { data } = useQuery({
    queryKey: ['attachment-blob', attachment.id],
    queryFn: () => attachmentsApi.blob(attachment.id),
    enabled,
    staleTime: Infinity,
  })
  const [url, setUrl] = useState<string | null>(null)
  useEffect(() => {
    if (!data) return
    const objectUrl = URL.createObjectURL(data)
    setUrl(objectUrl)
    return () => URL.revokeObjectURL(objectUrl)
  }, [data])
  return url
}

async function download(attachment: Attachment) {
  const blob = await attachmentsApi.blob(attachment.id)
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = attachment.filename
  a.click()
  URL.revokeObjectURL(url)
}

function Item({ attachment, canEdit }: { attachment: Attachment; canEdit: boolean }) {
  const qc = useQueryClient()
  const isImage = IMAGE.test(attachment.content_type)
  const url = useBlobUrl(attachment, isImage)
  const [caption, setCaption] = useState(attachment.caption ?? '')
  const refresh = () => qc.invalidateQueries({ queryKey: ['attachments', attachment.finding_id] })
  const save = useMutation({ mutationFn: () => attachmentsApi.setCaption(attachment.id, caption), onSuccess: refresh })
  const remove = useMutation({ mutationFn: () => attachmentsApi.remove(attachment.id), onSuccess: refresh })

  return (
    <li className="evidence-item">
      {isImage ? (
        <button type="button" className="evidence-thumb" onClick={() => url && window.open(url, '_blank', 'noopener')} aria-label={`Open ${attachment.filename}`}>
          {url ? <img src={url} alt={attachment.caption ?? attachment.filename} /> : <span>Loading…</span>}
        </button>
      ) : (
        <div className="evidence-file"><FileText size={20} /><span className="mono">{attachment.content_type === 'application/pdf' ? 'PDF' : 'TEXT'}</span></div>
      )}
      <div className="evidence-meta">
        <span className="evidence-name" title={attachment.filename}>{attachment.filename}</span>
        <span className="dimmer">{formatSize(attachment.size)} · {attachment.uploaded_by ?? 'unknown'}</span>
        {canEdit ? (
          <input className="input evidence-caption" placeholder="Caption for the report…" value={caption}
                 onChange={e => setCaption(e.target.value)}
                 onBlur={() => { if (caption !== (attachment.caption ?? '')) save.mutate() }}
                 onKeyDown={e => { if (e.key === 'Enter') (e.target as HTMLInputElement).blur() }} />
        ) : attachment.caption && <span>{attachment.caption}</span>}
      </div>
      <div className="evidence-actions">
        <button type="button" className="btn btn-ghost btn-icon btn-sm" title="Download" onClick={() => download(attachment)}><Download size={13} /></button>
        {canEdit && <button type="button" className="btn btn-ghost btn-icon btn-sm" title="Delete" style={{ color: 'var(--sev-high)' }}
                            onClick={() => { if (confirm(`Delete ${attachment.filename}?`)) remove.mutate() }}><Trash2 size={13} /></button>}
      </div>
    </li>
  )
}

/** Screenshots and files proving a finding. Paste (Ctrl+V), drop or choose files. */
export default function EvidencePanel({ findingId, canEdit }: { findingId: string; canEdit: boolean }) {
  const qc = useQueryClient()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { data: attachments = [] } = useQuery({
    queryKey: ['attachments', findingId],
    queryFn: () => attachmentsApi.list(findingId),
  })
  const upload = useMutation({
    mutationFn: async (files: File[]) => {
      for (const file of files) await attachmentsApi.upload(findingId, file)
    },
    onSuccess: () => { setError(null); qc.invalidateQueries({ queryKey: ['attachments', findingId] }) },
    onError: (e: unknown) => { setError(apiErrorMessage(e)); qc.invalidateQueries({ queryKey: ['attachments', findingId] }) },
  })

  useEffect(() => {
    if (!canEdit) return
    const onPaste = (event: ClipboardEvent) => {
      const images = Array.from(event.clipboardData?.files ?? []).filter(f => IMAGE.test(f.type))
      if (images.length === 0) return
      event.preventDefault()
      const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')
      upload.mutate(images.map((f, i) => new File([f], `screenshot-${stamp}${images.length > 1 ? `-${i + 1}` : ''}.png`, { type: f.type })))
    }
    window.addEventListener('paste', onPaste)
    return () => window.removeEventListener('paste', onPaste)
  }, [canEdit, upload])

  return (
    <div className="evidence-panel"
         onDragOver={e => { if (canEdit) { e.preventDefault(); setDragging(true) } }}
         onDragLeave={() => setDragging(false)}
         onDrop={e => { e.preventDefault(); setDragging(false); if (canEdit && e.dataTransfer.files.length) upload.mutate(Array.from(e.dataTransfer.files)) }}>
      <div className="evidence-head">
        <div className="label" style={{ margin: 0 }}>Evidence files {attachments.length > 0 && <span className="dimmer">({attachments.length})</span>}</div>
        {canEdit && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => inputRef.current?.click()} disabled={upload.isPending}>
            <Paperclip size={12} /> {upload.isPending ? 'Uploading…' : 'Attach'}
          </button>
        )}
        <input ref={inputRef} type="file" multiple hidden accept="image/png,image/jpeg,image/gif,image/webp,application/pdf,.txt,.log,.har,.json,.xml,.http,.req"
               onChange={e => { const files = Array.from(e.target.files ?? []); if (files.length) upload.mutate(files); e.target.value = '' }} />
      </div>
      {error && <div className="evidence-error" role="alert">{error}</div>}
      {attachments.length > 0 && <ul className="evidence-list">{attachments.map(a => <Item key={a.id} attachment={a} canEdit={canEdit} />)}</ul>}
      {canEdit && (
        <div className={`evidence-drop ${dragging ? 'is-dragging' : ''}`}>
          Paste a screenshot (Ctrl+V), drop files here, or use Attach. PNG, JPEG, GIF, WebP, PDF or text, up to 20 MB.
        </div>
      )}
    </div>
  )
}
