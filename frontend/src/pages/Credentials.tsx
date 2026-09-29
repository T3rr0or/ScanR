import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Trash2, Plus } from 'lucide-react'
import { credentialsApi, type CredentialCreate } from '@/api/credentials'
import { relTime } from '@/components/ui'
import './OperatorSetup.css'

export default function Credentials() {
  const qc = useQueryClient()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState<{
    name: string; type: string; username: string; description: string
    password: string; private_key: string
  }>({ name: '', type: 'smb', username: '', description: '', password: '', private_key: '' })

  const { data: credentials = [] } = useQuery({
    queryKey: ['credentials'],
    queryFn: credentialsApi.list,
  })

  const createMut = useMutation({
    mutationFn: () => {
      const body: CredentialCreate = {
        name: form.name,
        type: form.type,
        username: form.username || undefined,
        description: form.description || undefined,
        secret_data: form.type === 'ssh' ? { private_key: form.private_key } : { password: form.password },
      }
      return credentialsApi.create(body)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      setShowForm(false)
      setForm({ name: '', type: 'smb', username: '', description: '', password: '', private_key: '' })
    },
  })

  const deleteMut = useMutation({
    mutationFn: credentialsApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })

  return <main className="setup-page credentials-page page-pad">
    <header className="setup-header"><div><h1>Credentials</h1><p>Credentials for authenticated scans. Secrets are encrypted at rest.</p></div><button className="setup-button setup-button-primary" onClick={() => setShowForm(v=>!v)}><Plus size={14}/> New credential</button></header>
    <div className="setup-summary"><span>{credentials.length} saved credentials</span><span>SSH, SMB, HTTP, FTP, SNMP, WMI</span></div>
    {showForm && <section className="setup-form"><div className="setup-form-heading"><strong>New credential</strong><button onClick={()=>setShowForm(false)}>Close</button></div><div className="setup-form-row"><label>Name *<input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="Domain audit"/></label><label>Type<select value={form.type} onChange={e=>setForm(f=>({...f,type:e.target.value}))}><option value="smb">SMB / Windows password</option><option value="ssh">SSH key</option><option value="http_basic">HTTP Basic password</option><option value="ftp">FTP password</option><option value="snmp">SNMP secret</option><option value="wmi">WMI password</option></select></label><label>Username<input value={form.username} onChange={e=>setForm(f=>({...f,username:e.target.value}))} placeholder="administrator"/></label><label>Description<input value={form.description} onChange={e=>setForm(f=>({...f,description:e.target.value}))} placeholder="Optional note"/></label></div><div className="setup-secret">{form.type==='ssh'?<label>Private key (PEM) *<textarea value={form.private_key} onChange={e=>setForm(f=>({...f,private_key:e.target.value}))} rows={5} placeholder="-----BEGIN PRIVATE KEY-----"/></label>:<label>Password / secret *<input type="password" value={form.password} onChange={e=>setForm(f=>({...f,password:e.target.value}))}/></label>}</div><div className="setup-form-actions"><button className="setup-button setup-button-primary" onClick={()=>createMut.mutate()} disabled={!form.name.trim() || (form.type==='ssh'?!form.private_key.trim():!form.password) || createMut.isPending}>{createMut.isPending?'Saving...':'Save credential'}</button><button className="setup-button" onClick={()=>setShowForm(false)}>Cancel</button></div></section>}
    <section className="setup-list"><div className="setup-list-heading"><span>Saved credentials</span><span>{credentials.length} records</span></div><div className="credential-table-wrap"><table className="setup-table"><thead><tr><th>Name</th><th>Type</th><th>Username</th><th>Description</th><th>Created</th><th>Action</th></tr></thead><tbody>{credentials.map(c=><tr key={c.id}><td><strong>{c.name}</strong></td><td><code>{c.type}</code></td><td><code>{c.username??'-'}</code></td><td>{c.description??'-'}</td><td>{relTime(c.created_at)}</td><td><button className="setup-icon-button" onClick={()=>{if(confirm(`Delete credential "${c.name}"?`))deleteMut.mutate(c.id)}} title={`Delete ${c.name}`} aria-label={`Delete ${c.name}`}><Trash2 size={14}/></button></td></tr>)}{credentials.length===0&&<tr><td colSpan={6} className="setup-empty">No credentials saved. Add one to enable authenticated scans.</td></tr>}</tbody></table></div></section>
  </main>
}
