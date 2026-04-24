import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  type LucideIcon,
  LayoutDashboard, Scan, AlertTriangle, Puzzle, FileText, LogOut,
  Settings as SettingsIcon, LayoutTemplate, Clock, Bot, Key, List,
  ArrowUpCircle, X,
} from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import api from '@/api/client'
import Dashboard from '@/pages/Dashboard'
import Scans from '@/pages/Scans'
import Findings from '@/pages/Findings'
import Plugins from '@/pages/Plugins'
import Reports from '@/pages/Reports'
import SettingsPage from '@/pages/Settings'
import Templates from '@/pages/Templates'
import Schedules from '@/pages/Schedules'
import Agents from '@/pages/Agents'
import Credentials from '@/pages/Credentials'
import Wordlists from '@/pages/Wordlists'
import ScanDetail from '@/pages/ScanDetail'
import { Logo } from '@/components/Logo'

type PageId = 'dashboard' | 'scans' | 'findings' | 'templates' | 'schedules' | 'agents' | 'credentials' | 'wordlists' | 'plugins' | 'reports' | 'settings'

const NAV: { id: PageId; label: string; icon: LucideIcon }[] = [
  { id: 'dashboard',   label: 'Dashboard',   icon: LayoutDashboard },
  { id: 'scans',       label: 'Scans',       icon: Scan },
  { id: 'findings',    label: 'Findings',    icon: AlertTriangle },
  { id: 'templates',   label: 'Templates',   icon: LayoutTemplate },
  { id: 'schedules',   label: 'Schedules',   icon: Clock },
  { id: 'agents',      label: 'Agents',      icon: Bot },
  { id: 'credentials', label: 'Credentials', icon: Key },
  { id: 'wordlists',   label: 'Wordlists',   icon: List },
  { id: 'plugins',     label: 'Plugins',     icon: Puzzle },
  { id: 'reports',     label: 'Reports',     icon: FileText },
]

export default function Layout() {
  const [page, setPage] = useState<PageId>('dashboard')
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [bannerDismissed, setBannerDismissed] = useState(false)
  const logout = useAuthStore((s) => s.logout)

  const { data: versionData } = useQuery({
    queryKey: ['version'],
    queryFn: () => api.get('/system/version').then(r => r.data),
    refetchInterval: 60 * 60 * 1000,
    staleTime: 60 * 60 * 1000,
  })

  const PageComponent = {
    dashboard:   Dashboard,
    scans:       Scans,
    findings:    Findings,
    plugins:     Plugins,
    reports:     Reports,
    settings:    SettingsPage,
    templates:   Templates,
    schedules:   Schedules,
    agents:      Agents,
    credentials: Credentials,
    wordlists:   Wordlists,
  }[page] ?? Dashboard

  const showBanner = versionData?.update_available && !bannerDismissed

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-0)' }}>

      {/* Sidebar */}
      <aside style={{
        width: 210, flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: 'var(--bg-1)', borderRight: '1px solid var(--border)',
      }}>
        {/* Logo */}
        <div style={{ padding: '18px 16px 14px', borderBottom: '1px solid var(--border)' }}>
          <Logo />
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, padding: '8px 10px', overflowY: 'auto' }}>
          {NAV.map(({ id, label, icon: Icon }) => {
            const active = page === id && !activeScanId
            return (
              <button
                key={id}
                onClick={() => { setPage(id); setActiveScanId(null) }}
                className={`nav-item${active ? ' active' : ''}`}
              >
                <Icon size={14} />
                <span>{label}</span>
              </button>
            )
          })}
        </nav>

        {/* Footer */}
        <div style={{ padding: '8px 10px', borderTop: '1px solid var(--border)' }}>
          <button
            onClick={() => { setPage('settings'); setActiveScanId(null) }}
            className={`nav-item${page === 'settings' && !activeScanId ? ' active' : ''}`}
          >
            <SettingsIcon size={14} />
            <span>Settings</span>
          </button>
          <button onClick={logout} className="nav-item" style={{ marginTop: 2 }}>
            <LogOut size={14} />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, background: 'var(--bg-0)' }}>

        {/* Update banner */}
        {showBanner && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '8px 16px', flexShrink: 0,
            background: 'var(--accent-soft)',
            borderBottom: '1px solid oklch(0.78 0.14 200 / 0.25)',
          }}>
            <ArrowUpCircle size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
            <span style={{ fontSize: 12.5, color: 'var(--accent)', flex: 1 }}>
              ScanR v{versionData.latest} available — you're running v{versionData.current}.{' '}
              {versionData.release_url && (
                <a href={versionData.release_url} target="_blank" rel="noreferrer"
                  style={{ color: 'var(--accent)', textDecoration: 'underline' }}>
                  View release notes
                </a>
              )}
            </span>
            <button
              onClick={() => setBannerDismissed(true)}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', display: 'flex', padding: 2 }}
            >
              <X size={13} />
            </button>
          </div>
        )}

        {/* Page */}
        <div style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
          {activeScanId
            ? <ScanDetail scanId={activeScanId} onBack={() => setActiveScanId(null)} />
            : <PageComponent onOpenScan={page === 'scans' ? (id: string) => setActiveScanId(id) : undefined} />
          }
        </div>
      </main>
    </div>
  )
}
