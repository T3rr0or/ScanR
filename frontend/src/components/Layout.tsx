import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  type LucideIcon,
  LayoutDashboard, Scan, AlertTriangle, Puzzle, FileText, LogOut,
  Settings as SettingsIcon, LayoutTemplate, Clock, Bot, Key, List,
  ArrowUpCircle, X, Menu,
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

// Primary nav shown in bottom bar on mobile (most used)
const BOTTOM_NAV: PageId[] = ['dashboard', 'scans', 'findings', 'reports', 'settings']

function useIsMobile() {
  const [mobile, setMobile] = useState(() => window.innerWidth < 900)
  useEffect(() => {
    const handler = () => setMobile(window.innerWidth < 900)
    window.addEventListener('resize', handler)
    return () => window.removeEventListener('resize', handler)
  }, [])
  return mobile
}

export default function Layout() {
  const [page, setPage] = useState<PageId>('dashboard')
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [bannerDismissed, setBannerDismissed] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const isMobile = useIsMobile()

  const _storeLogout = useAuthStore((s) => s.logout)
  const logout = async () => {
    try { await api.post('/auth/logout', {}) } catch { /* ignore */ }
    _storeLogout()
  }

  const navigate = (id: PageId) => {
    setPage(id)
    setActiveScanId(null)
    setSidebarOpen(false)
  }

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
  const activePage = activeScanId ? null : page

  const sidebar = (
    <aside style={{
      width: 210, flexShrink: 0, display: 'flex', flexDirection: 'column',
      background: 'var(--bg-1)', borderRight: '1px solid var(--border)',
      height: '100%',
    }}>
      <div style={{ padding: '18px 16px 14px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Logo />
        {isMobile && (
          <button onClick={() => setSidebarOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-2)', display: 'flex', padding: 4 }}>
            <X size={16} />
          </button>
        )}
      </div>

      <nav style={{ flex: 1, padding: '8px 10px', overflowY: 'auto' }}>
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = activePage === id
          return (
            <button
              key={id}
              onClick={() => navigate(id)}
              className={`nav-item${active ? ' active' : ''}`}
            >
              <Icon size={14} />
              <span>{label}</span>
            </button>
          )
        })}
      </nav>

      <div style={{ padding: '8px 10px', borderTop: '1px solid var(--border)' }}>
        <button
          onClick={() => navigate('settings')}
          className={`nav-item${activePage === 'settings' ? ' active' : ''}`}
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
  )

  return (
    <div style={{ display: 'flex', height: '100dvh', overflow: 'hidden', background: 'var(--bg-0)', flexDirection: 'column' }}>

      {/* Mobile top bar */}
      {isMobile && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '10px 14px', flexShrink: 0,
          background: 'var(--bg-1)', borderBottom: '1px solid var(--border)',
        }}>
          <button
            onClick={() => setSidebarOpen(true)}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-1)', display: 'flex', padding: 4 }}
            aria-label="Open menu"
          >
            <Menu size={20} />
          </button>
          <Logo />
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, minHeight: 0, position: 'relative' }}>

        {/* Desktop sidebar — always visible */}
        {!isMobile && sidebar}

        {/* Mobile sidebar — overlay drawer */}
        {isMobile && sidebarOpen && (
          <>
            {/* Backdrop */}
            <div
              onClick={() => setSidebarOpen(false)}
              style={{
                position: 'fixed', inset: 0, zIndex: 40,
                background: 'oklch(0.05 0.01 255 / 0.6)',
                backdropFilter: 'blur(2px)',
              }}
            />
            {/* Drawer */}
            <div style={{ position: 'fixed', left: 0, top: 0, bottom: 0, zIndex: 50 }}>
              {sidebar}
            </div>
          </>
        )}

        {/* Main content */}
        <main style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, background: 'var(--bg-0)', minHeight: 0 }}>

          {/* Update banner */}
          {showBanner && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '8px 16px', flexShrink: 0,
              background: 'var(--accent-soft)',
              borderBottom: '1px solid oklch(0.78 0.14 200 / 0.25)',
            }}>
              <ArrowUpCircle size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
              <span style={{ fontSize: 12.5, color: 'var(--accent)', flex: 1, minWidth: 0 }}>
                ScanR v{versionData.latest} available.{' '}
                {versionData.release_url && (
                  <a href={versionData.release_url} target="_blank" rel="noreferrer"
                    style={{ color: 'var(--accent)', textDecoration: 'underline' }}>
                    View release notes
                  </a>
                )}
              </span>
              <button
                onClick={() => setBannerDismissed(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent)', display: 'flex', padding: 4, flexShrink: 0 }}
              >
                <X size={13} />
              </button>
            </div>
          )}

          {/* Page */}
          <div style={{ flex: 1, overflowY: 'auto', minHeight: 0, paddingBottom: isMobile ? 60 : 0 }}>
            {activeScanId
              ? <ScanDetail scanId={activeScanId} onBack={() => setActiveScanId(null)} />
              : <PageComponent
                  onOpenScan={(id: string) => { setPage('scans'); setActiveScanId(id) }}
                  onNavigate={(p: PageId) => { setPage(p); setActiveScanId(null) }}
                />
            }
          </div>
        </main>
      </div>

      {/* Mobile bottom tab bar */}
      {isMobile && (
        <nav style={{
          position: 'fixed', bottom: 0, left: 0, right: 0, zIndex: 30,
          background: 'var(--bg-1)', borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'stretch',
        }}>
          {BOTTOM_NAV.map(id => {
            const item = id === 'settings'
              ? { id: 'settings' as PageId, label: 'Settings', icon: SettingsIcon }
              : NAV.find(n => n.id === id)!
            const active = activePage === item.id
            const Icon = item.icon
            return (
              <button
                key={item.id}
                onClick={() => navigate(item.id)}
                style={{
                  flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
                  justifyContent: 'center', gap: 3, padding: '8px 4px',
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: active ? 'var(--accent)' : 'var(--text-3)',
                  borderTop: active ? '2px solid var(--accent)' : '2px solid transparent',
                  transition: 'color 120ms',
                  minHeight: 52,
                }}
              >
                <Icon size={18} />
                <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
                  {item.label}
                </span>
              </button>
            )
          })}
          {/* More button → opens full sidebar */}
          <button
            onClick={() => setSidebarOpen(true)}
            style={{
              flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center',
              justifyContent: 'center', gap: 3, padding: '8px 4px',
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-3)', borderTop: '2px solid transparent',
              minHeight: 52,
            }}
          >
            <Menu size={18} />
            <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>More</span>
          </button>
        </nav>
      )}
    </div>
  )
}
