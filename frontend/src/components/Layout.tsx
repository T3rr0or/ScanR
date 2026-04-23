import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard, Scan, AlertTriangle, LayoutTemplate, Clock, Bot, Key,
  Puzzle, FileText, Settings as SettingsIcon, LogOut, ArrowUpCircle, Bell, Search,
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
import ScanDetail from '@/pages/ScanDetail'
import { Logo } from '@/components/Logo'
import { Avatar } from '@/components/ui'

type PageId = 'dashboard' | 'scans' | 'findings' | 'templates' | 'schedules' | 'agents' | 'credentials' | 'plugins' | 'reports' | 'settings'

const NAV: { id: PageId; label: string; icon: LucideIcon }[] = [
  { id: 'dashboard',   label: 'Dashboard',   icon: LayoutDashboard },
  { id: 'scans',       label: 'Scans',       icon: Scan },
  { id: 'findings',    label: 'Findings',    icon: AlertTriangle },
  { id: 'templates',   label: 'Templates',   icon: LayoutTemplate },
  { id: 'schedules',   label: 'Schedules',   icon: Clock },
  { id: 'agents',      label: 'Agents',      icon: Bot },
  { id: 'credentials', label: 'Credentials', icon: Key },
  { id: 'plugins',     label: 'Plugins',     icon: Puzzle },
  { id: 'reports',     label: 'Reports',     icon: FileText },
]

export default function Layout() {
  const [page, setPage] = useState<PageId>('dashboard')
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const logout = useAuthStore((s) => s.logout)

  const { data: versionData } = useQuery({
    queryKey: ['version'],
    queryFn: () => api.get('/system/version').then(r => r.data),
    refetchInterval: 60 * 60 * 1000,
    staleTime: 60 * 60 * 1000,
  })

  const { data: stats } = useQuery({
    queryKey: ['system-stats'],
    queryFn: () => api.get('/system/stats').then(r => r.data),
    refetchInterval: 10_000,
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
  }[page] ?? Dashboard

  function openScan(id: string) { setActiveScanId(id) }
  function closeScan() { setActiveScanId(null) }

  const crumbs = activeScanId
    ? [{ label: 'Scans', onClick: closeScan }, { label: 'Scan Detail' }]
    : [{ label: NAV.find(n => n.id === page)?.label ?? 'Dashboard' }]

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-0)' }}>
      {/* Sidebar */}
      <aside style={{
        width: 220, background: 'var(--bg-1)', borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '16px 16px 14px', borderBottom: '1px solid var(--border)' }}>
          <Logo version={versionData?.current} />
        </div>

        {/* Nav section label */}
        <div style={{ padding: '12px 14px 4px', fontSize: 10, color: 'var(--text-3)', letterSpacing: '0.1em', textTransform: 'uppercase', fontWeight: 600 }}>
          Navigation
        </div>

        {/* Nav items */}
        <nav style={{ flex: 1, padding: '4px 10px', overflowY: 'auto' }}>
          {NAV.map(({ id, label, icon: Icon }) => {
            const active = page === id && !activeScanId
            return (
              <button
                key={id}
                onClick={() => { setPage(id); setActiveScanId(null) }}
                className={`nav-item ${active ? 'active' : ''}`}
                style={{ marginBottom: 1 }}
              >
                <Icon size={14} />
                <span style={{ flex: 1 }}>{label}</span>
                {id === 'scans' && stats?.scans_running > 0 && (
                  <span className="mono" style={{ fontSize: 10, color: 'var(--accent-2)', display: 'inline-flex', gap: 4, alignItems: 'center' }}>
                    <span className="live-dot" style={{ width: 5, height: 5, boxShadow: 'none' }} />
                    {stats.scans_running}
                  </span>
                )}
              </button>
            )
          })}

          {/* System divider */}
          <div style={{ height: 1, background: 'var(--border-subtle)', margin: '8px 4px' }} />

          <button
            onClick={() => { setPage('settings'); setActiveScanId(null) }}
            className={`nav-item ${page === 'settings' && !activeScanId ? 'active' : ''}`}
          >
            <SettingsIcon size={14} />
            <span>Settings</span>
          </button>
        </nav>

        {/* Bottom strip */}
        <div style={{ borderTop: '1px solid var(--border)', padding: 10 }}>
          <div style={{
            padding: '8px 10px', background: 'var(--bg-2)', borderRadius: 6,
            marginBottom: 8, fontSize: 11,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
              <span className="live-dot ok" />
              <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>Scanner online</span>
            </div>
            {stats && (
              <div className="mono dimmer" style={{ fontSize: 10 }}>
                {stats.scans_total} scans · {stats.hosts_total} hosts
              </div>
            )}
          </div>
          <button
            onClick={logout}
            className="nav-item"
            style={{ color: 'var(--text-2)' }}
          >
            <Avatar initials="AD" />
            <span style={{ flex: 1, fontSize: 11.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              admin
            </span>
            <LogOut size={13} style={{ color: 'var(--text-3)', flexShrink: 0 }} />
          </button>
        </div>
      </aside>

      {/* Main area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
        {/* Update banner */}
        {versionData?.update_available && (
          <a
            href={versionData.release_url ?? '#'}
            target="_blank"
            rel="noreferrer"
            style={{
              display: 'flex', alignItems: 'center', gap: 8,
              padding: '8px 16px', background: 'var(--accent)', color: 'oklch(0.14 0.01 255)',
              fontSize: 12.5, fontWeight: 500, flexShrink: 0, textDecoration: 'none',
            }}
          >
            <ArrowUpCircle size={15} />
            ScanR v{versionData.latest} available — running v{versionData.current}. Click for release notes.
          </a>
        )}

        {/* Topbar */}
        <div style={{
          height: 44, borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', padding: '0 16px', gap: 12,
          background: 'var(--bg-0)', flexShrink: 0,
        }}>
          {/* Breadcrumbs */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
            {crumbs.map((c, i) => (
              <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {i > 0 && <span style={{ color: 'var(--text-3)', fontSize: 11 }}>/</span>}
                <span
                  style={{ color: i === crumbs.length - 1 ? 'var(--text-0)' : 'var(--text-2)', cursor: c.onClick ? 'pointer' : 'default' }}
                  onClick={c.onClick}
                >
                  {c.label}
                </span>
              </span>
            ))}
          </div>

          <div style={{ flex: 1 }} />

          {/* Right cluster */}
          <div className="search" style={{ maxWidth: 220 }}>
            <Search size={13} color="var(--text-3)" />
            <input placeholder="Search scans, hosts, CVEs…" style={{ minWidth: 0, flex: 1 }} />
            <span className="kbd">⌘K</span>
          </div>
          <button className="btn btn-ghost btn-icon" title="Notifications">
            <Bell size={14} />
          </button>
        </div>

        {/* Page content */}
        <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
          {activeScanId
            ? <ScanDetail scanId={activeScanId} onBack={closeScan} />
            : <PageComponent
                onOpenScan={openScan}
                onNavigate={(p: PageId) => { setPage(p); setActiveScanId(null) }}
              />
          }
        </div>
      </div>
    </div>
  )
}
