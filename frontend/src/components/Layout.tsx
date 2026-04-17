import { useState } from 'react'
import { Shield, Scan, AlertTriangle, Puzzle, FileText, LogOut, Settings as SettingsIcon, LayoutTemplate, Clock, Bot, Key } from 'lucide-react'
import { useAuthStore } from '@/store/auth'
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

const NAV = [
  { id: 'dashboard', label: 'Dashboard', icon: Shield },
  { id: 'scans', label: 'Scans', icon: Scan },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'templates', label: 'Templates', icon: LayoutTemplate },
  { id: 'schedules', label: 'Schedules', icon: Clock },
  { id: 'agents', label: 'Agents', icon: Bot },
  { id: 'credentials', label: 'Credentials', icon: Key },
  { id: 'plugins', label: 'Plugins', icon: Puzzle },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: SettingsIcon },
]

export default function Layout() {
  const [page, setPage] = useState('dashboard')
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const logout = useAuthStore((s) => s.logout)

  const PageComponent = {
    dashboard: Dashboard,
    scans: Scans,
    findings: Findings,
    plugins: Plugins,
    reports: Reports,
    settings: SettingsPage,
    templates: Templates,
    schedules: Schedules,
    agents: Agents,
    credentials: Credentials,
  }[page] ?? Dashboard

  function openScan(id: string) {
    setActiveScanId(id)
  }

  function closeScan() {
    setActiveScanId(null)
  }

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-900 flex flex-col flex-shrink-0">
        <div className="px-6 py-5 border-b border-gray-700">
          <span className="text-white font-bold text-xl">ScanR</span>
          <span className="text-blue-400 text-xs ml-2">v0.6.0</span>
        </div>
        <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => { setPage(id); setActiveScanId(null) }}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                page === id && !activeScanId
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </nav>
        <div className="p-3 border-t border-gray-700">
          <button
            onClick={logout}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
          >
            <LogOut size={16} />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-auto min-h-0">
        {activeScanId
          ? <ScanDetail scanId={activeScanId} onBack={closeScan} />
          : <PageComponent onOpenScan={page === 'scans' ? openScan : undefined} />
        }
      </main>
    </div>
  )
}
