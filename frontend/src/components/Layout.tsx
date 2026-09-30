import { lazy, Suspense, useCallback, useEffect, useState, type ComponentType } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOut, Menu, Plus, X } from "lucide-react";
import { useAuthStore } from "@/store/auth";
import { parseJwtRole } from "@/utils/jwt";
import { Logo } from "@/components/Logo";
import api from "@/api/client";

type PageId = "dashboard" | "scans" | "findings" | "assets" | "vulnerabilities" |
  "templates" | "schedules" | "agents" | "credentials" | "wordlists" |
  "plugins" | "reports" | "settings";

type PageProps = {
  onOpenScan?: (id: string) => void;
  onNavigate?: (page: PageId) => void;
  openNewScan?: boolean;
  onNewScanOpened?: () => void;
};

const Dashboard = lazy(() => import("@/pages/Dashboard")) as ComponentType<PageProps>;
const Scans = lazy(() => import("@/pages/Scans")) as ComponentType<PageProps>;
const Findings = lazy(() => import("@/pages/Findings")) as ComponentType<PageProps>;
const Assets = lazy(() => import("@/pages/Assets")) as ComponentType<PageProps>;
const Vulnerabilities = lazy(() => import("@/pages/Vulnerabilities")) as ComponentType<PageProps>;
const Agents = lazy(() => import("@/pages/Agents")) as ComponentType<PageProps>;
const Schedules = lazy(() => import("@/pages/Schedules")) as ComponentType<PageProps>;
const Credentials = lazy(() => import("@/pages/Credentials")) as ComponentType<PageProps>;
const Plugins = lazy(() => import("@/pages/Plugins")) as ComponentType<PageProps>;
const Templates = lazy(() => import("@/pages/Templates")) as ComponentType<PageProps>;
const Wordlists = lazy(() => import("@/pages/Wordlists")) as ComponentType<PageProps>;
const Reports = lazy(() => import("@/pages/Reports")) as ComponentType<PageProps>;
const SettingsPage = lazy(() => import("@/pages/Settings")) as ComponentType<PageProps>;
const ScanDetail = lazy(() => import("@/pages/ScanDetail"));

const PAGES: Record<PageId, ComponentType<PageProps>> = {
  dashboard: Dashboard, scans: Scans, findings: Findings, assets: Assets,
  vulnerabilities: Vulnerabilities, agents: Agents, schedules: Schedules,
  credentials: Credentials, plugins: Plugins, templates: Templates,
  wordlists: Wordlists, reports: Reports, settings: SettingsPage,
};

const SECTIONS: { label: string; pages: { id: PageId; label: string }[] }[] = [
  { label: "Overview", pages: [{ id: "dashboard", label: "Dashboard" }] },
  { label: "Scanning", pages: [
    { id: "scans", label: "Scans" }, { id: "agents", label: "Agents" },
    { id: "schedules", label: "Schedules" }, { id: "credentials", label: "Credentials" },
  ] },
  { label: "Results", pages: [
    { id: "findings", label: "Findings" }, { id: "assets", label: "Assets" },
    { id: "vulnerabilities", label: "Vulnerabilities" },
  ] },
  { label: "Tools", pages: [
    { id: "plugins", label: "Plugins" }, { id: "templates", label: "Templates" },
    { id: "wordlists", label: "Wordlists" },
  ] },
  { label: "Reports", pages: [{ id: "reports", label: "Reports" }] },
  { label: "Settings", pages: [{ id: "settings", label: "Settings" }] },
];

const pageIds = new Set<PageId>(Object.keys(PAGES) as PageId[]);
const pageName = (id: PageId) => SECTIONS.flatMap(s => s.pages).find(p => p.id === id)?.label ?? "Overview";

export default function Layout() {
  const qc = useQueryClient();
  const parseHash = useCallback((): PageId => {
    const value = window.location.hash.replace(/^#\/?/, "") as PageId;
    return pageIds.has(value) ? value : "dashboard";
  }, []);
  const [page, setPage] = useState<PageId>(parseHash);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [bannerDismissed, setBannerDismissed] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [openNewScan, setOpenNewScan] = useState(false);

  useEffect(() => {
    const onHashChange = () => {
      setPage(parseHash());
      setActiveScanId(null);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, [parseHash]);

  const navigate = (id: PageId) => {
    setPage(id);
    setActiveScanId(null);
    setSidebarOpen(false);
    window.location.hash = `#/${id}`;
  };

  const token = useAuthStore(s => s.token);
  const storeLogout = useAuthStore(s => s.logout);
  const role = parseJwtRole(token);
  const logout = async () => {
    try { await api.post("/auth/logout", {}); } catch { /* clear local session anyway */ }
    storeLogout();
  };

  const { data: versionData } = useQuery({
    queryKey: ["version"],
    queryFn: () => api.get("/system/version").then(r => r.data),
    refetchInterval: 60 * 60 * 1000,
    staleTime: 60 * 60 * 1000,
  });
  const { data: updateStatus } = useQuery({
    queryKey: ["system-update-status"],
    queryFn: () => api.get("/system/update/status").then(r => r.data),
    enabled: Boolean(versionData?.self_update_enabled) && role === "admin",
    refetchInterval: query => query.state.data?.state === "running" || query.state.data?.state === "queued" || query.state.data?.state === "restarting" ? 2500 : false,
  });
  const updateMut = useMutation({
    mutationFn: () => api.post("/system/update").then(r => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["system-update-status"] }),
  });

  const activeSection = SECTIONS.find(s => s.pages.some(p => p.id === page)) ?? SECTIONS[0];
  const PageComponent = PAGES[page];
  const updateRunning = updateStatus?.state === "running" || updateStatus?.state === "queued" || updateStatus?.state === "restarting";

  return (
    <div className="console-shell">
      {sidebarOpen && <button className="console-backdrop" onClick={() => setSidebarOpen(false)} aria-label="Close navigation" />}
      <aside className={`console-sidebar${sidebarOpen ? " is-open" : ""}`}>
        <div className="console-brand-row"><button onClick={() => navigate("dashboard")} aria-label="Dashboard"><Logo /></button><button className="console-close-nav" onClick={() => setSidebarOpen(false)} aria-label="Close navigation"><X size={18} /></button></div>
        <nav className="console-navigation" aria-label="Application navigation">
          {SECTIONS.map(section => (
            <div className="console-nav-group" key={section.label}>
              <div className="console-nav-heading">{section.label}</div>
              {section.pages.map(item => (
                <button key={item.id} className={`console-nav-link${page === item.id ? " is-active" : ""}`}
                  onClick={() => navigate(item.id)} aria-current={page === item.id ? "page" : undefined}>
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <div className="console-sidebar-bottom">
          <div className="console-version mono">SCANR {versionData?.version ? `v${versionData.version}` : ""}</div>
          <button className="console-logout" onClick={logout}><LogOut size={14} /> Sign out</button>
        </div>
      </aside>

      <div className="console-main">
        <header className="console-toolbar">
          <button className="console-menu-button" onClick={() => setSidebarOpen(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="console-breadcrumb"><span>{activeSection.label}</span><span>/</span><strong>{activeScanId ? "Scan detail" : pageName(page)}</strong></div>
          <div className="console-toolbar-actions">{page !== "scans" && role !== "viewer" && <button className="console-new-scan" onClick={() => { setOpenNewScan(true); navigate("scans"); }}><Plus size={14} /> New scan</button>}</div>
        </header>
        {versionData?.update_available && !bannerDismissed && (
          <div className="console-update">
            <strong>Update available</strong><span>ScanR v{versionData.latest}</span>
            {versionData.release_url && <a href={versionData.release_url} target="_blank" rel="noreferrer">Release notes</a>}
            {updateStatus?.state === "restarting" && <span>Restarting services. Waiting for ScanR to come back.</span>}
            {updateMut.isError && <span role="alert">Could not start update. Check Settings → System.</span>}
            {updateStatus?.state === "failed" && <span>Update failed: {updateStatus.message}</span>}
            {updateStatus?.state === "succeeded" && <span>Update command completed.</span>}
            {Boolean(versionData.self_update_enabled) && role === "admin" && (
              <button className="btn btn-primary btn-sm" onClick={() => updateMut.mutate()} disabled={updateRunning || updateMut.isPending}>{updateRunning || updateMut.isPending ? "Updating…" : "Update now"}</button>
            )}
            <button className="console-update-close" onClick={() => setBannerDismissed(true)} aria-label="Dismiss update"><X size={14} /></button>
          </div>
        )}
        <main className="console-content" id="main-content">
          <Suspense fallback={<div className="console-loading">Loading {activeScanId ? "scan detail" : pageName(page).toLowerCase()}…</div>}>
            {activeScanId ? (
              <ScanDetail scanId={activeScanId} onBack={() => setActiveScanId(null)} />
            ) : (
              <PageComponent onOpenScan={id => { window.history.replaceState(null, "", "#/scans"); setPage("scans"); setActiveScanId(id); }} onNavigate={navigate} openNewScan={openNewScan} onNewScanOpened={() => setOpenNewScan(false)} />
            )}
          </Suspense>
        </main>
      </div>
    </div>
  );
}
