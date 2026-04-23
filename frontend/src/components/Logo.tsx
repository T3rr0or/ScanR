export function LogoMark({ size = 22 }: { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.35" strokeWidth="1"/>
      <circle cx="12" cy="12" r="6.5" stroke="currentColor" strokeOpacity="0.55" strokeWidth="1"/>
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeOpacity="0.85" strokeWidth="1"/>
      <circle cx="12" cy="12" r="1.2" fill="currentColor"/>
      <line x1="12" y1="12" x2="21" y2="6.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/>
      <circle cx="21" cy="6.5" r="1.5" fill="currentColor"/>
    </svg>
  )
}

export function Logo({ version }: { version?: string }) {
  return (
    <div className="logo">
      <span style={{ color: 'var(--accent)' }}>
        <LogoMark />
      </span>
      <span>ScanR</span>
      {version && (
        <span className="mono" style={{ fontSize: 10, color: 'var(--text-3)', marginLeft: 2 }}>
          v{version}
        </span>
      )}
    </div>
  )
}
