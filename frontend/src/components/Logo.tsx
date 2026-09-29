export function LogoMark({ size = 22 }: { size?: number }) {
  return <span aria-hidden="true" style={{ color: 'var(--accent)', fontSize: size, fontWeight: 900, lineHeight: 1 }}>/</span>
}

export function Logo({ version }: { version?: string }) {
  return (
    <span className="logo">
      <span>SCAN</span><span className="logo-mark">/</span><span>R</span>
      {version && <span className="logo-version mono">v{version}</span>}
    </span>
  )
}
