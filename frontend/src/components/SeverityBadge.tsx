export default function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`sev-tag ${severity}`}>{severity}</span>
}
