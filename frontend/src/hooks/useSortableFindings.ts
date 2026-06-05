import { useState, useMemo } from 'react'
import type { Finding } from '@/api/findings'

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }

export type FindingSortKey = 'severity' | 'title' | 'port' | 'vpr' | 'cvss' | 'status'

export function useSortableFindings(findings: Finding[]) {
  const [sortKey, setSortKey] = useState<FindingSortKey>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  function toggleSort(key: FindingSortKey) {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sorted = useMemo(() => {
    const mult = sortDir === 'asc' ? 1 : -1
    return [...findings].sort((a, b) => {
      switch (sortKey) {
        case 'severity':
          return mult * ((SEV_RANK[a.severity] ?? 99) - (SEV_RANK[b.severity] ?? 99))
        case 'title':
          return mult * (a.title ?? '').localeCompare(b.title ?? '')
        case 'port':
          return mult * ((a.port_number ?? 0) - (b.port_number ?? 0))
        case 'vpr':
          return mult * ((a.vpr_score ?? -1) - (b.vpr_score ?? -1))
        case 'cvss':
          return mult * ((a.cvss_score ?? -1) - (b.cvss_score ?? -1))
        case 'status': {
          const la = a.false_positive ? 'false_positive' : (a.remediation_status ?? '')
          const lb = b.false_positive ? 'false_positive' : (b.remediation_status ?? '')
          return mult * la.localeCompare(lb)
        }
        default:
          return 0
      }
    })
  }, [findings, sortKey, sortDir])

  return { sorted, sortKey, sortDir, toggleSort }
}
