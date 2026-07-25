import api from './client'

export type AttackEdgeKind =
  | 'foothold'
  | 'credential_access'
  | 'lateral_movement'
  | 'credential_reuse'
  | 'privilege_escalation'
  | 'domain_compromise'

export type AttackNodeKind = 'entry' | 'host' | 'credential' | 'domain'

export interface AttackNode {
  id: string
  kind: AttackNodeKind
  label: string
  severity: string
  meta: Record<string, unknown>
}

export interface AttackEdge {
  source: string
  target: string
  kind: AttackEdgeKind
  label: string
  severity: string
  finding_ids: string[]
  /** True when the step is a reasoned hypothesis, not something the scan proved. */
  inferred: boolean
  cost: number
}

export interface AttackStep {
  kind: AttackEdgeKind
  label: string
  severity: string
  source: string
  target: string
  finding_ids: string[]
  inferred: boolean
}

export interface AttackPath {
  nodes: string[]
  objective: string
  severity: string
  /** Attacker effort — lower means easier for them, so worse for us. */
  cost: number
  length: number
  inferred: boolean
  steps: AttackStep[]
}

export interface Chokepoint {
  node_id: string
  label: string
  kind: AttackNodeKind
  path_count: number
}

export interface AttackPathGraph {
  scan_id: string
  nodes: AttackNode[]
  edges: AttackEdge[]
  paths: AttackPath[]
  chokepoints: Chokepoint[]
  summary: {
    host_count: number
    path_count: number
    confirmed_path_count: number
    worst_severity: string | null
  }
}

export const attackPathsApi = {
  get: (scanId: string, opts?: { includeInferred?: boolean; maxPaths?: number }) =>
    api
      .get<AttackPathGraph>(`/scans/${scanId}/attack-paths`, {
        params: {
          include_inferred: opts?.includeInferred ?? true,
          max_paths: opts?.maxPaths ?? 25,
        },
      })
      .then(r => r.data),
}
