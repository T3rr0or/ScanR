import api from './client'

export interface TimelinePoint {
  date: string
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

export interface TopVulnerableHost {
  id: string
  ip: string
  hostname: string | null
  finding_count: number
  /** Weighted by severity, not a raw count — see analytics.risk_expr. */
  risk_score: number
  /** Worst severity present on the host. */
  top_severity: string
}

export interface ScanActivityPoint {
  date: string
  scans: number
}

export const analyticsApi = {
  severityDistribution: (scan_id?: string) =>
    api.get<Record<string, number>>('/analytics/severity-distribution', {
      params: scan_id ? { scan_id } : undefined,
    }).then(r => r.data),

  findingsTimeline: (days = 30) =>
    api.get<TimelinePoint[]>(
      '/analytics/findings-timeline', { params: { days } }
    ).then(r => r.data),

  topVulnerableHosts: (limit = 10) =>
    api.get<TopVulnerableHost[]>(
      '/analytics/top-vulnerable-hosts', { params: { limit } }
    ).then(r => r.data),

  scanActivity: (days = 30) =>
    api.get<ScanActivityPoint[]>(
      '/analytics/scan-activity', { params: { days } }
    ).then(r => r.data),

  pluginHitRate: (limit = 20) =>
    api.get<Array<{ plugin_id: string; hit_count: number }>>(
      '/analytics/plugin-hit-rate', { params: { limit } }
    ).then(r => r.data),
}
