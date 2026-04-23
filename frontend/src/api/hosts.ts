/** TypeScript interfaces for host data returned by GET /api/v1/scans/{id}/hosts */

export interface HostPort {
  number: number
  protocol: string
  state: string
  service?: string
  version?: string
  banner?: string
}

export interface HostRead {
  id: string
  ip: string
  hostname?: string
  mac_address?: string
  os_name?: string
  os_accuracy?: number
  status: string
  ports?: HostPort[]
}
