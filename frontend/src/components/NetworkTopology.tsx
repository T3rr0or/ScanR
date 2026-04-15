/**
 * NetworkTopology — D3 force-directed graph of discovered hosts.
 *
 * Layout: pure force repulsion, no subnet chain — nodes spread organically.
 * Subnet siblings get weak attraction so same-/24 nodes loosely cluster.
 * Nodes sized by open port count, colored by highest severity finding.
 */
import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'

interface HostNode {
  id: string
  ip: string
  hostname?: string
  os_name?: string
  ports?: { number: number; state: string }[]
  status: string
}

interface Props {
  hosts: HostNode[]
  findingsByHost?: Record<string, { severity: string }[]>
  onSelectHost?: (host: HostNode) => void
}

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#3b82f6',
  none:     '#4b5563',
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

function hostSeverity(ip: string, findingsByHost?: Record<string, { severity: string }[]>): string {
  if (!findingsByHost) return 'none'
  const findings = findingsByHost[ip] ?? []
  for (const sev of SEV_ORDER) {
    if (findings.some(f => f.severity === sev)) return sev
  }
  return 'none'
}

function subnet24(ip: string): string {
  return ip.split('.').slice(0, 3).join('.')
}

function nodeRadius(openPorts: number): number {
  return Math.max(7, Math.min(24, 7 + Math.sqrt(openPorts) * 3))
}

export default function NetworkTopology({ hosts, findingsByHost, onSelectHost }: Props) {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [tooltip, setTooltip] = useState<{ x: number; y: number; host: HostNode } | null>(null)

  useEffect(() => {
    if (!svgRef.current || !containerRef.current || hosts.length === 0) return

    const width = containerRef.current.clientWidth || 800
    const height = containerRef.current.clientHeight || 500

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    // Build nodes
    const nodes = hosts.map(h => ({
      ...h,
      openPorts: (h.ports ?? []).filter(p => p.state === 'open').length,
      severity: hostSeverity(h.ip, findingsByHost),
      subnet: subnet24(h.ip),
    }))

    // Weak subnet links — pull same-/24 nodes together without chaining
    const subnetMap: Record<string, string[]> = {}
    nodes.forEach(n => {
      if (!subnetMap[n.subnet]) subnetMap[n.subnet] = []
      subnetMap[n.subnet].push(n.id)
    })

    // Connect each node to the first node in its subnet (star within subnet, not chain)
    const links: { source: string; target: string }[] = []
    Object.values(subnetMap).forEach(group => {
      if (group.length < 2) return
      const anchor = group[0]
      for (let i = 1; i < group.length; i++) {
        links.push({ source: anchor, target: group[i] })
      }
    })

    // Simulation
    const sim = d3.forceSimulation(nodes as any)
      .force('link', d3.forceLink(links)
        .id((d: any) => d.id)
        .distance(80)
        .strength(0.05)   // very weak — just a gentle pull, not rigid
      )
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius((d: any) => nodeRadius(d.openPorts) + 10))
      .alphaDecay(0.02)

    const g = svg.append('g')

    svg.call(d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.15, 6])
      .on('zoom', e => { g.attr('transform', e.transform.toString()) }) as any)

    // Subnet boundary rings (drawn first, behind nodes)
    const subnetRingGroup = g.append('g').attr('class', 'subnet-rings')

    // invisible links — just force hints, not rendered
    g.append('g')
      .selectAll('line')
      .data(links).enter().append('line')
      .attr('stroke-opacity', 0)

    // Nodes
    const nodeGroup = g.append('g')
      .selectAll('g')
      .data(nodes).enter().append('g')
      .attr('cursor', 'pointer')
      .call(d3.drag<SVGGElement, any>()
        .on('start', (event, d: any) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (event, d: any) => { d.fx = event.x; d.fy = event.y })
        .on('end', (event, d: any) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )

    // Glow ring for critical/high
    nodeGroup.filter((d: any) => d.severity === 'critical' || d.severity === 'high')
      .append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts) + 5)
      .attr('fill', 'none')
      .attr('stroke', (d: any) => SEV_COLOR[d.severity])
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.4)

    nodeGroup.append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts))
      .attr('fill', (d: any) => SEV_COLOR[d.severity])
      .attr('fill-opacity', 0.9)
      .attr('stroke', '#111827')
      .attr('stroke-width', 1.5)

    // Last-octet label below node
    nodeGroup.append('text')
      .text((d: any) => d.ip)
      .attr('text-anchor', 'middle')
      .attr('dy', (d: any) => nodeRadius(d.openPorts) + 12)
      .attr('font-size', 9)
      .attr('fill', '#6b7280')
      .attr('pointer-events', 'none')

    nodeGroup.on('mouseenter', (event, d: any) => {
      const rect = svgRef.current!.getBoundingClientRect()
      setTooltip({ x: event.clientX - rect.left, y: event.clientY - rect.top, host: d })
    })
    nodeGroup.on('mouseleave', () => setTooltip(null))
    nodeGroup.on('click', (_, d: any) => { onSelectHost?.(d) })

    // Draw convex-hull subnet backgrounds after simulation settles
    sim.on('tick', () => {
      nodeGroup.attr('transform', (d: any) => `translate(${d.x},${d.y})`)

      // Update subnet hulls
      subnetRingGroup.selectAll('*').remove()
      const subnets = Object.entries(subnetMap)
      if (subnets.length > 1) {
        subnets.forEach(([subnet, ids]) => {
          const pts = ids.map(id => {
            const n = (nodes as any[]).find(n => n.id === id)
            return n ? [n.x, n.y] as [number, number] : null
          }).filter(Boolean) as [number, number][]

          if (pts.length < 3) return
          const hull = d3.polygonHull(pts)
          if (!hull) return

          // Expand hull outward a bit
          const cx = d3.mean(hull, d => d[0])!
          const cy = d3.mean(hull, d => d[1])!
          const expanded = hull.map(([x, y]) => {
            const dx = x - cx, dy = y - cy
            const dist = Math.sqrt(dx * dx + dy * dy) || 1
            return [x + (dx / dist) * 20, y + (dy / dist) * 20] as [number, number]
          })

          subnetRingGroup.append('path')
            .attr('d', `M${expanded.map(p => p.join(',')).join('L')}Z`)
            .attr('fill', '#1e3a5f')
            .attr('fill-opacity', 0.12)
            .attr('stroke', '#3b82f6')
            .attr('stroke-opacity', 0.2)
            .attr('stroke-width', 1)
            .attr('stroke-dasharray', '4,3')

          subnetRingGroup.append('text')
            .attr('x', cx)
            .attr('y', cy - 8)
            .attr('text-anchor', 'middle')
            .attr('font-size', 10)
            .attr('fill', '#3b82f6')
            .attr('fill-opacity', 0.4)
            .attr('pointer-events', 'none')
            .text(subnet + '.0/24')
        })
      }
    })

    return () => { sim.stop() }
  }, [hosts, findingsByHost])

  return (
    <div ref={containerRef} className="relative w-full h-full bg-gray-950 rounded-lg overflow-hidden">
      <svg ref={svgRef} className="w-full h-full" />

      {/* Legend */}
      <div className="absolute top-3 right-3 bg-gray-900/90 border border-gray-800 rounded-lg p-2.5 text-xs space-y-1">
        {Object.entries(SEV_COLOR).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full inline-block flex-shrink-0" style={{ background: color }} />
            <span className="text-gray-400 capitalize">{sev}</span>
          </div>
        ))}
        <div className="border-t border-gray-700 pt-1 mt-1 text-gray-500 space-y-0.5">
          <div>Node size = open ports</div>
          <div>Scroll to zoom · drag to pan</div>
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="absolute pointer-events-none bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-xs shadow-lg z-10"
          style={{ left: tooltip.x + 14, top: tooltip.y - 8, maxWidth: 240 }}
        >
          <div className="font-mono font-semibold text-white">{tooltip.host.ip}</div>
          {tooltip.host.hostname && <div className="text-gray-400">{tooltip.host.hostname}</div>}
          {tooltip.host.os_name && <div className="text-gray-500 truncate">{tooltip.host.os_name}</div>}
          <div className="text-gray-400 mt-1">
            {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length} open port(s)
          </div>
          {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length > 0 && (
            <div className="text-gray-500 mt-0.5 font-mono">
              {(tooltip.host.ports ?? []).filter(p => p.state === 'open').slice(0, 8).map(p => p.number).join(', ')}
              {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length > 8 && '…'}
            </div>
          )}
        </div>
      )}

      {hosts.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-gray-600 text-sm">
          No hosts discovered yet
        </div>
      )}
    </div>
  )
}
