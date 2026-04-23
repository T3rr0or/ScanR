/**
 * NetworkTopology — D3 force-directed graph of discovered hosts.
 * Center node = scanner itself. Hosts orbit around it.
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

// Resolved hex values for D3 (can't use CSS vars in SVG attributes directly)
const SEV_HEX: Record<string, string> = {
  critical: '#f43f5e',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#22c55e',
  info:     '#38bdf8',
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
    if (!svgRef.current || !containerRef.current) return

    const width = containerRef.current.clientWidth || 800
    const height = containerRef.current.clientHeight || 500

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    // Grid background
    const defs = svg.append('defs')
    defs.append('pattern')
      .attr('id', 'topo-grid')
      .attr('width', 32)
      .attr('height', 32)
      .attr('patternUnits', 'userSpaceOnUse')
      .append('path')
        .attr('d', 'M 32 0 L 0 0 0 32')
        .attr('fill', 'none')
        .attr('stroke', '#1f2937')
        .attr('stroke-width', 0.5)

    svg.append('rect')
      .attr('width', width)
      .attr('height', height)
      .attr('fill', 'url(#topo-grid)')

    if (hosts.length === 0) return

    // Build nodes
    const nodes = hosts.map(h => ({
      ...h,
      openPorts: (h.ports ?? []).filter(p => p.state === 'open').length,
      severity: hostSeverity(h.ip, findingsByHost),
      subnet: subnet24(h.ip),
      _isScanner: false,
    }))

    // Center scanner node (fixed at center)
    const scannerNode: any = {
      id: '__scanner__',
      ip: 'Scanner',
      _isScanner: true,
      openPorts: 0,
      severity: 'none',
      subnet: '',
      fx: width / 2,
      fy: height / 2,
    }
    const allNodes = [scannerNode, ...nodes]

    // Links: every host → scanner center
    const links: { source: string; target: string }[] = nodes.map(n => ({
      source: '__scanner__',
      target: n.id,
    }))

    // Weak subnet links — pull same-/24 nodes together
    const subnetMap: Record<string, string[]> = {}
    nodes.forEach(n => {
      if (!subnetMap[n.subnet]) subnetMap[n.subnet] = []
      subnetMap[n.subnet].push(n.id)
    })
    Object.values(subnetMap).forEach(group => {
      if (group.length < 2) return
      const anchor = group[0]
      for (let i = 1; i < group.length; i++) {
        links.push({ source: anchor, target: group[i] })
      }
    })

    const sim = d3.forceSimulation(allNodes as any)
      .force('link', d3.forceLink(links)
        .id((d: any) => d.id)
        .distance((d: any) => d.source.id === '__scanner__' ? 140 : 80)
        .strength((d: any) => d.source.id === '__scanner__' ? 0.12 : 0.05)
      )
      .force('charge', d3.forceManyBody().strength(-260))
      .force('collision', d3.forceCollide().radius((d: any) => d._isScanner ? 28 : nodeRadius(d.openPorts) + 10))
      .alphaDecay(0.02)

    const g = svg.append('g')

    svg.call(d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.15, 6])
      .on('zoom', e => { g.attr('transform', e.transform.toString()) }) as any)

    // Subnet hulls (behind everything)
    const subnetRingGroup = g.append('g')

    // Edges — thin lines from scanner to each host
    const linkGroup = g.append('g')
      .selectAll('line')
      .data(links.filter((l: any) => l.source === '__scanner__' || (typeof l.source === 'object' && (l.source as any).id === '__scanner__')))
      .enter().append('line')
      .attr('stroke', '#1f2937')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.6)

    // Host nodes
    const hostGroup = g.append('g')
      .selectAll('g')
      .data(nodes).enter().append('g')
      .attr('cursor', 'pointer')
      .call(d3.drag<SVGGElement, any>()
        .on('start', (event, d: any) => { if (!event.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag', (event, d: any) => { d.fx = event.x; d.fy = event.y })
        .on('end', (event, d: any) => { if (!event.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )

    // Glow ring for critical/high
    hostGroup.filter((d: any) => d.severity === 'critical' || d.severity === 'high')
      .append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts) + 5)
      .attr('fill', 'none')
      .attr('stroke', (d: any) => SEV_HEX[d.severity])
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.4)

    hostGroup.append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts))
      .attr('fill', (d: any) => SEV_HEX[d.severity])
      .attr('fill-opacity', 0.9)
      .attr('stroke', '#0d1117')
      .attr('stroke-width', 1.5)

    hostGroup.append('text')
      .text((d: any) => d.ip)
      .attr('text-anchor', 'middle')
      .attr('dy', (d: any) => nodeRadius(d.openPorts) + 12)
      .attr('font-size', 9)
      .attr('font-family', 'var(--font-mono, monospace)')
      .attr('fill', '#6b7280')
      .attr('pointer-events', 'none')

    hostGroup
      .on('mouseenter', (event, d: any) => {
        const rect = svgRef.current!.getBoundingClientRect()
        setTooltip({ x: event.clientX - rect.left, y: event.clientY - rect.top, host: d })
      })
      .on('mouseleave', () => setTooltip(null))
      .on('click', (_, d: any) => { onSelectHost?.(d) })

    // Center scanner node (drawn on top)
    const scannerG = g.append('g').attr('cursor', 'default')

    // Outer pulse ring
    scannerG.append('circle')
      .attr('r', 22)
      .attr('fill', 'none')
      .attr('stroke', '#38bdf8')
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.25)
      .attr('stroke-dasharray', '4,3')

    scannerG.append('circle')
      .attr('r', 16)
      .attr('fill', '#0d1117')
      .attr('stroke', '#38bdf8')
      .attr('stroke-width', 2)

    // Scanner crosshair icon
    scannerG.append('line').attr('x1', -8).attr('x2', 8).attr('y1', 0).attr('y2', 0)
      .attr('stroke', '#38bdf8').attr('stroke-width', 1.5).attr('stroke-linecap', 'round')
    scannerG.append('line').attr('x1', 0).attr('x2', 0).attr('y1', -8).attr('y2', 8)
      .attr('stroke', '#38bdf8').attr('stroke-width', 1.5).attr('stroke-linecap', 'round')
    scannerG.append('circle').attr('r', 3).attr('fill', 'none').attr('stroke', '#38bdf8').attr('stroke-width', 1.5)

    scannerG.append('text')
      .text('scanner')
      .attr('text-anchor', 'middle')
      .attr('dy', 28)
      .attr('font-size', 9)
      .attr('font-family', 'var(--font-mono, monospace)')
      .attr('fill', '#38bdf8')
      .attr('fill-opacity', 0.6)
      .attr('pointer-events', 'none')

    sim.on('tick', () => {
      // Position scanner node
      scannerG.attr('transform', `translate(${width / 2},${height / 2})`)

      // Position host nodes
      hostGroup.attr('transform', (d: any) => `translate(${d.x},${d.y})`)

      // Update edge lines
      linkGroup
        .attr('x1', width / 2)
        .attr('y1', height / 2)
        .attr('x2', (d: any) => {
          const target = typeof d.target === 'object' ? d.target : allNodes.find(n => n.id === d.target)
          return target?.x ?? 0
        })
        .attr('y2', (d: any) => {
          const target = typeof d.target === 'object' ? d.target : allNodes.find(n => n.id === d.target)
          return target?.y ?? 0
        })

      // Subnet hulls
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
          const cx = d3.mean(hull, d => d[0])!
          const cy = d3.mean(hull, d => d[1])!
          const expanded = hull.map(([x, y]) => {
            const dx = x - cx, dy = y - cy
            const dist = Math.sqrt(dx * dx + dy * dy) || 1
            return [x + (dx / dist) * 20, y + (dy / dist) * 20] as [number, number]
          })
          subnetRingGroup.append('path')
            .attr('d', `M${expanded.map(p => p.join(',')).join('L')}Z`)
            .attr('fill', '#0ea5e920')
            .attr('stroke', '#0ea5e9')
            .attr('stroke-opacity', 0.18)
            .attr('stroke-width', 1)
            .attr('stroke-dasharray', '4,3')
          subnetRingGroup.append('text')
            .attr('x', cx).attr('y', cy - 8)
            .attr('text-anchor', 'middle')
            .attr('font-size', 10)
            .attr('font-family', 'var(--font-mono, monospace)')
            .attr('fill', '#0ea5e9')
            .attr('fill-opacity', 0.4)
            .attr('pointer-events', 'none')
            .text(subnet + '.0/24')
        })
      }
    })

    return () => { sim.stop() }
  }, [hosts, findingsByHost])

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', height: '100%', background: 'var(--bg-1)', borderRadius: 8, overflow: 'hidden' }}>
      <svg ref={svgRef} style={{ width: '100%', height: '100%', display: 'block' }} />

      {/* Legend */}
      <div style={{
        position: 'absolute', top: 12, right: 12,
        background: 'var(--bg-2)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '10px 12px',
        fontSize: 11, display: 'flex', flexDirection: 'column', gap: 4,
      }}>
        {SEV_ORDER.concat(['none']).map(sev => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: SEV_HEX[sev], flexShrink: 0 }} />
            <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{sev}</span>
          </div>
        ))}
        <div style={{ borderTop: '1px solid var(--border)', marginTop: 4, paddingTop: 4, color: 'var(--text-3)', lineHeight: 1.6 }}>
          <div>Node size = open ports</div>
          <div>Scroll to zoom · drag to pan</div>
        </div>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div style={{
          position: 'absolute', pointerEvents: 'none',
          left: tooltip.x + 14, top: tooltip.y - 8,
          background: 'var(--bg-2)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '8px 12px', fontSize: 12, maxWidth: 240,
          boxShadow: '0 4px 20px #0006', zIndex: 10,
        }}>
          <div className="mono" style={{ fontWeight: 600, color: 'var(--text-0)' }}>{tooltip.host.ip}</div>
          {tooltip.host.hostname && <div style={{ color: 'var(--text-2)' }}>{tooltip.host.hostname}</div>}
          {tooltip.host.os_name && <div style={{ color: 'var(--text-3)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{tooltip.host.os_name}</div>}
          <div style={{ color: 'var(--text-2)', marginTop: 4 }}>
            {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length} open port(s)
          </div>
          {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length > 0 && (
            <div className="mono" style={{ color: 'var(--text-3)', marginTop: 2 }}>
              {(tooltip.host.ports ?? []).filter(p => p.state === 'open').slice(0, 8).map(p => p.number).join(', ')}
              {(tooltip.host.ports ?? []).filter(p => p.state === 'open').length > 8 && '…'}
            </div>
          )}
        </div>
      )}

      {hosts.length === 0 && (
        <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', fontSize: 13 }}>
          No hosts discovered yet
        </div>
      )}
    </div>
  )
}
