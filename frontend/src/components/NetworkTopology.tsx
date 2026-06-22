/**
 * NetworkTopology — D3 force-directed graph of discovered hosts.
 *
 * Single subnet:   all hosts connect directly to scanner node.
 * Multiple subnets: subnet gateway nodes sit between scanner and hosts —
 *                   scanner → subnet/24 → individual hosts.
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
  scanName?: string
}

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
  return Math.max(7, Math.min(22, 7 + Math.sqrt(openPorts) * 2.8))
}

async function exportPng(svgEl: SVGSVGElement, filename: string): Promise<string> {
  const width = svgEl.clientWidth || 800
  const height = svgEl.clientHeight || 500
  const scale = 2 // retina

  const serializer = new XMLSerializer()
  const svgStr = serializer.serializeToString(svgEl)
  const blob = new Blob([svgStr], { type: 'image/svg+xml;charset=utf-8' })
  const url = URL.createObjectURL(blob)

  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = () => {
      const canvas = document.createElement('canvas')
      canvas.width = width * scale
      canvas.height = height * scale
      const ctx = canvas.getContext('2d')!
      ctx.scale(scale, scale)
      ctx.fillStyle = '#0d1117'
      ctx.fillRect(0, 0, width, height)
      ctx.drawImage(img, 0, 0, width, height)
      URL.revokeObjectURL(url)
      const dataUrl = canvas.toDataURL('image/png')
      const a = document.createElement('a')
      a.href = dataUrl
      a.download = filename
      a.click()
      resolve(dataUrl)
    }
    img.onerror = reject
    img.src = url
  })
}

function printPdf(dataUrl: string, scanName: string, hostCount: number, date: string) {
  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Network Topology — ${scanName}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Arial, sans-serif; background: #fff; color: #111; padding: 32px; }
  h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
  .meta { font-size: 12px; color: #555; margin-bottom: 24px; }
  img { width: 100%; border: 1px solid #ddd; border-radius: 4px; }
  .legend { margin-top: 16px; font-size: 11px; color: #555; display: flex; gap: 16px; flex-wrap: wrap; }
  .dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 4px; vertical-align: middle; }
  @media print { body { padding: 0; } }
</style>
</head>
<body>
<h1>Network Topology — ${scanName}</h1>
<div class="meta">${hostCount} host${hostCount !== 1 ? 's' : ''} discovered · Generated ${date}</div>
<img src="${dataUrl}" alt="Network topology diagram">
<div class="legend">
  <span><span class="dot" style="background:#f43f5e"></span>Critical</span>
  <span><span class="dot" style="background:#f97316"></span>High</span>
  <span><span class="dot" style="background:#eab308"></span>Medium</span>
  <span><span class="dot" style="background:#22c55e"></span>Low</span>
  <span><span class="dot" style="background:#38bdf8"></span>Info</span>
  <span><span class="dot" style="background:#4b5563"></span>None</span>
  <span style="margin-left:auto">Node size = number of open ports</span>
</div>
</body>
</html>`
  const w = window.open('', '_blank')
  if (!w) return
  w.document.write(html)
  w.document.close()
  w.onload = () => { w.focus(); w.print() }
}

export default function NetworkTopology({ hosts, findingsByHost, onSelectHost, scanName = 'scan' }: Props) {
  const svgRef = useRef<SVGSVGElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [tooltip, setTooltip] = useState<{ x: number; y: number; host: HostNode } | null>(null)
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return

    const width = containerRef.current.clientWidth || 800
    const height = containerRef.current.clientHeight || 500
    const cx = width / 2
    const cy = height / 2

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', width).attr('height', height)

    // Grid background
    const defs = svg.append('defs')
    defs.append('pattern')
      .attr('id', 'topo-grid').attr('width', 32).attr('height', 32).attr('patternUnits', 'userSpaceOnUse')
      .append('path').attr('d', 'M 32 0 L 0 0 0 32').attr('fill', 'none').attr('stroke', '#1a2032').attr('stroke-width', 0.5)
    svg.append('rect').attr('width', width).attr('height', height).attr('fill', 'url(#topo-grid)')

    if (hosts.length === 0) return

    // Group hosts by /24 subnet
    const subnetMap: Record<string, HostNode[]> = {}
    hosts.forEach(h => {
      const s = subnet24(h.ip)
      if (!subnetMap[s]) subnetMap[s] = []
      subnetMap[s].push(h)
    })
    const subnets = Object.keys(subnetMap)
    const multiSubnet = subnets.length > 1

    // Build simulation nodes
    type SimNode = {
      id: string; _kind: 'scanner' | 'subnet' | 'host'
      ip?: string; subnet?: string; label?: string
      openPorts?: number; severity?: string
      hostData?: HostNode
      fx?: number | null; fy?: number | null
      x?: number; y?: number
    }

    const simNodes: SimNode[] = []

    // Scanner (fixed center)
    const scannerNode: SimNode = { id: '__scanner__', _kind: 'scanner', fx: cx, fy: cy }
    simNodes.push(scannerNode)

    // Subnet gateway nodes (only when multiple subnets)
    if (multiSubnet) {
      subnets.forEach(s => {
        simNodes.push({ id: `__subnet__${s}`, _kind: 'subnet', subnet: s, label: s + '.0/24' })
      })
    }

    // Host nodes
    hosts.forEach(h => {
      simNodes.push({
        id: h.id, _kind: 'host',
        ip: h.ip, subnet: subnet24(h.ip),
        openPorts: (h.ports ?? []).filter(p => p.state === 'open').length,
        severity: hostSeverity(h.ip, findingsByHost),
        hostData: h,
      })
    })

    // Build links
    const links: { source: string; target: string; _kind: 'trunk' | 'branch' }[] = []

    if (multiSubnet) {
      // Scanner → subnet gateways (trunk lines, stronger/longer)
      subnets.forEach(s => {
        links.push({ source: '__scanner__', target: `__subnet__${s}`, _kind: 'trunk' })
      })
      // Subnet gateway → hosts (branch lines)
      hosts.forEach(h => {
        links.push({ source: `__subnet__${subnet24(h.ip)}`, target: h.id, _kind: 'branch' })
      })
    } else {
      // Single subnet — all hosts connect directly to scanner
      hosts.forEach(h => {
        links.push({ source: '__scanner__', target: h.id, _kind: 'trunk' })
      })
    }

    const sim = d3.forceSimulation(simNodes as any)
      .force('link', d3.forceLink(links as any)
        .id((d: any) => d.id)
        .distance((d: any) => d._kind === 'trunk' ? 180 : 90)
        .strength((d: any) => d._kind === 'trunk' ? 0.18 : 0.25)
      )
      .force('charge', d3.forceManyBody().strength((d: any) => d._kind === 'subnet' ? -400 : -220))
      .force('collision', d3.forceCollide().radius((d: any) => {
        if (d._kind === 'scanner') return 30
        if (d._kind === 'subnet') return 22
        return nodeRadius(d.openPorts ?? 0) + 12
      }))
      .alphaDecay(0.018)

    const g = svg.append('g')
    svg.call(d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 8])
      .on('zoom', e => g.attr('transform', e.transform.toString())) as any)

    // ── Draw layers (back to front) ──

    // 1. All edges
    const edgeGroup = g.append('g')
    const edges = edgeGroup.selectAll('line')
      .data(links).enter().append('line')
      .attr('stroke', (d: any) => d._kind === 'trunk' ? '#1e3a5f' : '#1a2535')
      .attr('stroke-width', (d: any) => d._kind === 'trunk' ? 1.5 : 1)
      .attr('stroke-opacity', (d: any) => d._kind === 'trunk' ? 0.8 : 0.5)
      .attr('stroke-dasharray', (d: any) => d._kind === 'trunk' ? 'none' : '3,2')

    // 2. Subnet gateway nodes
    const subnetGroup = g.append('g')
    if (multiSubnet) {
      const subnetNodes = simNodes.filter(n => n._kind === 'subnet')
      const subnetGs = subnetGroup.selectAll('g')
        .data(subnetNodes).enter().append('g')
        .attr('cursor', 'default')

      // Outer dashed ring
      subnetGs.append('circle')
        .attr('r', 18)
        .attr('fill', 'none')
        .attr('stroke', '#1e3a5f')
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '4,3')

      // Inner fill
      subnetGs.append('circle')
        .attr('r', 13)
        .attr('fill', '#0d1420')
        .attr('stroke', '#1e4d7b')
        .attr('stroke-width', 1.5)

      // Subnet label
      subnetGs.append('text')
        .text((d: any) => (d.subnet ?? '').split('.').slice(0, 3).join('.') + '.x')
        .attr('text-anchor', 'middle')
        .attr('dy', '0.35em')
        .attr('font-size', 7.5)
        .attr('font-family', 'var(--font-mono, monospace)')
        .attr('fill', '#38bdf8')
        .attr('fill-opacity', 0.8)
        .attr('pointer-events', 'none')

      // /24 label below
      subnetGs.append('text')
        .text((_d: any) => '/24')
        .attr('text-anchor', 'middle')
        .attr('dy', 28)
        .attr('font-size', 8.5)
        .attr('font-family', 'var(--font-mono, monospace)')
        .attr('fill', '#38bdf8')
        .attr('fill-opacity', 0.4)
        .attr('pointer-events', 'none')
    }

    // 3. Host nodes
    const hostSimNodes = simNodes.filter(n => n._kind === 'host')
    const hostGs = g.append('g').selectAll('g')
      .data(hostSimNodes).enter().append('g')
      .attr('cursor', 'pointer')
      .call(d3.drag<SVGGElement, any>()
        .on('start', (ev, d: any) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag',  (ev, d: any) => { d.fx = ev.x; d.fy = ev.y })
        .on('end',   (ev, d: any) => { if (!ev.active) sim.alphaTarget(0); d.fx = null; d.fy = null })
      )

    // Glow ring for critical/high
    hostGs.filter((d: any) => d.severity === 'critical' || d.severity === 'high')
      .append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts ?? 0) + 5)
      .attr('fill', 'none')
      .attr('stroke', (d: any) => SEV_HEX[d.severity ?? 'none'] as string)
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.35)

    hostGs.append('circle')
      .attr('r', (d: any) => nodeRadius(d.openPorts ?? 0))
      .attr('fill', (d: any) => SEV_HEX[d.severity ?? 'none'])
      .attr('fill-opacity', 0.88)
      .attr('stroke', '#0d1117')
      .attr('stroke-width', 1.5)

    hostGs.append('text')
      .text((d: any) => d.ip ?? '')
      .attr('text-anchor', 'middle')
      .attr('dy', (d: any) => nodeRadius(d.openPorts ?? 0) + 12)
      .attr('font-size', 9)
      .attr('font-family', 'var(--font-mono, monospace)')
      .attr('fill', '#6b7280')
      .attr('pointer-events', 'none')

    hostGs
      .on('mouseenter', (ev, d: any) => {
        if (!svgRef.current || !d.hostData) return
        const rect = svgRef.current.getBoundingClientRect()
        setTooltip({ x: ev.clientX - rect.left, y: ev.clientY - rect.top, host: d.hostData })
      })
      .on('mouseleave', () => setTooltip(null))
      .on('click', (_, d: any) => { if (d.hostData) onSelectHost?.(d.hostData) })

    // 4. Scanner node (topmost)
    const scannerG = g.append('g').attr('cursor', 'default')
    scannerG.append('circle').attr('r', 22).attr('fill', 'none')
      .attr('stroke', '#38bdf8').attr('stroke-width', 1).attr('stroke-opacity', 0.2).attr('stroke-dasharray', '4,3')
    scannerG.append('circle').attr('r', 15).attr('fill', '#0d1117').attr('stroke', '#38bdf8').attr('stroke-width', 2)
    scannerG.append('line').attr('x1', -7).attr('x2', 7).attr('y1', 0).attr('y2', 0)
      .attr('stroke', '#38bdf8').attr('stroke-width', 1.5).attr('stroke-linecap', 'round')
    scannerG.append('line').attr('x1', 0).attr('x2', 0).attr('y1', -7).attr('y2', 7)
      .attr('stroke', '#38bdf8').attr('stroke-width', 1.5).attr('stroke-linecap', 'round')
    scannerG.append('circle').attr('r', 3).attr('fill', 'none').attr('stroke', '#38bdf8').attr('stroke-width', 1.5)
    scannerG.append('text').text('scanner')
      .attr('text-anchor', 'middle').attr('dy', 27).attr('font-size', 9)
      .attr('font-family', 'var(--font-mono, monospace)').attr('fill', '#38bdf8').attr('fill-opacity', 0.55)
      .attr('pointer-events', 'none')

    // ── Tick ──
    const subnetNodeEls = multiSubnet
      ? subnetGroup.selectAll<SVGGElement, SimNode>('g')
      : null

    sim.on('tick', () => {
      scannerG.attr('transform', `translate(${cx},${cy})`)

      edges
        .attr('x1', (d: any) => (typeof d.source === 'object' ? d.source.x : cx) ?? cx)
        .attr('y1', (d: any) => (typeof d.source === 'object' ? d.source.y : cy) ?? cy)
        .attr('x2', (d: any) => (typeof d.target === 'object' ? d.target.x : 0) ?? 0)
        .attr('y2', (d: any) => (typeof d.target === 'object' ? d.target.y : 0) ?? 0)

      if (subnetNodeEls) {
        subnetNodeEls.attr('transform', (d: any) => `translate(${d.x ?? cx},${d.y ?? cy})`)
      }

      hostGs.attr('transform', (d: any) => `translate(${d.x ?? 0},${d.y ?? 0})`)
    })

    return () => { sim.stop() }
  }, [hosts, findingsByHost])

  const sevLegend = ['critical', 'high', 'medium', 'low', 'info', 'none']

  return (
    <div ref={containerRef} style={{ position: 'relative', width: '100%', height: '100%', background: 'var(--bg-1)', borderRadius: 8, overflow: 'hidden' }}>
      <svg ref={svgRef} style={{ width: '100%', height: '100%', display: 'block' }} />

      {/* Legend + export */}
      <div style={{
        position: 'absolute', top: 12, right: 12,
        background: 'var(--bg-2)', border: '1px solid var(--border)',
        borderRadius: 8, padding: '10px 12px', fontSize: 11,
        display: 'flex', flexDirection: 'column', gap: 4,
      }}>
        {sevLegend.map(sev => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: SEV_HEX[sev], flexShrink: 0 }} />
            <span style={{ color: 'var(--text-2)', textTransform: 'capitalize' }}>{sev}</span>
          </div>
        ))}
        <div style={{ borderTop: '1px solid var(--border)', marginTop: 4, paddingTop: 4, color: 'var(--text-3)', lineHeight: 1.7 }}>
          <div>Node size = open ports</div>
          <div>Scroll to zoom · drag to pan</div>
        </div>
        <div style={{ borderTop: '1px solid var(--border)', marginTop: 4, paddingTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <button
            disabled={exporting || hosts.length === 0}
            style={{
              fontSize: 11, padding: '4px 8px', borderRadius: 4, cursor: 'pointer',
              background: 'var(--bg-3)', border: '1px solid var(--border)',
              color: 'var(--text-1)', opacity: (exporting || hosts.length === 0) ? 0.4 : 1,
            }}
            onClick={async () => {
              if (!svgRef.current) return
              setExporting(true)
              try {
                const slug = scanName.replace(/[^a-z0-9]+/gi, '-').toLowerCase()
                await exportPng(svgRef.current, `topology-${slug}.png`)
              } finally {
                setExporting(false)
              }
            }}
          >
            {exporting ? 'Exporting…' : '↓ Export PNG'}
          </button>
          <button
            disabled={exporting || hosts.length === 0}
            style={{
              fontSize: 11, padding: '4px 8px', borderRadius: 4, cursor: 'pointer',
              background: 'var(--bg-3)', border: '1px solid var(--border)',
              color: 'var(--text-1)', opacity: (exporting || hosts.length === 0) ? 0.4 : 1,
            }}
            onClick={async () => {
              if (!svgRef.current) return
              setExporting(true)
              try {
                const slug = scanName.replace(/[^a-z0-9]+/gi, '-').toLowerCase()
                const dataUrl = await exportPng(svgRef.current, `topology-${slug}.png`)
                const date = new Date().toLocaleString()
                printPdf(dataUrl, scanName, hosts.length, date)
              } finally {
                setExporting(false)
              }
            }}
          >
            {exporting ? 'Exporting…' : '↓ Export PDF'}
          </button>
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
