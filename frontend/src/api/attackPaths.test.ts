import { describe, expect, it } from 'vitest'
import { parseAttackPathGraph } from './attackPaths'

const emptyGraph = {
  scan_id: 'scan-1',
  nodes: [],
  edges: [],
  paths: [],
  chokepoints: [],
  truncated: false,
  totals: { nodes: 0, edges: 0 },
  inferred_paths_available: 0,
  summary: { host_count: 0, path_count: 0, confirmed_path_count: 0, worst_severity: null },
}

describe('parseAttackPathGraph', () => {
  it('accepts a valid empty graph', () => {
    expect(parseAttackPathGraph(emptyGraph)).toBe(emptyGraph)
  })

  it('rejects a malformed API response before the view renders', () => {
    expect(() => parseAttackPathGraph([])).toThrow('invalid API response')
    expect(() => parseAttackPathGraph({ ...emptyGraph, nodes: undefined })).toThrow('incomplete API response')
    expect(() => parseAttackPathGraph({ ...emptyGraph, paths: [{ nodes: [], steps: undefined }] })).toThrow('incomplete API response')
  })
})
