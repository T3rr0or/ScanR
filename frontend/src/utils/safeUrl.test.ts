import { describe, expect, it } from 'vitest'
import { isSafeUrl, safeUrl } from './safeUrl'

describe('safeUrl', () => {
  it('allows http, https and mailto', () => {
    expect(safeUrl('https://nvd.nist.gov/vuln/detail/CVE-2024-1234'))
      .toBe('https://nvd.nist.gov/vuln/detail/CVE-2024-1234')
    expect(safeUrl('http://192.0.2.10:8080/admin')).toBe('http://192.0.2.10:8080/admin')
    expect(safeUrl('mailto:security@example.com')).toBe('mailto:security@example.com')
  })

  it('blocks script-executing and data schemes', () => {
    // Scan data is not authored by us: plugin output, Nuclei templates, NVD
    // feeds and AI-created findings all feed the reference lists we render.
    expect(safeUrl('javascript:alert(1)')).toBeUndefined()
    expect(safeUrl('JavaScript:alert(1)')).toBeUndefined()
    expect(safeUrl('  javascript:alert(1)')).toBeUndefined()
    expect(safeUrl('java\tscript:alert(1)')).toBeUndefined()
    expect(safeUrl('data:text/html,<script>alert(1)</script>')).toBeUndefined()
    expect(safeUrl('vbscript:msgbox(1)')).toBeUndefined()
    expect(safeUrl('file:///etc/passwd')).toBeUndefined()
  })

  it('returns undefined for empty and unparseable values', () => {
    expect(safeUrl(null)).toBeUndefined()
    expect(safeUrl(undefined)).toBeUndefined()
    expect(safeUrl('')).toBeUndefined()
    expect(safeUrl('   ')).toBeUndefined()
  })

  it('isSafeUrl mirrors safeUrl', () => {
    expect(isSafeUrl('https://example.com')).toBe(true)
    expect(isSafeUrl('javascript:alert(1)')).toBe(false)
  })
})
