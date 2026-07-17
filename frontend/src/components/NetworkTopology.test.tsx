import { describe, expect, it } from 'vitest'
import { escapeHtml } from './NetworkTopology'

// Regression: the print/PDF window interpolates the user-controlled scan name
// into raw HTML of a same-origin window — without escaping this is stored XSS
// (script in that window can read sessionStorage tokens).
describe('escapeHtml', () => {
  it('neutralizes injected markup', () => {
    const out = escapeHtml('</h1><img src=x onerror=alert(1)>')
    expect(out).not.toContain('<')
    expect(out).not.toContain('>')
    expect(out).toBe('&lt;/h1&gt;&lt;img src=x onerror=alert(1)&gt;')
  })

  it('escapes ampersands and quotes', () => {
    expect(escapeHtml(`a&b"c'd`)).toBe('a&amp;b&quot;c&#39;d')
  })

  it('leaves safe text untouched', () => {
    expect(escapeHtml('Weekly internal scan 2024-06-01')).toBe('Weekly internal scan 2024-06-01')
  })
})
