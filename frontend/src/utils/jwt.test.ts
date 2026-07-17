import { describe, expect, it } from 'vitest'
import { isAdminToken, parseJwtRole } from './jwt'

function makeToken(payload: unknown): string {
  const b64 = btoa(JSON.stringify(payload)).replace(/=+$/, '')
  return `header.${b64}.sig`
}

describe('parseJwtRole', () => {
  it('returns the role claim from the payload', () => {
    expect(parseJwtRole(makeToken({ role: 'admin' }))).toBe('admin')
    expect(parseJwtRole(makeToken({ role: 'analyst' }))).toBe('analyst')
  })

  it('defaults to analyst when the claim is missing', () => {
    expect(parseJwtRole(makeToken({ sub: 'user-1' }))).toBe('analyst')
  })

  it('defaults to analyst for null/undefined/garbage tokens', () => {
    expect(parseJwtRole(null)).toBe('analyst')
    expect(parseJwtRole(undefined)).toBe('analyst')
    expect(parseJwtRole('')).toBe('analyst')
    expect(parseJwtRole('not-a-jwt')).toBe('analyst')
    expect(parseJwtRole('a.!!!.b')).toBe('analyst')
    expect(parseJwtRole('a.b.c')).toBe('analyst')
  })
})

describe('isAdminToken', () => {
  it('is true only for the admin role', () => {
    expect(isAdminToken(makeToken({ role: 'admin' }))).toBe(true)
    expect(isAdminToken(makeToken({ role: 'analyst' }))).toBe(false)
    expect(isAdminToken(null)).toBe(false)
  })
})
