const assert = require('node:assert/strict')
const { test } = require('node:test')
const {
  canonicalizeRequest,
  signCanonicalRequest,
  signUrl,
} = require('./auth')

test('canonical query excludes signature and sorts parameters', () => {
  const url = new URL(
    'http://localhost:3000/banner?z=last&heartide_sign=ignored&a=first',
  )
  const canonical = canonicalizeRequest('get', url.pathname, url.searchParams)
  assert.equal(canonical, 'GET\n/banner\na=first&z=last')
})

test('signed url can be recomputed from canonical request', () => {
  const signed = signUrl('/banner?type=2', {
    appId: 'heartide',
    secret: 'test-secret',
    timestamp: 1800000000,
    nonce: 'nonce-1',
  })
  const provided = signed.searchParams.get('heartide_sign')
  signed.searchParams.delete('heartide_sign')
  const canonical = canonicalizeRequest(
    'GET',
    signed.pathname,
    signed.searchParams,
  )
  const expected = signCanonicalRequest(canonical, 'test-secret')
  assert.equal(provided, expected)
})
