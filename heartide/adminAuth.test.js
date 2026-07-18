const assert = require('node:assert/strict')
const { test } = require('node:test')
const {
  createSessionToken,
  verifySessionToken,
} = require('./adminAuth')

test('admin session token verifies before expiry', () => {
  const config = {
    username: 'admin',
    sessionSecret: 'test-session-secret',
    ttlSeconds: 60,
  }
  const token = createSessionToken('admin', config, 100)
  assert.equal(verifySessionToken(token, config, 120), true)
})

test('admin session token rejects tampering and expiry', () => {
  const config = {
    username: 'admin',
    sessionSecret: 'test-session-secret',
    ttlSeconds: 60,
  }
  const token = createSessionToken('admin', config, 100)
  assert.equal(verifySessionToken(`${token}x`, config, 120), false)
  assert.equal(verifySessionToken(token, config, 200), false)
})
