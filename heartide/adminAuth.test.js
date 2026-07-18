const assert = require('node:assert/strict')
const { test } = require('node:test')
const {
  createHeartideAdminAuthMiddleware,
  createSessionToken,
  verifySessionToken,
} = require('./adminAuth')

function withAdminEnv(env, fn) {
  const keys = [
    'HEARTIDE_ADMIN_AUTH_ENABLED',
    'HEARTIDE_ADMIN_USERNAME',
    'HEARTIDE_ADMIN_PASSWORD',
    'HEARTIDE_ADMIN_PASSWORD_SHA256',
    'HEARTIDE_ADMIN_SESSION_SECRET',
    'HEARTIDE_APP_SECRET',
  ]
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]))
  keys.forEach((key) => {
    delete process.env[key]
  })
  Object.assign(process.env, env)
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      keys.forEach((key) => {
        if (previous[key] === undefined) {
          delete process.env[key]
        } else {
          process.env[key] = previous[key]
        }
      })
    })
}

async function runMiddleware(req) {
  const middleware = createHeartideAdminAuthMiddleware()
  let nextCalled = false
  let body = ''
  const headers = {}
  const res = {
    statusCode: 200,
    setHeader(name, value) {
      headers[name.toLowerCase()] = value
    },
    end(value = '') {
      body += value
    },
  }
  await middleware(req, res, () => {
    nextCalled = true
  })
  return { res, headers, body, nextCalled }
}

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

test('admin docs root redirects to login when admin config is missing', async () => {
  await withAdminEnv({}, async () => {
    const { res, headers, nextCalled } = await runMiddleware({
      path: '/',
      method: 'GET',
      headers: { accept: 'text/html' },
    })

    assert.equal(nextCalled, false)
    assert.equal(res.statusCode, 302)
    assert.equal(headers.location, '/heartide/login')
  })
})

test('admin login page renders config guidance when admin config is missing', async () => {
  await withAdminEnv({}, async () => {
    const { res, headers, body, nextCalled } = await runMiddleware({
      path: '/heartide/login',
      method: 'GET',
      headers: { accept: 'text/html' },
    })

    assert.equal(nextCalled, false)
    assert.equal(res.statusCode, 200)
    assert.equal(headers['content-type'], 'text/html; charset=utf-8')
    assert.match(body, /管理员账号未配置/)
    assert.match(body, /HEARTIDE_ADMIN_USERNAME/)
  })
})
