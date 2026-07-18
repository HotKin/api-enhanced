const crypto = require('crypto')

const DEFAULT_SESSION_TTL_SECONDS = 12 * 60 * 60
const DEFAULT_LOGIN_PATH = '/heartide/login'
const DEFAULT_LOGOUT_PATH = '/heartide/logout'

const loginAttempts = new Map()

function isAdminAuthEnabled() {
  return process.env.HEARTIDE_ADMIN_AUTH_ENABLED !== 'false'
}

function readNumber(name, fallback) {
  const raw = process.env[name]
  if (!raw) return fallback
  const value = Number(raw)
  return Number.isFinite(value) && value > 0 ? value : fallback
}

function readAdminConfig() {
  const username = process.env.HEARTIDE_ADMIN_USERNAME || ''
  const password = process.env.HEARTIDE_ADMIN_PASSWORD || ''
  const passwordHash = process.env.HEARTIDE_ADMIN_PASSWORD_SHA256 || ''
  const sessionSecret =
    process.env.HEARTIDE_ADMIN_SESSION_SECRET ||
    process.env.HEARTIDE_APP_SECRET ||
    ''
  return {
    username,
    password,
    passwordHash,
    sessionSecret,
    ttlSeconds: readNumber(
      'HEARTIDE_ADMIN_SESSION_TTL_SECONDS',
      DEFAULT_SESSION_TTL_SECONDS,
    ),
    loginPath: process.env.HEARTIDE_ADMIN_LOGIN_PATH || DEFAULT_LOGIN_PATH,
    logoutPath: process.env.HEARTIDE_ADMIN_LOGOUT_PATH || DEFAULT_LOGOUT_PATH,
  }
}

function isConfigured(config) {
  return (
    Boolean(config.username) &&
    (Boolean(config.password) || Boolean(config.passwordHash)) &&
    Boolean(config.sessionSecret)
  )
}

function parseCookies(cookieHeader) {
  const cookies = {}
  ;(cookieHeader || '').split(/;\s*/g).forEach((pair) => {
    const splitAt = pair.indexOf('=')
    if (splitAt <= 0) return
    const key = pair.slice(0, splitAt).trim()
    const value = pair.slice(splitAt + 1).trim()
    if (key) cookies[key] = decodeURIComponent(value)
  })
  return cookies
}

function parseFormBody(req, maxBytes = 8192) {
  return new Promise((resolve, reject) => {
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => {
      body += chunk
      if (body.length > maxBytes) {
        reject(new Error('form_body_too_large'))
        req.destroy()
      }
    })
    req.on('end', () => {
      const data = new URLSearchParams(body)
      resolve({
        username: data.get('username') || '',
        password: data.get('password') || '',
      })
    })
    req.on('error', reject)
  })
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex')
}

function hmacHex(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest('hex')
}

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(left)
  const rightBuffer = Buffer.from(right)
  if (leftBuffer.length !== rightBuffer.length) {
    return false
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer)
}

function passwordMatches(input, config) {
  if (config.passwordHash) {
    return timingSafeEqualString(sha256Hex(input), config.passwordHash)
  }
  return timingSafeEqualString(input, config.password)
}

function createSessionToken(username, config, nowSeconds = now()) {
  const expiresAt = nowSeconds + config.ttlSeconds
  const nonce = crypto.randomBytes(16).toString('hex')
  const payload = Buffer.from(
    JSON.stringify({ username, expiresAt, nonce }),
  ).toString('base64url')
  const signature = hmacHex(config.sessionSecret, payload)
  return `${payload}.${signature}`
}

function verifySessionToken(token, config, nowSeconds = now()) {
  const splitAt = token.lastIndexOf('.')
  if (splitAt <= 0) return false
  const payload = token.slice(0, splitAt)
  const signature = token.slice(splitAt + 1)
  const expected = hmacHex(config.sessionSecret, payload)
  if (!timingSafeEqualString(signature, expected)) {
    return false
  }
  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString())
    return session.username === config.username && session.expiresAt > nowSeconds
  } catch (_) {
    return false
  }
}

function now() {
  return Math.floor(Date.now() / 1000)
}

function isSecureRequest(req) {
  return req.secure || req.headers['x-forwarded-proto'] === 'https'
}

function setSessionCookie(req, res, token, config) {
  const secure = isSecureRequest(req) ? '; Secure' : ''
  res.setHeader(
    'Set-Cookie',
    `heartide_admin=${encodeURIComponent(
      token,
    )}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${config.ttlSeconds}${secure}`,
  )
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'heartide_admin=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
  )
}

function redirect(res, location) {
  res.statusCode = 302
  res.setHeader('Location', location)
  res.end()
}

function wantsHtml(req) {
  const accept = req.headers.accept || ''
  return accept.includes('text/html') || accept.includes('*/*')
}

function renderLogin(res, config, errorMessage = '') {
  res.statusCode = 200
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.end(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Heartide API 登录</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#101318;color:#edf1f7;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{width:min(360px,calc(100vw - 40px));padding:28px;border:1px solid #28303a;border-radius:8px;background:#171c23}
    h1{margin:0 0 8px;font-size:22px}
    p{margin:0 0 20px;color:#9aa7b7;font-size:14px;line-height:1.5}
    label{display:block;margin:14px 0 6px;color:#cbd5e1;font-size:13px}
    input{width:100%;box-sizing:border-box;border:1px solid #384354;border-radius:6px;background:#0f141b;color:#fff;padding:11px 12px;font-size:15px}
    button{width:100%;margin-top:18px;border:0;border-radius:6px;background:#4dd0c8;color:#071011;padding:11px 12px;font-weight:700;font-size:15px}
    .error{margin:0 0 12px;color:#ffb4a8}
  </style>
</head>
<body>
  <main>
    <h1>Heartide API</h1>
    <p>访问 API 文档和静态资料需要登录。业务接口仍使用 App 请求签名。</p>
    ${errorMessage ? `<p class="error">${htmlEscape(errorMessage)}</p>` : ''}
    <form method="post" action="${htmlEscape(config.loginPath)}">
      <label for="username">账号</label>
      <input id="username" name="username" autocomplete="username" required>
      <label for="password">密码</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>
      <button type="submit">登录</button>
    </form>
  </main>
</body>
</html>`)
}

function missingConfigMessage() {
  return '管理员账号未配置，请设置 HEARTIDE_ADMIN_USERNAME、HEARTIDE_ADMIN_PASSWORD_SHA256（或 HEARTIDE_ADMIN_PASSWORD）和 HEARTIDE_ADMIN_SESSION_SECRET。'
}

function renderMissingConfig(res) {
  res.statusCode = 503
  res.setHeader('Content-Type', 'application/json; charset=utf-8')
  res.end(
    JSON.stringify({
      code: 503,
      msg: 'Heartide admin authentication is not configured',
      required:
        'HEARTIDE_ADMIN_USERNAME + HEARTIDE_ADMIN_PASSWORD_SHA256(or HEARTIDE_ADMIN_PASSWORD) + HEARTIDE_ADMIN_SESSION_SECRET',
    }),
  )
}

function isLoginRateLimited(req) {
  const maxAttempts = readNumber('HEARTIDE_ADMIN_LOGIN_MAX_ATTEMPTS', 8)
  const windowSeconds = readNumber('HEARTIDE_ADMIN_LOGIN_WINDOW_SECONDS', 300)
  const key =
    req.ip ||
    req.socket?.remoteAddress ||
    req.headers['x-forwarded-for'] ||
    'unknown'
  const current = now()
  const attempt = loginAttempts.get(key) || {
    count: 0,
    resetAt: current + windowSeconds,
  }
  if (attempt.resetAt <= current) {
    attempt.count = 0
    attempt.resetAt = current + windowSeconds
  }
  attempt.count += 1
  loginAttempts.set(key, attempt)
  return attempt.count > maxAttempts
}

function isDocsLikeRequest(req, config) {
  if (req.method === 'OPTIONS') return false
  if (req.path === '/health') return false
  if (req.path === config.loginPath || req.path === config.logoutPath) {
    return true
  }
  if (req.path === '/' || req.path === '/index.html') return true
  if (req.path.includes('.')) return true
  return req.path.startsWith('/docs') || req.path.startsWith('/static')
}

function createHeartideAdminAuthMiddleware() {
  return async function heartideAdminAuth(req, res, next) {
    if (!isAdminAuthEnabled()) {
      next()
      return
    }

    const config = readAdminConfig()
    if (!isDocsLikeRequest(req, config)) {
      next()
      return
    }

    if (req.path === config.logoutPath) {
      clearSessionCookie(res)
      redirect(res, config.loginPath)
      return
    }

    if (req.path === config.loginPath && req.method === 'GET') {
      renderLogin(
        res,
        config,
        isConfigured(config) ? '' : missingConfigMessage(),
      )
      return
    }

    if (req.path === config.loginPath && req.method === 'POST') {
      if (!isConfigured(config)) {
        renderLogin(res, config, missingConfigMessage())
        return
      }
      if (isLoginRateLimited(req)) {
        renderLogin(res, config, '登录尝试过多，请稍后再试。')
        return
      }
      try {
        const form = await parseFormBody(req)
        if (
          form.username === config.username &&
          passwordMatches(form.password, config)
        ) {
          setSessionCookie(
            req,
            res,
            createSessionToken(config.username, config),
            config,
          )
          redirect(res, '/')
          return
        }
      } catch (_) {
        renderLogin(res, config, '登录请求无效。')
        return
      }
      renderLogin(res, config, '账号或密码错误。')
      return
    }

    if (!isConfigured(config)) {
      if (wantsHtml(req)) {
        redirect(res, config.loginPath)
        return
      }
      renderMissingConfig(res)
      return
    }

    const cookies = parseCookies(req.headers.cookie)
    const token = cookies.heartide_admin || ''
    if (token && verifySessionToken(token, config)) {
      next()
      return
    }

    if (wantsHtml(req)) {
      redirect(res, config.loginPath)
      return
    }

    res.statusCode = 401
    res.setHeader('Content-Type', 'application/json; charset=utf-8')
    res.end(
      JSON.stringify({
        code: 401,
        msg: 'Heartide admin login required',
      }),
    )
  }
}

module.exports = {
  createHeartideAdminAuthMiddleware,
  createSessionToken,
  verifySessionToken,
}
