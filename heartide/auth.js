const crypto = require('crypto')

const DEFAULT_PUBLIC_PATHS = '/health'
const HEARTIDE_AUTH_KEYS = [
  'heartide_app_id',
  'heartide_ts',
  'heartide_nonce',
  'heartide_sign',
]

const nonceCache = new Map()
let purgeCounter = 0

function isAuthEnabled() {
  return process.env.HEARTIDE_AUTH_ENABLED !== 'false'
}

function readNumber(name, fallback) {
  const raw = process.env[name]
  if (!raw) return fallback
  const value = Number(raw)
  return Number.isFinite(value) && value > 0 ? value : fallback
}

function readPublicPaths() {
  return (process.env.HEARTIDE_AUTH_PUBLIC_PATHS || DEFAULT_PUBLIC_PATHS)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

function readSecrets() {
  const result = new Map()
  const multi = process.env.HEARTIDE_APP_SECRETS || ''
  multi
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .forEach((item) => {
      const splitAt = item.indexOf(':')
      if (splitAt > 0 && splitAt < item.length - 1) {
        result.set(item.slice(0, splitAt), item.slice(splitAt + 1))
      }
    })

  const appId = process.env.HEARTIDE_APP_ID || 'heartide'
  const secret = process.env.HEARTIDE_APP_SECRET || ''
  if (secret) {
    result.set(appId, secret)
  }
  return result
}

function encodeCanonical(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (ch) =>
    `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  )
}

function canonicalizeSearchParams(searchParams) {
  const pairs = []
  for (const [key, value] of searchParams.entries()) {
    if (key === 'heartide_sign') continue
    pairs.push([key, value])
  }
  pairs.sort((left, right) => {
    if (left[0] === right[0]) return left[1].localeCompare(right[1])
    return left[0].localeCompare(right[0])
  })
  return pairs
    .map(([key, value]) => `${encodeCanonical(key)}=${encodeCanonical(value)}`)
    .join('&')
}

function canonicalizeRequest(method, path, searchParams) {
  return [
    method.toUpperCase(),
    path,
    canonicalizeSearchParams(searchParams),
  ].join('\n')
}

function signCanonicalRequest(canonicalRequest, secret) {
  return crypto
    .createHmac('sha256', secret)
    .update(canonicalRequest)
    .digest('hex')
}

function signUrl(inputUrl, options) {
  const opts = options || {}
  const method = opts.method || 'GET'
  const appId = opts.appId || process.env.HEARTIDE_APP_ID || 'heartide'
  const secret = opts.secret || process.env.HEARTIDE_APP_SECRET || ''
  if (!secret) {
    throw new Error('HEARTIDE_APP_SECRET is required to sign a request')
  }

  const url = new URL(inputUrl, opts.baseUrl || 'http://localhost:3000')
  const nowSeconds = Math.floor(Date.now() / 1000)
  url.searchParams.set('heartide_app_id', appId)
  url.searchParams.set('heartide_ts', String(opts.timestamp || nowSeconds))
  url.searchParams.set('heartide_nonce', opts.nonce || crypto.randomUUID())
  url.searchParams.delete('heartide_sign')

  const canonical = canonicalizeRequest(method, url.pathname, url.searchParams)
  url.searchParams.set('heartide_sign', signCanonicalRequest(canonical, secret))
  return url
}

function isPublicPath(pathname, publicPaths) {
  return publicPaths.some((item) => {
    if (item.endsWith('*')) {
      return pathname.startsWith(item.slice(0, -1))
    }
    return pathname === item
  })
}

function getSingleParam(searchParams, key) {
  const values = searchParams.getAll(key)
  if (values.length !== 1 || !values[0]) {
    return ''
  }
  return values[0]
}

function timingSafeEqualHex(left, right) {
  if (!/^[a-f0-9]+$/i.test(left) || !/^[a-f0-9]+$/i.test(right)) {
    return false
  }
  const leftBuffer = Buffer.from(left, 'hex')
  const rightBuffer = Buffer.from(right, 'hex')
  if (leftBuffer.length !== rightBuffer.length) {
    return false
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer)
}

function purgeExpiredNonces(nowSeconds) {
  purgeCounter += 1
  if (purgeCounter % 100 !== 0) return
  for (const [key, expiresAt] of nonceCache.entries()) {
    if (expiresAt <= nowSeconds) {
      nonceCache.delete(key)
    }
  }
}

function reject(res, reason) {
  res.status(401).send({
    code: 401,
    msg: 'Heartide service authentication failed',
    reason,
  })
}

function createHeartideAuthMiddleware() {
  const publicPaths = readPublicPaths()
  const maxSkewSeconds = readNumber('HEARTIDE_AUTH_MAX_SKEW_SECONDS', 300)
  const nonceTtlSeconds = readNumber('HEARTIDE_AUTH_NONCE_TTL_SECONDS', 300)

  return function heartideAuth(req, res, next) {
    if (!isAuthEnabled()) {
      req.heartideAuth = { disabled: true }
      next()
      return
    }

    if (req.method === 'OPTIONS' || isPublicPath(req.path, publicPaths)) {
      next()
      return
    }

    const secrets = readSecrets()
    if (secrets.size === 0) {
      reject(res, 'server_secret_not_configured')
      return
    }

    const url = new URL(req.originalUrl, 'http://heartide.local')
    const searchParams = url.searchParams
    const appId = getSingleParam(searchParams, 'heartide_app_id')
    const timestampRaw = getSingleParam(searchParams, 'heartide_ts')
    const nonce = getSingleParam(searchParams, 'heartide_nonce')
    const providedSign = getSingleParam(searchParams, 'heartide_sign')

    if (!appId || !timestampRaw || !nonce || !providedSign) {
      reject(res, 'missing_auth_params')
      return
    }

    const unknownHeartideKeys = []
    for (const key of searchParams.keys()) {
      if (key.startsWith('heartide_') && !HEARTIDE_AUTH_KEYS.includes(key)) {
        unknownHeartideKeys.push(key)
      }
    }
    if (unknownHeartideKeys.length > 0) {
      reject(res, 'unknown_auth_params')
      return
    }

    const secret = secrets.get(appId)
    if (!secret) {
      reject(res, 'unknown_app_id')
      return
    }

    const timestamp = Number(timestampRaw)
    const nowSeconds = Math.floor(Date.now() / 1000)
    if (!Number.isInteger(timestamp)) {
      reject(res, 'invalid_timestamp')
      return
    }
    if (Math.abs(nowSeconds - timestamp) > maxSkewSeconds) {
      reject(res, 'expired_timestamp')
      return
    }

    purgeExpiredNonces(nowSeconds)
    const nonceKey = `${appId}:${nonce}`
    const nonceExpiresAt = nonceCache.get(nonceKey)
    if (nonceExpiresAt && nonceExpiresAt > nowSeconds) {
      reject(res, 'replayed_nonce')
      return
    }

    const canonical = canonicalizeRequest(req.method, url.pathname, searchParams)
    const expectedSign = signCanonicalRequest(canonical, secret)
    if (!timingSafeEqualHex(expectedSign, providedSign)) {
      reject(res, 'bad_signature')
      return
    }

    nonceCache.set(nonceKey, nowSeconds + nonceTtlSeconds)
    req.heartideAuth = { appId }
    next()
  }
}

function redactRequestUrl(input) {
  try {
    const url = new URL(input, 'http://heartide.local')
    const sensitiveKeys = [
      'cookie',
      'heartide_sign',
      'heartide_nonce',
      'captcha',
      'password',
    ]
    sensitiveKeys.forEach((key) => {
      if (url.searchParams.has(key)) {
        url.searchParams.set(key, '***')
      }
    })
    return `${url.pathname}${url.search}`
  } catch (_) {
    return String(input)
      .replace(/cookie=[^&\s]+/g, 'cookie=***')
      .replace(/heartide_sign=[^&\s]+/g, 'heartide_sign=***')
      .replace(/heartide_nonce=[^&\s]+/g, 'heartide_nonce=***')
      .replace(/captcha=[^&\s]+/g, 'captcha=***')
      .replace(/password=[^&\s]+/g, 'password=***')
  }
}

module.exports = {
  canonicalizeRequest,
  canonicalizeSearchParams,
  createHeartideAuthMiddleware,
  redactRequestUrl,
  signCanonicalRequest,
  signUrl,
}
