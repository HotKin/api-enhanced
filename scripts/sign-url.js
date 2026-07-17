#!/usr/bin/env node
const { signUrl } = require('../heartide/auth')

const input = process.argv[2]
if (!input) {
  console.error('Usage: node scripts/sign-url.js "/banner?type=2"')
  process.exit(1)
}

try {
  const url = signUrl(input, {
    method: process.env.HEARTIDE_SIGN_METHOD || 'GET',
    appId: process.env.HEARTIDE_APP_ID || 'heartide',
    secret: process.env.HEARTIDE_APP_SECRET,
    baseUrl: process.env.HEARTIDE_SIGN_BASE_URL || 'http://localhost:3000',
  })
  console.log(url.toString())
} catch (err) {
  console.error(err.message)
  process.exit(1)
}
