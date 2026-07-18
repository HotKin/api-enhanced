# Upstream Source

This project is a Heartide-specific backend fork based on `HotKin/api-enhanced`.

## Snapshot

- Repository: `https://github.com/HotKin/api-enhanced`
- Commit: `35d1c61cb4dccd1c55c25bf791a915cd29f7fedf`
- Upstream package: `@neteasecloudmusicapienhanced/api`
- Upstream version: `4.37.0`

## Local Changes

- Added `heartide/auth.js` for service-level HMAC request verification.
- Added `heartide/adminAuth.js` for environment-configured account login around public docs/static pages.
- Added `/health` for deployment checks.
- Added `scripts/sign-url.js` for local curl/smoke testing.
- Redacted sensitive query parameters in request logs.
- Added Heartide npm scripts and README notes.
