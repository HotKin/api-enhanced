# Heartide API

这是潮音 Heartide 的独立后端项目，基于 `HotKin/api-enhanced` 源码快照二次开发。

## 当前基础

- 上游仓库：`https://github.com/HotKin/api-enhanced`
- 上游 commit：`35d1c61cb4dccd1c55c25bf791a915cd29f7fedf`
- 上游版本：`@neteasecloudmusicapienhanced/api@4.37.0`
- 本地说明：见 `UPSTREAM.md`

## Heartide 改动

- 增加服务级 HMAC 请求签名校验。
- 所有 NCM 业务接口默认必须携带 `heartide_app_id`、`heartide_ts`、`heartide_nonce`、`heartide_sign`。
- `/captcha/*`、`/login/*` 登录前接口也必须验签。
- `/health` 和 `OPTIONS` 预检放行。
- 服务日志会脱敏 `cookie`、`heartide_sign`、`heartide_nonce`、`captcha`、`password`。

## 环境变量

```bash
HEARTIDE_AUTH_ENABLED=true
HEARTIDE_APP_ID=heartide
HEARTIDE_APP_SECRET=replace-with-a-long-random-secret
HEARTIDE_AUTH_MAX_SKEW_SECONDS=300
HEARTIDE_AUTH_NONCE_TTL_SECONDS=300
HEARTIDE_AUTH_PUBLIC_PATHS=/health
```

`HEARTIDE_APP_SECRET` 必须在部署环境里设置为长随机值。不要把真实值提交进仓库。

## 启动

```bash
npm install
npm start
```

局域网 / 云端监听：

```bash
HEARTIDE_APP_SECRET=replace-with-a-long-random-secret npm run start:lan
```

## 本地验证

未签名请求应被拒绝：

```bash
curl -i "http://localhost:3000/banner"
```

生成签名 URL：

```bash
HEARTIDE_APP_SECRET=replace-with-a-long-random-secret npm run sign -- "/banner"
```

访问签名 URL：

```bash
curl "$(HEARTIDE_APP_SECRET=replace-with-a-long-random-secret npm run -s sign -- "/banner")"
```

健康检查不需要签名：

```bash
curl "http://localhost:3000/health"
```

## 测试

```bash
npm run test:heartide
```

## App 侧适配约定

App 请求最终 URL 需要追加：

- `heartide_app_id`
- `heartide_ts`
- `heartide_nonce`
- `heartide_sign`

签名串：

```text
METHOD
PATH
CANONICAL_QUERY_WITHOUT_HEARTIDE_SIGN
```

签名算法：`HMAC-SHA256(secret, canonicalRequest)`，输出小写 hex。

Canonical query 会按 key、value 升序排序，并排除 `heartide_sign`。`cookie`、`timestamp` 等原 NCM 参数会参与签名。
