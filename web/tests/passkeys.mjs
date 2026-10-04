import assert from 'node:assert/strict'
import { mkdir } from 'node:fs/promises'
import { pathToFileURL } from 'node:url'
import { SQL } from 'bun'
import { createHmac } from 'node:crypto'

// Run only through the ignored Rust test, which owns a temporary PostgreSQL database and HTTP server.
const origin = process.env.SINAN_PASSKEY_TEST_ORIGIN
const database = process.env.SINAN_PASSKEY_TEST_DATABASE_URL
assert.equal(new URL(origin).hostname, 'localhost')
assert.match(new URL(database).pathname, /^\/_sqlx_test/)
const databaseUrl = new URL(database)
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(databaseUrl.hostname), 'Browser fixtures require a local test database')
// sqlx's driver options are not PostgreSQL startup parameters. The isolated fixture has no TLS.
databaseUrl.search = '?sslmode=disable'
const sql = new SQL({ url: databaseUrl.href, connectionTimeout: 5 })
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const password = 'business-test-password'
const errors = [], results = []
const contexts = []
const clearLimit = () => sql.unsafe('UPDATE auth_rate_limits SET attempts=0,window_start=0')
async function client(width = 1280) {
  const context = await browser.newContext({ viewport: { width, height: 1000 } })
  contexts.push(context)
  const page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  const cdp = await context.newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } })
  return { context, page, cdp, authenticatorId }
}
async function request(page, path, body, method = 'POST') {
  return page.evaluate(async ({ path, body, method }) => {
    const response = await fetch(path, { method, credentials: 'same-origin', headers: body === undefined ? undefined : { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
    const text = await response.text()
    let result = null
    if (text) { try { result = JSON.parse(text) } catch { result = { error: text } } }
    return { status: response.status, body: result }
  }, { path, body, method })
}
async function ok(page, path, body, method) {
  const response = await request(page, path, body, method)
  assert.ok(response.status >= 200 && response.status < 300, `${path}: ${JSON.stringify(response)}`)
  return response.body
}
async function native(page, challenge, create = false, credentialId) {
  return page.evaluate(async ({ challenge, create, credentialId }) => {
    const options = structuredClone(challenge.options.publicKey)
    if (credentialId) options.allowCredentials = [{ id: credentialId, type: 'public-key' }]
    const publicKey = create ? PublicKeyCredential.parseCreationOptionsFromJSON(options) : PublicKeyCredential.parseRequestOptionsFromJSON(options)
    const result = create ? await navigator.credentials.create({ publicKey }) : await navigator.credentials.get({ publicKey })
    return { challenge_id: challenge.challenge_id, credential: result.toJSON() }
  }, { challenge, create, credentialId })
}
const portalPath = invitation => `/api/plugins/sing-box/portal/${invitation.url.match(/account\/([^?]+)/)[1]}`
const activation = invitation => invitation.url.split('?activate=')[1]

try {
  const admin = await client()
  const page = admin.page
  await page.goto(`${origin}/#/system/administrator`)
  await page.getByLabel('管理员密码', { exact: true }).fill(password)
  await page.getByRole('button', { name: '登录面板', exact: true }).click()
  await page.getByRole('heading', { name: '系统管理员', exact: true }).waitFor()
  await page.getByRole('button', { name: '添加 Passkey', exact: true }).click()
  let dialog = page.getByRole('dialog')
  await dialog.getByLabel('密钥名称', { exact: true }).fill('管理员测试密钥')
  await dialog.getByLabel('管理员密码', { exact: true }).fill(password)
  await dialog.getByRole('button', { name: '验证并绑定', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  await page.getByRole('cell', { name: '管理员测试密钥', exact: true }).waitFor()
  const management = await ok(page, '/api/security/passkeys', undefined, 'GET')
  const adminKey = management.keys[0]
  assert.deepEqual(Object.keys(adminKey).sort(), ['created_at', 'id', 'last_used_at', 'name'])
  results.push('administrator registration through shipped UI with required user verification')
  await page.locator('.logout-button').click()
  await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
  await page.getByRole('button', { name: '使用初始所有者 Passkey 登录', exact: true }).click()
  await page.getByRole('heading', { name: '系统管理员', exact: true }).waitFor()
  assert.equal((await request(page, '/api/me', undefined, 'GET')).status, 200)
  results.push('administrator passwordless login and admin cookie')

  await clearLimit()
  const replayChallenge = await ok(page, '/api/login/passkey/start')
  const replayBody = await native(page, replayChallenge)
  const replayResults = await Promise.all([request(page, '/api/login/passkey/finish', replayBody), request(page, '/api/login/passkey/finish', replayBody)])
  assert.deepEqual(replayResults.map(r => r.status).sort(), [200, 400])
  assert.equal((await request(page, '/api/login/passkey/finish', replayBody)).status, 400)
  results.push('concurrent assertion finish succeeds once; replays fail')

  for (const mutation of ['signature', 'origin', 'rp_id', 'user_verification', 'expired', 'browser_binding', 'wrong_purpose']) {
    await clearLimit()
    const challenge = await ok(page, '/api/login/passkey/start')
    const body = await native(page, challenge)
    if (mutation === 'signature') {
      const signature = Buffer.from(body.credential.response.signature, 'base64url'); signature[signature.length - 1] ^= 1
      body.credential.response.signature = signature.toString('base64url')
    } else if (mutation === 'origin') {
      const data = JSON.parse(Buffer.from(body.credential.response.clientDataJSON, 'base64url').toString())
      data.origin = 'https://other.example.com'
      body.credential.response.clientDataJSON = Buffer.from(JSON.stringify(data)).toString('base64url')
    } else if (mutation === 'rp_id' || mutation === 'user_verification') {
      const data = Buffer.from(body.credential.response.authenticatorData, 'base64url')
      if (mutation === 'rp_id') data[0] ^= 1
      else data[32] &= ~4
      body.credential.response.authenticatorData = data.toString('base64url')
    } else if (mutation === 'expired') {
      await sql`UPDATE passkey_ceremonies SET expires_at=0 WHERE id=${challenge.challenge_id}`
    } else if (mutation === 'browser_binding') {
      const cookies = await admin.context.cookies()
      const binding = cookies.find(c => c.name === 'sinan_admin_passkey')
      await admin.context.addCookies([{ ...binding, value: 'TEST_ONLY_WRONG_BINDING' }])
    }
    const path = mutation === 'wrong_purpose' ? '/api/security/passkeys/register/finish' : '/api/login/passkey/finish'
    const reply = await request(page, path, body)
    assert.ok([400, 422].includes(reply.status), `${mutation}: ${JSON.stringify(reply)}`)
    assert.equal(reply.body.id, undefined)
    results.push(`${mutation} rejected`)
  }
  await clearLimit()
  const wrongOrigin = await admin.context.request.post(`${origin}/api/login/passkey/start`, { headers: { Origin: 'https://other.example.com' } })
  assert.equal(wrongOrigin.status(), 400)

  // A registration must finish in the same administrator session that authorized it.
  const pending = await ok(page, '/api/security/passkeys/register/start', { name: '不能迁移会话', password })
  const preservedAdminKeys = await admin.cdp.send('WebAuthn.getCredentials', { authenticatorId: admin.authenticatorId })
  await admin.cdp.send('WebAuthn.clearCredentials', { authenticatorId: admin.authenticatorId })
  const pendingBody = await native(page, pending, true)
  for (const credential of preservedAdminKeys.credentials) await admin.cdp.send('WebAuthn.addCredential', { authenticatorId: admin.authenticatorId, credential })
  await ok(page, '/api/login', { password })
  assert.equal((await request(page, '/api/security/passkeys/register/finish', pendingBody)).status, 400)
  results.push('administrator registration is bound to its authorizing session')

  await clearLimit()
  const user = await ok(page, '/api/plugins/sing-box/users', { name: '受验代理用户' })
  await page.goto(`${origin}/#/plugins/sing-box/users`)
  await page.getByRole('button', { name: '生成开通链接', exact: true }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByLabel('管理员密码', { exact: true }).fill(password)
  await dialog.getByRole('button', { name: '验证并生成', exact: true }).click()
  await dialog.getByRole('heading', { name: '用户开通链接', exact: true }).waitFor()
  const inviteUrl = await dialog.locator('.copy-field code').innerText()
  const invite = { url: inviteUrl }, userPath = portalPath(invite)
  const saved = await sql`SELECT activation_hash FROM singbox_portal_accounts WHERE user_id=${user.id}`
  assert.notEqual(saved[0].activation_hash, activation(invite))
  const userClient = await client(390), userPage = userClient.page
  await userPage.goto(inviteUrl)
  await userPage.getByRole('heading', { name: '开通代理用户入口', exact: true }).waitFor()
  assert.equal(userPage.url().includes('activate='), false, 'Activation secret is removed from address/history')
  await userPage.getByLabel('密钥名称', { exact: true }).fill('用户手机')
  await userPage.getByRole('button', { name: '绑定 Passkey 并开通', exact: true }).click()
  await userPage.getByRole('heading', { name: user.name, exact: true }).waitFor()
  const own = await ok(userPage, userPath, undefined, 'GET')
  assert.equal(own.authenticated, true)
  assert.equal(own.subscription_url, `${user.subscription_url}?format=singbox`)
  assert.deepEqual(own.usage, { uplink: '0', downlink: '0' })
  const userCookies = await userClient.context.cookies()
  assert.ok(userCookies.some(c => c.name === 'sinan_proxy_session' && c.httpOnly && c.sameSite === 'Strict'))
  assert.equal(userCookies.some(c => c.name === 'sinan_session'), false)
  for (const path of ['/api/me', '/api/security/passkeys', '/api/plugins/sing-box/users', '/api/plugins/ddns/rules']) {
    assert.equal((await request(userPage, path, undefined, 'GET')).status, 401)
  }
  assert.equal((await ok(page, userPath, undefined, 'GET')).authenticated, false, 'Administrator session is not a proxy session')
  results.push('proxy activation, private subscription/usage and role separation')

  await clearLimit()
  assert.equal((await request(userPage, `${userPath}/register/start`, { name: '重放邀请', activation_token: activation(invite) })).status, 400)
  assert.equal((await request(userPage, `${userPath}/keys/${own.keys[0].id}/remove`)).status, 409)
  await sql`UPDATE singbox_portal_sessions SET verified_at=0 WHERE account_id=${userPath.split('/').at(-1)}`
  const staleProof = await request(userPage, `${userPath}/register/start`, { name: '需要重新验证' })
  assert.equal(staleProof.status, 409)
  assert.match(staleProof.body.error, /重新验证/)
  await userPage.getByRole('button', { name: '退出登录', exact: true }).click()
  await userPage.getByRole('button', { name: '使用 Passkey 登录', exact: true }).click()
  await userPage.getByRole('heading', { name: user.name, exact: true }).waitFor()
  assert.equal(await userPage.getByRole('navigation', { name: '主导航' }).count(), 0)
  assert.ok(await userPage.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth))
  if (process.env.SINAN_UI_SCREENSHOT_DIR) {
    await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true })
    await userPage.screenshot({ path: `${process.env.SINAN_UI_SCREENSHOT_DIR}/passkey-proxy-390.png`, fullPage: true })
  }
  results.push('proxy passwordless login, one-time invitation and last-key guard')

  // Authentication with one account's key cannot satisfy another account's challenge.
  await clearLimit()
  const peer = await ok(page, '/api/plugins/sing-box/users', { name: '另一个代理用户' })
  const peerInvite = await ok(page, `/api/plugins/sing-box/users/${peer.id}/portal/invitation`, { password })
  const peerPath = portalPath(peerInvite)
  const peerClient = await client(), peerPage = peerClient.page
  await peerPage.goto(peerInvite.url)
  const peerChallenge = await ok(peerPage, `${peerPath}/register/start`, { name: '另一用户密钥', activation_token: activation(peerInvite) })
  await ok(peerPage, `${peerPath}/register/finish`, await native(peerPage, peerChallenge, true))
  assert.equal((await ok(userPage, peerPath, undefined, 'GET')).authenticated, false)
  const wrongAccount = await ok(userPage, `${peerPath}/login/start`)
  const userCreds = await userClient.cdp.send('WebAuthn.getCredentials', { authenticatorId: userClient.authenticatorId })
  const userCredentialId = Buffer.from(userCreds.credentials[0].credentialId, 'base64').toString('base64url')
  const wrongBody = await native(userPage, wrongAccount, false, userCredentialId)
  assert.equal((await request(userPage, `${peerPath}/login/finish`, wrongBody)).status, 400)
  const adminChallenge = await ok(userPage, '/api/login/passkey/start')
  assert.equal((await request(userPage, '/api/login/passkey/finish', await native(userPage, adminChallenge, false, userCredentialId))).status, 400)
  results.push('valid signatures from other proxy accounts/roles cannot log in')

  await clearLimit()
  let previousCredential
  await userPage.route(`**${userPath}/register/start`, async route => {
    const existing = await userClient.cdp.send('WebAuthn.getCredentials', { authenticatorId: userClient.authenticatorId })
    previousCredential = existing.credentials[0]
    await userClient.cdp.send('WebAuthn.clearCredentials', { authenticatorId: userClient.authenticatorId })
    await route.continue()
  })
  await userPage.getByRole('button', { name: '添加 Passkey', exact: true }).click()
  const userDialog = userPage.getByRole('dialog')
  await userDialog.getByLabel('新密钥名称', { exact: true }).fill('用户备用密钥')
  await userDialog.getByRole('button', { name: '验证并添加', exact: true }).click()
  await userDialog.waitFor({ state: 'hidden' })
  await userPage.unroute(`**${userPath}/register/start`)
  await userPage.getByRole('cell', { name: '用户备用密钥', exact: true }).waitFor()
  await userClient.cdp.send('WebAuthn.addCredential', { authenticatorId: userClient.authenticatorId, credential: previousCredential })
  const beforeDelete = await userClient.context.cookies()
  await clearLimit()
  await userPage.getByRole('row').filter({ hasText: '用户手机' }).getByRole('button', { name: '删除', exact: true }).click()
  await userDialog.getByRole('button', { name: '验证并删除', exact: true }).click()
  await userDialog.waitFor({ state: 'hidden' })
  await userPage.getByText('Passkey 已删除，其他用户会话已退出。', { exact: true }).waitFor()
  assert.equal((await ok(userPage, userPath, undefined, 'GET')).keys.length, 1)
  const oldSession = beforeDelete.find(c => c.name === 'sinan_proxy_session').value
  const oldSessionView = await admin.context.request.get(`${origin}${userPath}`, { headers: { Cookie: `sinan_proxy_session=${oldSession}` } })
  assert.equal((await oldSessionView.json()).authenticated, false)
  results.push('proxy add/remove UI, fresh verification and revocation of other sessions')

  await clearLimit()
  const staleChallenge = await ok(userPage, `${userPath}/login/start`)
  const staleBody = await native(userPage, staleChallenge)
  assert.equal((await request(page, `/api/plugins/sing-box/users/${user.id}/portal/invitation`, { password })).status, 409)
  const replacement = await ok(page, `/api/plugins/sing-box/users/${user.id}/portal/invitation`, { password, reset: true })
  assert.equal((await request(userPage, `${userPath}/login/finish`, staleBody)).status, 400)
  assert.equal((await ok(userPage, userPath, undefined, 'GET')).authenticated, false)
  const unchanged = await ok(page, `/api/plugins/sing-box/users/${user.id}`, undefined, 'GET')
  assert.equal(unchanged.subscription_token, user.subscription_token)
  assert.equal(unchanged.id, user.id)
  await sql`UPDATE singbox_portal_accounts SET activation_expires_at=0 WHERE user_id=${user.id}`
  assert.equal((await request(userPage, `${userPath}/register/start`, { name: '过期', activation_token: activation(replacement) })).status, 400)
  results.push('explicit admin recovery revokes keys/sessions/challenges while preserving existing proxy identity')

  await clearLimit()
  const fresh = await ok(page, `/api/plugins/sing-box/users/${user.id}/portal/invitation`, { password })
  const registration = await ok(userPage, `${userPath}/register/start`, { name: '重开通', activation_token: activation(fresh) })
  const registrationBody = await native(userPage, registration, true)
  const rival = await client()
  await rival.page.goto(fresh.url)
  const rivalRegistration = await ok(rival.page, `${userPath}/register/start`, { name: '并发开通', activation_token: activation(fresh) })
  const rivalBody = await native(rival.page, rivalRegistration, true)
  const activated = await Promise.all([request(userPage, `${userPath}/register/finish`, registrationBody), request(rival.page, `${userPath}/register/finish`, rivalBody)])
  assert.deepEqual(activated.map(r => r.status).sort(), [200, 400])
  await ok(page, `/api/plugins/sing-box/users/${user.id}`, undefined, 'DELETE')
  assert.equal((await request(userPage, userPath, undefined, 'GET')).status, 404)
  const count = await sql`SELECT count(*) AS count FROM passkey_credentials WHERE account_id=${userPath.split('/').at(-1)}`
  assert.equal(Number(count[0].count), 0)
  results.push('concurrent initial activation has one winner; deleting owner removes credentials')

  await clearLimit()
  const loginPending = await ok(page, '/api/login/passkey/start')
  const loginBody = await native(page, loginPending)
  const totpSecret = Buffer.alloc(20, 0x54)
  const totpStep = Math.floor(Date.now() / 30000)
  const totp = step => {
    const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(step))
    const digest = createHmac('sha1', totpSecret).update(counter).digest(), offset = digest[19] & 15
    return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0')
  }
  await sql`UPDATE admins SET totp_secret=${totpSecret},totp_last_step=NULL WHERE id=1`
  assert.equal((await request(page, '/api/security/passkeys/register/start', { name: '缺少验证码', password })).status, 400)
  assert.equal((await request(page, `/api/security/passkeys/${adminKey.id}/remove`, { password })).status, 400)
  assert.equal((await request(page, `/api/plugins/sing-box/users/${peer.id}/portal/invitation`, { password, reset: true })).status, 400)
  await ok(page, '/api/security/passkeys/register/start', { name: '需要新验证码', password, totp_code: totp(totpStep) })
  assert.equal((await request(page, `/api/security/passkeys/${adminKey.id}/remove`, { password, totp_code: totp(totpStep) })).status, 400)
  await ok(page, `/api/security/passkeys/${adminKey.id}/remove`, { password, totp_code: totp(totpStep + 1) })
  results.push('admin registration, removal and proxy recovery enforce enabled TOTP and reject code replay')
  assert.equal((await request(page, '/api/login/passkey/finish', loginBody)).status, 400)
  await sql`UPDATE admins SET totp_secret=NULL,totp_last_step=NULL WHERE id=1`
  await clearLimit()
  await ok(page, '/api/logout')
  await ok(page, '/api/login', { password })
  results.push('administrator key deletion cancels pending login; original password fallback works')
  assert.deepEqual(errors, [])
  console.log(JSON.stringify({ passed: results.length, results }))
} finally {
  await Promise.all(contexts.map(context => context.close()))
  await browser.close()
  await sql.close()
}
