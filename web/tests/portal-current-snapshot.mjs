import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { extname, resolve, sep } from 'node:path'

// TEST_ONLY: shipping UI and private loopback API snapshots, without a real authenticator.
// Real WebAuthn, PostgreSQL, password/TOTP and cookie isolation are covered separately.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url)), prefix = '/api/plugins/sing-box'
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname, file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []
const wait = async (condition, label) => { const deadline = Date.now() + 12000; while (!await condition()) { assert(Date.now() < deadline, label); await new Promise(resolve => setTimeout(resolve, 20)) } }
try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(12000)
    const writes = [], errors = [], unexpected = [], external = [], pending = [], failures = new Set()
    const users = [1, 2].map(id => ({ id, name: `TEST_ONLY 用户 ${id}`, subscription_token: `TEST_ONLY_${id}`, subscription_url: `${origin}/s/TEST_ONLY_${id}` }))
    const original = { configuration: { enabled: true, reason: null, origin }, keys: 0, url: null, activation_expires_at: null }
    const portalPath = `${prefix}/users/1/portal`
    let access = structuredClone(original), held = null, notFound = false, blocked = 0
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/*', route => {
      const task = (async () => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
        if (url.origin !== origin) { external.push(url.href); return route.abort() }
        if (!path.startsWith('/api/')) return route.continue()
        if (method === 'GET' && held?.path === path) { ++held.reached; await held.promise }
        if (method === 'GET' && failures.has(path)) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 当前读取失败' } })
        let value
        if (path === '/api/dashboard/access' || path === '/api/me') value = { authenticated: true, public_dashboard: false }
        else if (method === 'GET' && path === `${prefix}/users`) value = users
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/portal$/.test(path)) {
          const id = Number(path.split('/')[5])
          if (!users.some(user => user.id === id) || id === 1 && notFound) return route.fulfill({ status: 404, json: { error: 'TEST_ONLY 当前用户入口不存在' } })
          value = id === 1 ? access : original
        } else if (method === 'POST' && /^\/api\/plugins\/sing-box\/users\/\d+\/portal\/invitation$/.test(path)) {
          writes.push({ path, body: request.postDataJSON() })
          assert.equal(path, `${portalPath}/invitation`, 'an old draft must never redirect credentials to another user')
          assert.deepEqual(Object.keys(writes.at(-1).body).sort(), ['password', 'reset', 'totp_code'])
          value = { url: `${origin}/#/plugins/sing-box/account/00000000-0000-4000-8000-000000000001?activate=${'A'.repeat(43)}`, expires_at: Math.floor(Date.now() / 1000) + 900 }
        } else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/[1-9]\d*\/external-accesses$/.test(path)) value = { revision: 0, accesses: [], available_nodes: [] }
        else if (method === 'GET' && [ `${prefix}/nodes`, `${prefix}/proxy-resources`, `${prefix}/policy-groups`, `${prefix}/package-groups` ].includes(path)) value = []
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/(accesses|policy-groups)$/.test(path)) value = path.endsWith('/accesses') ? [] : { group_ids: [] }
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/entitlement$/.test(path)) value = { user_id: Number(path.split('/')[5]), package_group_id: null, package_name: null, monthly_bytes: null, starts_at: null, expires_at: null, used_bytes: '0', status: 'unmetered', allowed: true }
        else if (method === 'GET' && path === `${prefix}/usage`) value = { total: '0', uplink: '0', downlink: '0', by_node: [], by_user: [] }
        else { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { error: 'TEST_ONLY 未知请求' } }) }
        return route.fulfill({ json: value })
      })()
      pending.push(task); return task
    })
    const portalPanel = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: '用户 Passkey 入口', exact: true }) })
    const pageRefresh = page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true })
    const portalRefresh = portalPanel.getByRole('button', { name: '刷新', exact: true })
    const reread = async (path = portalPath) => {
      const response = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'GET')
      await (path === portalPath ? portalRefresh : pageRefresh).evaluate(button => button.click()); await response
    }
    const dialog = page.getByRole('dialog')
    const capture = async () => {
      await wait(() => dialog.locator('footer .button-primary').isEnabled(), 'capture an actually enabled invitation callback')
      await dialog.locator('form').evaluate(form => {
        const key = Object.keys(form).find(key => key.startsWith('__reactProps$')), handler = key && form[key]?.onSubmit
        if (typeof handler !== 'function') throw new Error('actual invitation form callback missing')
        window.TEST_ONLY_submit = () => handler({ preventDefault() {}, currentTarget: form })
      })
    }
    const retained = async () => {
      assert.equal(await dialog.getByLabel('管理员密码', { exact: true }).inputValue(), 'TEST_ONLY_DRAFT_PASSWORD')
      assert.equal(await dialog.getByLabel('二步验证码', { exact: false }).inputValue(), '123456')
    }
    const refuse = async () => {
      const baseline = writes.length
      await page.evaluate(() => window.TEST_ONLY_submit())
      await page.waitForTimeout(50)
      assert.equal(writes.length, baseline, 'the originally enabled callback must send zero invitations')
      await retained(); ++blocked
    }
    try {
      await page.goto(`${origin}/#/plugins/sing-box/users`)
      const open = portalPanel.getByRole('button', { name: '生成开通链接', exact: true })
      await wait(() => open.isEnabled(), 'initial current user and portal must be ready')
      await open.evaluate(button => {
        const key = Object.keys(button).find(key => key.startsWith('__reactProps$')), handler = key && button[key]?.onClick
        if (typeof handler !== 'function') throw new Error('actual portal editor opening callback missing')
        window.TEST_ONLY_choose = handler
      })
      for (const path of [ `${prefix}/users`, portalPath ]) {
        let release
        held = { path, reached: 0, promise: new Promise(resolve => { release = resolve }) }; held.release = release
        await (path === portalPath ? portalRefresh : pageRefresh).evaluate(button => { button.click(); window.TEST_ONLY_choose() })
        await wait(() => held.reached > 0, 'editor opening must await the current prerequisite read')
        await page.evaluate(() => window.TEST_ONLY_choose())
        assert.equal(await dialog.count(), 0, 'pending reads cannot open a credential editor through an old enabled callback')
        failures.add(path); const response = page.waitForResponse(response => new URL(response.url()).pathname === path && response.status() === 503)
        release(); held = null; await response
        await page.evaluate(() => window.TEST_ONLY_choose())
        assert.equal(await dialog.count(), 0, 'failed reads cannot open a credential editor through an old callback')
        assert.equal(writes.length, 0)
        failures.delete(path); await reread(path); await wait(() => open.isEnabled(), 'fresh prerequisites restore editor eligibility')
      }
      for (const unavailable of [ { ...original, configuration: { ...original.configuration, enabled: false, reason: 'TEST_ONLY RP 已停用' } }, {} ]) {
        access = unavailable; await reread(); await page.evaluate(() => window.TEST_ONLY_choose())
        assert.equal(await dialog.count(), 0, 'disabled or malformed portal readiness cannot open a credential editor')
        assert.equal(writes.length, 0)
        access = structuredClone(original); await reread(); await wait(() => open.isEnabled(), 'explicit valid readiness is required to reopen')
      }
      await open.click()
      await dialog.getByLabel('管理员密码', { exact: true }).fill('TEST_ONLY_DRAFT_PASSWORD')
      await dialog.getByLabel('二步验证码', { exact: false }).fill('123456')
      await capture()
      for (const path of [ `${prefix}/users`, portalPath ]) {
        let release
        held = { path, reached: 0, promise: new Promise(resolve => { release = resolve }) }
        held.release = release
        const baseline = writes.length
        await (path === portalPath ? portalRefresh : pageRefresh).evaluate(button => { button.click(); window.TEST_ONLY_submit() })
        await wait(() => held.reached > 0, 'prerequisite GET must actually be held')
        assert.equal(writes.length, baseline, 'same-event invalidation rejects the old enabled form callback')
        await refuse()
        failures.add(path); const response = page.waitForResponse(response => new URL(response.url()).pathname === path && response.status() === 503)
        release(); held = null; await response
        await refuse()
        failures.delete(path); await reread(path)
        await wait(() => dialog.getByRole('button', { name: '验证并生成', exact: true }).isEnabled(), 'successful prerequisite recovery retains the original draft')
      }
      for (const changed of [ { ...original, configuration: { ...original.configuration, enabled: false, reason: 'TEST_ONLY RP 已停用' } }, { ...original, keys: 1 }, { ...original, configuration: { ...original.configuration, origin: 'https://changed.example.com' } }, {} ]) {
        access = changed; await reread(); await refuse()
        assert.equal(await dialog.getByRole('button', { name: '验证并生成', exact: true }).isDisabled(), true)
        access = structuredClone(original); await reread()
        await wait(() => dialog.getByRole('button', { name: '验证并生成', exact: true }).isEnabled(), 'only the original portal identity can recover')
      }
      notFound = true; await reread(); await refuse(); notFound = false; await reread()
      users.shift(); await reread(`${prefix}/users`); await refuse()
      assert.equal(await page.getByRole('button', { name: '清除已删除的用户选择', exact: true }).isVisible(), true)
      users.unshift({ id: 1, name: 'TEST_ONLY 用户 1', subscription_token: 'TEST_ONLY_1', subscription_url: `${origin}/s/TEST_ONLY_1` })
      await reread(`${prefix}/users`)
      await wait(() => dialog.getByRole('button', { name: '验证并生成', exact: true }).isEnabled(), 'restoring user 1 and its exact portal enables the preserved draft')
      await dialog.getByRole('button', { name: '验证并生成', exact: true }).click()
      await dialog.getByRole('heading', { name: '用户开通链接', exact: true }).waitFor()
      assert.equal(writes.length, 1); assert.equal(writes[0].body.reset, false)
      await dialog.getByRole('button', { name: '关闭对话框', exact: true }).click()
      access = { ...original, keys: 1, url: `${origin}/#/plugins/sing-box/account/00000000-0000-4000-8000-000000000001` }; await reread()
      const reset = portalPanel.getByRole('button', { name: '重置用户 Passkey', exact: true })
      await wait(() => reset.isEnabled(), 'current one-key portal can explicitly open a reset')
      await reset.click(); await dialog.getByLabel('管理员密码', { exact: true }).fill('TEST_ONLY_DRAFT_PASSWORD'); await dialog.getByLabel('二步验证码', { exact: false }).fill('123456'); await capture()
      access = { ...access, keys: 2 }; await reread(); await refuse()
      access = { ...access, keys: 1 }; await reread()
      await page.locator('.user-row').filter({ hasText: 'TEST_ONLY 用户 2' }).evaluate(button => { button.click(); window.TEST_ONLY_submit() })
      await page.waitForTimeout(50); assert.equal(writes.length, 1, 'a synchronous user switch cannot redirect the retained old reset callback')
      await wait(() => portalPanel.getByRole('button', { name: '生成开通链接', exact: true }).isEnabled(), 'user 2 has an independent portal snapshot')
      await portalPanel.getByRole('button', { name: '生成开通链接', exact: true }).click()
      assert.equal(await dialog.getByLabel('管理员密码', { exact: true }).inputValue(), '', 'new user editors never inherit another user password')
      await dialog.getByRole('button', { name: '取消', exact: true }).click()
      await page.locator('.user-row').filter({ hasText: 'TEST_ONLY 用户 1' }).click()
      await wait(() => reset.isEnabled(), 'explicit selection restores user 1 only')
      await reset.click(); await dialog.getByLabel('管理员密码', { exact: true }).fill('TEST_ONLY_RESET_PASSWORD')
      await dialog.getByRole('button', { name: '确认重置并生成', exact: true }).click()
      await dialog.getByRole('heading', { name: '用户开通链接', exact: true }).waitFor()
      assert.equal(writes.length, 2); assert.equal(writes[1].body.reset, true)
      assert.deepEqual(writes.map(write => write.path), [ `${portalPath}/invitation`, `${portalPath}/invitation` ])
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.deepEqual(external, [])
      results.push({ width, blocked_original_callbacks: blocked, writes: writes.length, prerequisites: ['users', 'portal'], identity: ['missing target', 'different target', 'RP disabled', 'RP origin', 'malformed', '404', 'keys/reset changed'], authenticator_execution: false })
    } finally { held?.release?.(); await page.close(); await Promise.allSettled(pending) }
  }
  console.log(JSON.stringify({ passed: results }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
