import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// TEST_ONLY read-only contract for the newly mounted UserDiagnostics resource.
// Device state and sensitive template content remain explicitly unavailable.
const diagnosisFixture = user => ({ user_id: user.id, account: { user_id: user.id, name: user.name, portal_created: false, keys: 0, active_sessions: 0, activation_expires_at: null },
  subscription: { status: 'empty', message: 'TEST_ONLY 真实设备状态未验证。', granted_nodes: 0, ready_managed_nodes: 0, ready_external_nodes: 0 },
  permissions: [], external_authorizations: [], ledger: [], quota_credits: [], package_history: [], rotations: [], events: [],
  limitations: { credentials_read: { available: false, reason: 'TEST_ONLY 敏感内容未读取；此处仅为独立只读诊断快照。' } } })
const templateFixture = { template: null, definition_redacted: false, credential_access_reason: 'TEST_ONLY 完整模板未读取。', supported_client: 'singbox', supported_version: '1.14.2', schema_validation: true, runtime_validation: false, limitations: 'TEST_ONLY 没有保存的模板，未执行真实客户端验证。' }

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const results = []

try {
  for (const width of [1440, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 }, acceptDownloads: true })
    await context.addInitScript(() => { window.fixtureClipboard = ''; Object.defineProperty(navigator, 'clipboard', { value: { writeText: async value => { window.fixtureClipboard = value } } }) })
    const page = await context.newPage(), errors = [], unexpected = [], external = []
    page.on('pageerror', error => errors.push(error.message))
    page.on('request', request => { if (request.url().startsWith('https://panel.example.com')) external.push(request.url()) })
    let mode = 'ready', modern = true, subscriptionRequests = 0, resets = 0, lastContent = '', lastAddress = ''
    const user = { id: 1, name: '订阅测试用户', subscription_token: 'stale-fixture-token', subscription_url: 'https://panel.example.com/sub/stale-fixture-token' }
    const entitlement = { user_id: 1, package_group_id: null, package_name: null, status: 'unmetered', allowed: true, monthly_bytes: null, used_bytes: '4096', expires_at: null }
    const nodes = [{ id: 2, name: '现代协议节点 · 仅本用户可用', protocol: 'hysteria2', server_id: 1, public_host: 'proxy.example.com', port: 443, sni: 'proxy.example.com' }]
    const servers = [{ id: 1, name: '订阅示例服务器', enabled: true, online: false, read_only: false }]
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname
      const respond = json => route.fulfill({ json })
      if (path === '/api/dashboard/access') return respond({ authenticated: mode !== 'unauthorized', public_dashboard: false })
      if (request.method() === 'GET' && !url.search && path === '/api/plugins/sing-box/users/1/diagnosis') return respond(diagnosisFixture(user))
      if (request.method() === 'GET' && !url.search && path === '/api/plugins/sing-box/users/1/client-template') return respond(templateFixture)
      if (path === '/api/plugins/sing-box/users/1/portal') return respond({ configuration: { enabled: false, reason: 'TEST_ONLY 未启用', origin }, keys: 0, url: null, activation_expires_at: null })
      if (path === '/api/plugins/sing-box/users/1/external-accesses' && request.method() === 'GET') return respond({ revision: 0, accesses: [], available_nodes: [] })
      if (path === '/api/plugins/sing-box/users') return respond([user])
      if (path === '/api/plugins/sing-box/nodes') return respond(nodes)
      if (path === '/api/plugins/sing-box/proxy-resources') return respond(nodes.map(node => ({...node,kind:'direct',entry_node_id:null})))
      if (path === '/api/plugins/sing-box/chains' || path.endsWith('/accesses') || path.endsWith('/policy-groups') && !path.includes('/users/') || path.endsWith('/package-groups')) return respond([])
      if (path === '/api/plugins/sing-box/usage') return respond({ uplink: '0', downlink: '0', total: '0', by_user: [], by_node: [] })
      if (path === '/api/plugins/sing-box/users/1/policy-groups') return respond({ group_ids: [] })
      if (path === '/api/plugins/sing-box/users/1/entitlement') return respond(entitlement)
      if (path === '/api/plugins/sing-box/users/1/subscription/reset') {
        assert.equal(request.method(), 'POST'); resets++
        user.subscription_token = `reset-fixture-${resets}`; user.subscription_url = `https://panel.example.com/sub/reset-fixture-${resets}`
        return respond(user)
      }
      if (path === '/api/plugins/sing-box/users/1/subscription') {
        assert.equal(request.method(), 'GET'); subscriptionRequests++
        if (mode === 'unauthorized') return route.fulfill({ status: 401, json: { error: '登录已过期' } })
        if (mode === 'failure') return route.fulfill({ status: 500, json: { error: '测试：当前订阅读取失败' } })
        const format = url.searchParams.get('format'), status = mode === 'ready' && format === 'links' && modern ? 'format_unavailable' : mode
        lastContent = status === 'ready' ? (format === 'links' ? `vless://fixture-${subscriptionRequests}@proxy.example.com:443#测试节点` : JSON.stringify({ outbounds: [{ tag: '当前用户节点', password: `fixture-secret-${subscriptionRequests}` }] }, null, 2)) : null
        lastAddress = `https://panel.example.com/sub/fresh-fixture-${subscriptionRequests}?format=${format}`
        return respond({ format, status, message: ({ ready: '可获取已应用节点的完整配置。', empty: '设备尚未完成配置应用，请稍后刷新。', blocked: '本期流量已用完。', format_unavailable: '现代协议需要完整配置，请选择 sing-box 格式。' })[status], subscription_url: lastAddress,
          available_formats: status === 'ready' || status === 'format_unavailable' ? (modern ? ['singbox'] : ['singbox', 'links']) : [], granted_nodes: 2, eligible_nodes: status === 'blocked' ? 0 : 2,
          ready_nodes: status === 'ready' || status === 'format_unavailable' ? nodes.map(node => ({ ...node, protocol: modern ? 'hysteria2' : 'vless-reality' })) : [], content: lastContent, filename: '../../untrusted.html', content_type: 'text/html',
          entitlement: status === 'blocked' ? { ...entitlement, allowed: false, status: 'exhausted', monthly_bytes: '4096' } : entitlement })
      }
      unexpected.push(path); return route.fulfill({ status: 500, json: { error: 'Unexpected API' } })
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/sing-box/users`)
    await page.getByRole('button', { name: '订阅链接', exact: true }).click()
    let dialog = page.getByRole('dialog')
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    assert.equal(await dialog.getByLabel('配置预览').count(), 0)
    assert.equal((await dialog.innerText()).includes('fixture-secret'), false)
    assert.match(await dialog.innerText(), /现代协议节点/)
    let previous = subscriptionRequests
    await dialog.getByRole('button', { name: '复制订阅地址', exact: true }).click()
    await dialog.getByRole('status').filter({ hasText: '订阅地址已复制' }).waitFor()
    assert.equal(subscriptionRequests, previous + 1)
    assert.equal(await page.evaluate(() => window.fixtureClipboard), lastAddress)
    assert.equal(lastAddress.includes('stale-fixture-token'), false)
    previous = subscriptionRequests
    await dialog.getByRole('button', { name: '预览配置', exact: true }).click()
    await dialog.getByLabel('配置预览').waitFor()
    assert.equal(subscriptionRequests, previous + 1)
    assert.equal(await dialog.getByLabel('配置预览').inputValue(), lastContent)
    previous = subscriptionRequests
    await dialog.getByRole('button', { name: '复制配置', exact: true }).click()
    await dialog.getByRole('status').filter({ hasText: '配置内容已复制' }).waitFor()
    assert.equal(subscriptionRequests, previous + 1)
    assert.equal(await page.evaluate(() => window.fixtureClipboard), lastContent)
    const downloadPromise = page.waitForEvent('download')
    previous = subscriptionRequests
    await dialog.getByRole('button', { name: '下载文件', exact: true }).click()
    const download = await downloadPromise
    assert.equal(download.suggestedFilename(), 'sinan-subscription.json')
    assert.equal(await readFile(await download.path(), 'utf8'), lastContent)
    assert.equal(subscriptionRequests, previous + 1)
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false)
    if (screenshots) { await dialog.evaluate(element => { element.scrollTop = 0 }); await page.screenshot({ path: resolve(screenshots, `subscription-${width}.png`), animations: 'disabled' }) }
    await dialog.getByLabel('订阅格式').selectOption('links')
    await dialog.getByText('格式不可用', { exact: true }).waitFor()
    assert.equal(await dialog.getByLabel('配置预览').count(), 0)
    for (const label of ['预览配置', '复制配置', '下载文件', '复制订阅地址']) assert.equal(await dialog.getByRole('button', { name: label, exact: true }).isDisabled(), true)
    modern = false
    await dialog.getByRole('button', { name: '刷新状态', exact: true }).click()
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    const linksDownloadPromise = page.waitForEvent('download')
    await dialog.getByRole('button', { name: '下载文件', exact: true }).click()
    const linksDownload = await linksDownloadPromise
    assert.equal(linksDownload.suggestedFilename(), 'sinan-subscription.txt')
    assert.equal(await readFile(await linksDownload.path(), 'utf8'), lastContent)
    assert.match(lastContent, /^vless:\/\//)
    await dialog.getByLabel('订阅格式').selectOption('singbox')
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    for (const status of ['blocked', 'empty']) {
      mode = status
      await dialog.getByRole('button', { name: '刷新状态', exact: true }).click()
      await dialog.getByText(status === 'blocked' ? '套餐受限' : '等待可用节点', { exact: true }).waitFor()
      assert.equal(await dialog.getByRole('button', { name: '下载文件', exact: true }).isDisabled(), true)
      assert.equal(await dialog.getByRole('button', { name: '复制配置', exact: true }).isDisabled(), true)
      assert.equal(await dialog.getByLabel('配置预览').count(), 0)
    }
    mode = 'ready'
    await dialog.getByRole('button', { name: '刷新状态', exact: true }).click()
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    const copied = await page.evaluate(() => window.fixtureClipboard)
    mode = 'failure'
    await dialog.getByRole('button', { name: '复制配置', exact: true }).click()
    await dialog.getByRole('alert').filter({ hasText: '当前订阅读取失败' }).waitFor()
    assert.equal(await page.evaluate(() => window.fixtureClipboard), copied)
    assert.equal(await dialog.getByLabel('配置预览').count(), 0)
    for (const label of ['复制配置', '下载文件', '复制订阅地址']) assert.equal(await dialog.getByRole('button', { name: label, exact: true }).isDisabled(), true)
    mode = 'ready'
    await dialog.getByRole('button', { name: '重试', exact: true }).click()
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    await dialog.getByRole('button', { name: '重置订阅链接', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByRole('heading', { name: '重置「订阅测试用户」的订阅链接？' }).waitFor()
    assert.equal(resets, 0)
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    assert.equal(resets, 0)
    await page.getByRole('button', { name: '订阅链接', exact: true }).click()
    await page.getByRole('dialog').getByText('可以获取', { exact: true }).waitFor()
    await page.getByRole('dialog').getByRole('button', { name: '重置订阅链接', exact: true }).click()
    await page.getByRole('dialog').getByRole('button', { name: '确认重置', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByText('可以获取', { exact: true }).waitFor()
    assert.equal(resets, 1)
    assert.equal(await dialog.getByLabel('配置预览').count(), 0)
    assert.deepEqual(await page.evaluate(() => Object.keys(localStorage).filter(key => /subscription|token|config/i.test(key))), [])
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.deepEqual(external, [])
    await dialog.getByRole('button', { name: '预览配置', exact: true }).click()
    await dialog.getByLabel('配置预览').waitFor()
    mode = 'unauthorized'
    await dialog.getByRole('button', { name: '复制配置', exact: true }).click()
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    assert.equal(await page.getByRole('dialog').count(), 0)
    assert.equal(await page.locator('.subscription-preview').count(), 0)
    assert.equal((await page.locator('body').innerText()).includes('fixture-secret'), false)
    assert.equal((await page.locator('body').innerText()).includes('fresh-fixture'), false)
    assert.deepEqual(await page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter(key => /subscription|token|config/i.test(key))), [])
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.deepEqual(external, [])
    results.push({ width, freshRequests: 'passed', download: 'passed', unavailable: 'passed', reset: 'passed', unauthorizedClearsView: 'passed' })
    await context.close()
  }
  const context = await browser.newContext(), page = await context.newPage(), privateRequests = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/dashboard/access') return route.fulfill({ json: { authenticated: false, public_dashboard: true } })
    privateRequests.push(path); return route.fulfill({ status: 401, json: { error: '请先登录' } })
  })
  await installControlCenterFixtures(page)
  await page.goto(`${origin}/#/plugins/sing-box/users`)
  await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
  assert.deepEqual(privateRequests, [])
  assert.equal(await page.locator('.subscription-dialog').count(), 0)
  await context.close()
  console.log(JSON.stringify(results))
} finally { await browser.close(); server.close() }
