import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

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
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], writes = []
    page.on('pageerror', error => errors.push(error.message))
    let signedIn = false, publicDashboard = true, rejectLogin = false
    const sessions = []
    const settings = { public_dashboard: true, offline_alerts: true, offline_minutes: 5, telegram_enabled: false, telegram_chat_id: '', telegram_token_configured: true }
    const now = Date.now(), second = Math.floor(now / 1000)
    const asset = { region: 'JP', group_name: '主力', tags: [], hidden: false, offline_notify: true, agent_mirror: '', price: '12.00', currency: 'CNY', billing_cycle: 30, expires_at: second + 86400, auto_renewal: false, traffic_limit: '1000000', traffic_limit_type: 'sum', reset_day: 1, network_interface: '' }
    const device = { id: 1, name: '演示服务器', device_public_key: 'TEST_ONLY', online: true, last_seen: second, last_heartbeat_at: second, metrics_sampled_at: now, metrics_stale: false, static_info: { hostname: 'PRIVATE_HOST', system: 'Ubuntu', arch: 'amd64', cpu_cores: 2, memory_total: 1073741824 }, latest_metrics: { cpu_percent: 10, memory_used: 1000 }, agent_settings: { sample_interval_secs: 10, upload_interval_secs: 30, auto_update: true, discover_public_ips: true }, capabilities: [], manifest_rev: 0, asset_settings: asset, traffic: { cycle_start: second - 100, cycle_end: second + 10000, uploaded: '100', downloaded: '200', used: '300', limit: '1000000', remaining: '999700', percent: 0.03, exceeded: false, observed_from: now, last_sample_at: now, incomplete: false, interfaces: [], correction_id: null, corrected: false } }
    const view = () => signedIn ? device : { ...device, public_view: true, registered: true, device_public_key: null, agent_settings: undefined, static_info: { ...device.static_info, hostname: undefined }, asset_settings: { region: 'JP', group_name: '主力', tags: [], traffic_limit: '1000000', traffic_limit_type: 'sum', reset_day: 1 } }
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/dashboard/access') return respond({ authenticated: signedIn, public_dashboard: publicDashboard })
      if (path === '/api/login') {
        sessions.push({ path, body: request.postDataJSON() })
        if (rejectLogin) return respond({ error: '测试登录失败' }, 401)
        signedIn = true
        return respond({})
      }
      if (path === '/api/logout') { signedIn = false; sessions.push({ path }); return respond({}) }
      if (method !== 'GET') writes.push({ path, body: request.postDataJSON() })
      if (path.startsWith('/api/dashboard/') && !signedIn && !publicDashboard) return respond({ error: '请先登录' }, 401)
      if (path === '/api/dashboard/exchange-rates') return respond({base:'CNY',rates:{CNY:1},rate_dates:{},rate_date:null,fetched_at:null,stale:true,status:'unavailable'})
      if (path.endsWith('/telemetry-settings')) return respond({persist_interval_secs:60})
      if (path === '/api/dashboard/servers') return respond([view()])
      if (path === '/api/dashboard/servers/1') return respond(view())
      if (path === '/api/exchange-rates') return respond({base:'CNY',rates:{CNY:1},rate_dates:{},rate_date:null,source:null,source_url:null,fetched_at:null,attempted_at:null,next_refresh_at:0,stale:true,status:'unavailable',error_code:null})
      if (path === '/api/settings') {
        if (method === 'PATCH') { Object.assign(settings, request.postDataJSON()); publicDashboard = settings.public_dashboard; delete settings.telegram_token }
        return respond(settings)
      }
      if (path === '/api/alert-rules') return respond([])
      if (path === '/api/servers') return respond([device])
      if (path === '/api/servers/1') {
        if (method === 'PATCH') { const body = request.postDataJSON(); device.agent_settings.auto_update = body.auto_update; Object.assign(asset, body.asset_settings) }
        return respond(device)
      }
      if (path === '/api/servers/1/traffic-correction') return respond({ correction_id: 1 })
      if (path.endsWith('/agent-settings')) return respond(device.agent_settings)
      if (path === '/api/notifications/webhook') return respond({enabled:false,preset:'custom',url_configured:false,headers_configured:false,body_configured:false})
      if (path === '/api/notifications/channels') return respond([])
      if (path === '/api/telemetry/policy') return respond({history_retention_days:30})
      if (path === '/api/notifications') return respond([{ id: 1, server_id: 1, server_name: '演示服务器', last_seen: second - 600, opened_at: second - 300, resolved_at: null, resolution: null, deliveries: [{ kind: 'offline', status: 'pending', attempts: 1, last_error: '模拟网络失败' }] }])
      if (path === '/api/plugins/sing-box/servers/1') return respond({ enabled: false, online: true, agent_supported: false, read_only: false, source: null })
      if (['/metrics', '/probes', '/probe-results', '/commands', '/overview'].some(suffix => path.endsWith(suffix))) return respond([])
      throw new Error(`Unexpected route ${path}`)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/dashboard`)
    await page.locator('.d-card').first().waitFor()
    assert.equal(await page.getByRole('heading', { name: '欢迎回来' }).count(), 0)
    await page.getByRole('link', { name: /演示服务器/ }).first().click()
    await page.getByRole('heading', { name: /演示服务器/ }).waitFor()
    assert.equal(await page.getByText('PRIVATE_HOST', { exact: true }).count(), 0)
    assert.equal(await page.getByText('CNY 12.00', { exact: false }).count(), 0)
    publicDashboard = false
    await page.getByRole('button', { name: '刷新服务器详情' }).click()
    await page.getByRole('heading', { name: '欢迎回来' }).waitFor()
    assert.equal(await page.locator('.d-detail').count(), 0)
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/system/settings`)
    await page.getByRole('heading', { name: '欢迎回来' }).waitFor()
    assert.equal(await page.locator('.sidebar').count(), 0)
    rejectLogin = true
    await page.getByLabel('管理员密码', { exact: true }).fill('TEST_ONLY')
    await page.getByLabel(/^二步验证码/).fill('123456')
    await page.getByRole('button', { name: '登录面板' }).click()
    await page.getByText('密码或验证码不正确、已过期或已使用，请重新输入。', { exact: true }).waitFor()
    assert.equal(await page.locator('.sidebar').count(), 0)
    rejectLogin = false
    await page.getByRole('button', { name: '登录面板' }).click()
    await page.getByRole('heading', { name: '看板与通知', exact: true }).waitFor()
    assert.deepEqual(sessions.slice(0, 2), [0, 1].map(() => ({ path: '/api/login', body: { login_name: 'admin', password: 'TEST_ONLY', totp_code: '123456' } })))
    await page.getByRole('switch', { name: /^公开服务器看板/ }).uncheck()
    await page.getByLabel('离线告警阈值（分钟）', { exact: false }).fill('8')
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `operations-settings-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '保存设置' }).click()
    await page.getByRole('status').filter({ hasText: '设置已保存' }).waitFor()
    const settingsWrite = writes.find(write => write.path === '/api/settings').body
    assert.equal(settingsWrite.offline_minutes, 8)
    assert.equal(Object.hasOwn(settingsWrite, 'telegram_token'), false)
    await page.getByRole('link', { name: '服务器', exact: true }).click()
    assert.equal(await page.getByRole('link', { name: '打开服务器看板', exact: true }).count(), 0)
    await page.getByRole('button', { name: '编辑', exact: true }).click()
    let dialog = page.getByRole('dialog')
    assert.equal(await dialog.getByRole('switch', { name: /^自动更新 Agent/ }).isChecked(), true)
    await dialog.getByRole('switch', { name: /^自动更新 Agent/ }).uncheck()
    await dialog.getByRole('switch', { name: /^离线告警/ }).uncheck()
    await dialog.getByLabel('Agent 下载加速', { exact: false }).fill('https://mirror.example.com')
    await dialog.getByRole('button', { name: '保存修改' }).click()
    await dialog.waitFor({ state: 'detached' })
    const edit = writes.find(write => write.path === '/api/servers/1').body
    assert.equal(edit.auto_update, false); assert.equal(edit.asset_settings.offline_notify, false)
    assert.equal(edit.asset_settings.agent_mirror, 'https://mirror.example.com')
    await page.getByRole('button', { name: '详情', exact: true }).click()
    await page.getByRole('button', { name: '流量矫正', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByLabel('矫正后的上传流量').fill('999')
    await dialog.getByLabel('矫正后的下载流量').fill('888')
    await dialog.getByLabel('矫正原因').fill('供应商账单对齐')
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `operations-correction-${width}.png`), fullPage: true, animations: 'disabled' })
    await dialog.getByRole('button', { name: '保存矫正' }).click()
    await dialog.waitFor({ state: 'detached' })
    const correction = writes.find(write => write.path.endsWith('traffic-correction')).body
    assert.equal(correction.baseline_uploaded, '100'); assert.equal(correction.uploaded, '999')
    await page.getByRole('link', { name: '告警通知', exact: true }).click()
    await page.getByText('持续离线', { exact: true }).waitFor()
    await page.getByText('模拟网络失败', { exact: true }).waitFor()
    await page.getByRole('button', { name: /退出登录/ }).click()
    await page.getByRole('heading', { name: '欢迎回来' }).waitFor()
    assert.equal(await page.locator('.sidebar').count(), 0)
    assert.equal(sessions.filter(session => session.path === '/api/logout').length, 1)
    await page.getByLabel('管理员密码', { exact: true }).fill('TEST_ONLY')
    await page.getByRole('button', { name: '登录面板' }).click()
    await page.getByText('持续离线', { exact: true }).waitFor()
    assert.equal(await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '告警通知', exact: true }).getAttribute('aria-current'), 'page')
    assert.deepEqual(errors, [])
    results.push({ width, publicAccess: 'passed', revocation: 'passed', sessions: 'passed', settings: 'passed', operations: 'passed' })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally { await browser.close(); server.close() }
