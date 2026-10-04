import { installControlCenterFixtures } from './control-center-fixtures.mjs'
// Built-page regression with isolated API fixtures; never connects to a deployed panel.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.txt': 'text/plain' }
const host = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(done => host.listen(0, '127.0.0.1', done))
const origin = `http://127.0.0.1:${host.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const results = []
let activePage
const settle = () => new Promise(done => setTimeout(done, 150))

try {
  for (const width of [1440, 768, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 }, colorScheme: 'light' })
    const page = await context.newPage(), errors = [], writes = []
    const statValue = async label => (await page.locator('.d-overview-item').filter({ has: page.locator('.d-overview-label').getByText(label, { exact: true }) }).locator('.d-overview-value').innerText()).replace(/\s+/g, ' ')
    const visibility = value => page.evaluate(value => { Object.defineProperty(document, 'visibilityState', { configurable: true, value }); document.dispatchEvent(new Event('visibilitychange')) }, value)
    activePage = page
    page.on('pageerror', error => { errors.push(error.message); console.error('Page error:', error.message) })
    await page.clock.install()
    const GiB = 1024 ** 3, initial = Date.now()
    let signedIn = true, fail = false, empty = false, hiddenOnly = false, hold = false
    let serversRead = 0, probesRead = 0, release
    const entries = [
      ['东京 · 入口', true, false, 'JP', '亚洲', 0],
      ['新加坡 · 出口', true, false, 'SG', '亚洲', 96],
      ['法兰克福', false, false, 'DE', '欧洲', 42],
      ['台北 · 待更新', true, true, 'TW', '亚洲', 88],
      ['待接入设备', false, false, '', '', null],
      ['隐藏设备', true, false, 'US', '美洲', 100],
    ].map(([name, online, stale, region, group, cpu], i) => ({
      id: i + 1, name, online, metrics_stale: stale, device_public_key: i === 4 ? null : 'TEST_ONLY',
      metrics_sampled_at: i === 4 ? null : initial - (stale ? 600000 : 0), last_seen: initial / 1000, last_heartbeat_at: initial / 1000, manifest_rev: 0,
      static_info: { system: i === 2 ? 'Debian 12' : 'Ubuntu 24.04', arch: 'amd64', cpu_cores: 2, memory_total: 2 * GiB, disk_total: 32 * GiB },
      latest_metrics: { cpu_percent: cpu ?? undefined, memory_used: GiB, disk_used: 12 * GiB, swap_used: 0, swap_total: 0, load_1: .4, uptime_secs: 86400, tcp_connections: 12, network_interfaces: { eth0: { transmit_bytes_per_sec: i === 0 ? 0 : 1048576, receive_bytes_per_sec: i === 0 ? 0 : 2097152, transmitted_bytes: 10 * GiB, received_bytes: 30 * GiB } } },
      asset_settings: { region, group_name: group, tags: [], hidden: i === 5, price: null, currency: 'CNY', billing_cycle: 30, expires_at: null, auto_renewal: false, traffic_limit: '0', traffic_limit_type: 'sum', reset_day: 1, network_interface: '' },
    }))
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname.replace('/api/dashboard/', '/api/')
      if (request.method() !== 'GET') writes.push(path)
      if (path === '/api/exchange-rates' && request.method() === 'GET') return route.fulfill({ json: { base: 'CNY', rates: { CNY: 1 }, rate_dates: {}, rate_date: null, source: null, source_url: null, fetched_at: null, attempted_at: null, next_refresh_at: 0, stale: true, status: 'unavailable', error_code: null } })
      if (path === '/api/access') return route.fulfill({ json: { authenticated: signedIn, public_dashboard: false } })
      if (path === '/api/me') return route.fulfill({ status: signedIn ? 200 : 401, json: signedIn ? {} : { error: '登录已过期' } })
      if (path === '/api/servers') {
        serversRead++
        if (hold) await new Promise(done => { release = done })
        return route.fulfill({ status: !signedIn ? 401 : fail ? 503 : 200, json: !signedIn ? { error: '登录已过期' } : fail ? { error: '测试读取失败' } : empty ? [] : hiddenOnly ? [entries[5]] : entries }).catch(() => {})
      }
      if (path === '/api/probes/overview') { probesRead++; return route.fulfill({ json: [] }) }
      if (/^\/api\/servers\/[1-9]\d*$/.test(path)) return route.fulfill({ json: entries.find(s => s.id === Number(path.split('/').at(-1))) })
      if (['/metrics', '/probes', '/probe-results'].some(suffix => path.endsWith(suffix))) return route.fulfill({ json: [] })
      throw new Error(`Unexpected API: ${path}`)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers`)
    await page.getByRole('link', { name: '服务器看板', exact: true }).click()
    await page.getByRole('region', { name: '服务器总览', exact: true }).waitFor()
    await page.locator('.d-card').first().waitFor()
    assert(page.url().endsWith('/#/dashboard'))
    assert.equal(await page.locator('.sidebar').count(), 0)
    assert.equal(await page.locator('.d-card').count(), 5)
    assert.equal(await statValue('实时上行'), '1.0 MiB/秒')
    for (const phrase of ['基础设施监控', '集中查看设备状态与网络质量', '最近成功读取', '实时状态 · 每 3 秒读取', '汇总覆盖所有未隐藏', '每次显示的都是实际采样', '服务器成本', '每日参考汇率', '统一币种对比', '界面来源与许可']) assert(!(await page.locator('body').innerText()).includes(phrase), `Dashboard must omit explanatory copy: ${phrase}`)
    for (const name of ['全屏看板', '退出全屏看板', '暂停自动刷新', '恢复自动刷新', '更新汇率']) assert.equal(await page.getByRole('button', { name, exact: true }).count(), 0)
    assert.equal(await page.getByRole('button', { name: '筛选与视图', exact: true }).getAttribute('aria-expanded'), 'false')
    assert.equal(await page.getByRole('group', { name: '服务器状态筛选', exact: true }).count(), 0)
    assert.equal(await page.getByRole('link', { name: /^隐藏设备/ }).count(), 0)
    if (screenshots && [1440, 390].includes(width)) await page.screenshot({ path: resolve(screenshots, `dashboard-cards-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    assert.equal(await page.getByRole('button', { name: '指标待更新', exact: true }).locator('.d-filter-count').innerText(), '1')
    assert.equal(await page.getByRole('button', { name: '离线', exact: true }).locator('.d-filter-count').innerText(), '1')
    assert.equal(await page.getByRole('button', { name: '待接入', exact: true }).locator('.d-filter-count').innerText(), '1')
    await page.getByRole('button', { name: '表格', exact: true }).click()
    await page.locator('.d-fleet tbody tr').first().waitFor()
    assert.equal(await page.locator('.d-fleet tbody tr').count(), 5)
    await page.getByLabel('排序', { exact: true }).selectOption('cpu')
    assert.equal(await page.locator('.d-fleet tbody tr').first().getAttribute('data-server-id'), '2')
    await page.getByRole('group', { name: '服务器分组', exact: true }).getByRole('button', { name: '亚洲', exact: true }).click()
    await page.getByLabel('地区', { exact: true }).selectOption('JP')
    assert.equal(await page.locator('.d-fleet tbody tr').count(), 1)
    assert.match(await page.locator('.d-fleet tbody tr').innerText(), /0\.0%/)
    await page.getByRole('button', { name: '清除筛选', exact: true }).click()
    await page.getByRole('button', { name: '指标待更新', exact: true }).click()
    assert.equal(await page.locator('.d-fleet tbody tr').count(), 1)
    assert.match(await page.locator('.d-fleet tbody tr').innerText(), /指标已过期/)
    await page.getByRole('group', { name: '服务器状态筛选', exact: true }).getByRole('button', { name: '全部', exact: true }).click()
    await page.getByRole('button', { name: '切换深色主题', exact: true }).click()
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    if (screenshots && [1440, 390].includes(width)) await page.screenshot({ path: resolve(screenshots, `dashboard-table-dark-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.reload()
    await page.locator('.d-fleet tbody tr').first().waitFor()
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    assert.equal(await page.getByLabel('排序', { exact: true }).inputValue(), 'cpu')
    assert.equal(await page.locator('.server-display').getAttribute('data-theme'), 'dark')
    await page.getByRole('link', { name: '查看 东京 · 入口 详情', exact: true }).click()
    assert(page.url().endsWith('/#/dashboard/1'))
    await page.getByRole('link', { name: '返回服务器看板', exact: true }).click()
    await page.locator('.d-fleet tbody tr').first().waitFor()
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/overview/1`)
    await page.getByRole('link', { name: '返回服务器看板', exact: true }).click()
    assert(page.url().endsWith('/#/dashboard'))
    await page.locator('.d-fleet tbody tr').first().waitFor()
    // Polling stays automatic; it does not need an exposed pause control.
    await settle()
    const before = [serversRead, probesRead]
    await page.clock.fastForward(15000); await settle()
    assert(serversRead > before[0])
    assert(probesRead > before[1])
    assert.equal(await page.locator('.d-fleet tbody tr').count(), 5)
    const beforeManual = [serversRead, probesRead]
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click(); await settle()
    assert.deepEqual([serversRead, probesRead], beforeManual.map(v => v + 1))
    assert.equal(await statValue('实时上行'), '1.0 MiB/秒')
    if (width === 1440) {
      // Visibility is simulated; no production browser or external requests are involved.
      await visibility('hidden')
      const hiddenReads = [serversRead, probesRead]
      await page.clock.fastForward(20000); await settle()
      assert.deepEqual([serversRead, probesRead], hiddenReads)
      await visibility('visible')
      await settle()
      assert.deepEqual([serversRead, probesRead], hiddenReads.map(v => v + 1))
      // A stalled read is aborted, cannot overlap polls and cannot keep old rates live.
      hold = true
      await page.getByRole('button', { name: '刷新服务器', exact: true }).click(); await settle()
      const stalled = serversRead
      await page.clock.fastForward(10000); await settle()
      assert.equal(serversRead, stalled)
      await page.clock.fastForward(3000); await settle()
      await page.getByText('读取超过 12 秒，保留上次快照，请重试。', { exact: false }).waitFor()
      hold = false; release?.(); await settle()
      await page.getByRole('button', { name: '刷新服务器', exact: true }).click(); await settle()
      assert.equal(await statValue('实时上行'), '1.0 MiB/秒')
    }
    fail = true
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByText('测试读取失败', { exact: false }).waitFor()
    assert.equal(await page.locator('.d-fleet tbody tr').count(), 5)
    assert.equal(await statValue('实时上行'), '—')
    fail = false; hiddenOnly = true
    await page.getByRole('button', { name: '重试', exact: true }).click()
    await page.getByText('节点已隐藏', { exact: true }).waitFor()
    hiddenOnly = false; empty = true
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByText('尚未添加节点', { exact: true }).waitFor()
    if (width === 1440) {
      empty = false; hold = true
      await page.reload()
      await page.getByRole('region', { name: '服务器总览', exact: true }).waitFor()
      await settle()
      await visibility('hidden'); await settle()
      assert.equal(await page.getByText('尚未添加节点', { exact: true }).count(), 0)
      const cancelled = serversRead
      hold = false; release?.(); await settle()
      // A late response to the cancelled first read cannot restore a snapshot.
      assert.equal(await page.locator('.d-fleet tbody tr').count(), 0)
      assert.equal(serversRead, cancelled)
      await visibility('visible')
      await page.locator('.d-fleet tbody tr').first().waitFor()
    }
    empty = false; signedIn = false
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    const loggedOut = serversRead
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/dashboard`)
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    assert.equal(serversRead, loggedOut)
    assert.deepEqual(writes, []); assert.deepEqual(errors, [])
    results.push({ width, passed: true, writes: writes.length, browserErrors: errors.length })
    await context.close()
  }
  console.log(JSON.stringify(results))
} catch (error) {
  if (activePage && !activePage.isClosed()) {
    console.error('Failed page:', activePage.url(), await activePage.locator('body').innerText())
    if (screenshots) await activePage.screenshot({ path: resolve(screenshots, 'dashboard-failure.png'), fullPage: true })
  }
  throw error
} finally { await browser.close(); await new Promise(done => host.close(done)) }
