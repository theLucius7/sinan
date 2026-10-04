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
    const context = await browser.newContext({ viewport: { width, height: width > 800 ? 1000 : 844 } })
    const page = await context.newPage(), errors = [], unexpected = [], writes = []
    page.on('pageerror', error => errors.push(error.message))
    const now = Date.now(), second = Math.floor(now / 1000)
    const defaults = { region: '', group_name: '', tags: [], hidden: false, price: null, currency: 'CNY', billing_cycle: 30, expires_at: null, auto_renewal: false, traffic_limit: '0', traffic_limit_type: 'sum', reset_day: 1, network_interface: '' }
    const settings = { sample_interval_secs: 1, upload_interval_secs: 3, auto_update: false, discover_public_ips: true }
    const fixture = (id, name, asset) => ({ id, name, asset_settings: asset, device_public_key: 'TEST_ONLY', online: true, static_info: { hostname: 'fixture', system: 'Ubuntu', arch: 'x86_64', agent_version: '0.3.0', memory_total: 1024 ** 3, disk_total: 64 * 1024 ** 3 }, latest_metrics: { cpu_percent: 10, memory_used: 512 * 1024 ** 2, disk_used: 8 * 1024 ** 3, network_interfaces: { eth0: { transmitted_bytes: 500, received_bytes: 1000, transmit_bytes_per_sec: 1, receive_bytes_per_sec: 2 } } }, manifest_rev: 0, capabilities: [], metrics_sampled_at: now, metrics_stale: false, last_seen: second, traffic: { cycle_start: second - 15 * 86400, cycle_end: second + 15 * 86400, uploaded: '1073741824', downloaded: '536870912', used: '1073741824', limit: asset.traffic_limit, remaining: '536870912', percent: 66.6667, exceeded: false, observed_from: now - 86400000, last_sample_at: now, incomplete: false, interfaces: ['eth0'] } })
    let entries = [fixture(1, '备用服务器', { ...defaults, region: 'DE', group_name: '备用', tags: ['普通'], price: '0.00' })]
    const refreshTraffic = entry => {
      const asset = entry.asset_settings, traffic = entry.traffic, limit = BigInt(asset.traffic_limit)
      const up = BigInt(traffic.uploaded), down = BigInt(traffic.downloaded)
      const used = ({ up, down, sum: up + down, min: down, max: up })[asset.traffic_limit_type]
      Object.assign(traffic, { used: String(used), limit: String(limit), percent: limit === 0n ? null : Number(used) / Number(limit) * 100, remaining: limit === 0n ? null : String(limit > used ? limit - used : 0n), exceeded: limit > 0n && used >= limit })
    }
    entries.forEach(refreshTraffic)
    let failedPatch = false
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/dashboard/', '/api/')
      const fulfill = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/exchange-rates' && request.method() === 'GET') return route.fulfill({ json: { base: 'CNY', rates: { CNY: 1 }, rate_dates: {}, rate_date: null, source: null, source_url: null, fetched_at: null, attempted_at: null, next_refresh_at: 0, stale: true, status: 'unavailable', error_code: null } })
      if (path === '/api/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (/^\/api\/servers\/\d+\/telemetry-settings$/.test(path) && request.method() === 'GET') return route.fulfill({ json: { persist_interval_secs: 60 } })
      if (path === '/api/me') return fulfill({ id: 1 })
      if (path === '/api/artifacts/agent-versions') return fulfill({ versions: [{ version: '0.3.0', tag: 'agent-v0.3.0', targets: ['linux-musl-amd64'], cached_targets: ['linux-musl-amd64'], protocol_min: 1, protocol_max: 1 }] })
      if (request.method() !== 'GET') writes.push({ path, method: request.method(), body: request.postDataJSON() })
      if (path === '/api/servers' && request.method() === 'GET') return fulfill(entries)
      if (path === '/api/servers' && request.method() === 'POST') {
        const body = request.postDataJSON(), entry = fixture(2, body.name, body.asset_settings)
        refreshTraffic(entry); entries.push(entry); return fulfill(entry, 201)
      }
      if (/^\/api\/servers\/\d+$/.test(path)) {
        const entry = entries.find(entry => path.endsWith(`/${entry.id}`))
        if (request.method() === 'PATCH') {
          if (failedPatch) return fulfill({ error: '测试：资产保存失败' }, 400)
          const body = request.postDataJSON()
          Object.assign(entry, { name: body.name, ...(body.asset_settings ? { asset_settings: body.asset_settings } : {}) }); refreshTraffic(entry)
        }
        return fulfill(entry)
      }
      if (path.endsWith('/enrollment')) return fulfill({ token: 'TEST_ONLY', expires_at: second + 86400, install_command: 'sudo sinan-bootstrap --token TEST_ONLY', installation: { version: '0.3.0', tag: 'agent-v0.3.0' } })
      if (path.endsWith('/agent-settings')) return fulfill(settings)
      if (path.endsWith('/probes') || path.endsWith('/probe-results') || path.endsWith('/commands') || path.endsWith('/metrics') || path === '/api/probes/overview') return fulfill([])
      if (/^\/api\/plugins\/sing-box\/servers\/\d+$/.test(path)) return fulfill({ id: 2, name: '东京资产', enabled: false, online: true, agent_supported: false, read_only: false, source: null })
      unexpected.push(`${request.method()} ${path}`)
      return fulfill({ error: 'Unexpected fixture request' }, 500)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers`)
    await page.getByRole('button', { name: '添加服务器', exact: true }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByLabel('服务器名称', { exact: false }).fill('东京资产')
    await dialog.getByLabel('地区代码').fill('jp')
    await dialog.getByLabel('展示分组').fill('主力')
    await dialog.getByRole('textbox', { name: /^标签/ }).fill('线路:BGP, SSD, 线路:BGP')
    await dialog.getByLabel('每周期金额', { exact: false }).fill('12.50')
    await dialog.getByLabel('币种', { exact: true }).fill('USD')
    await dialog.getByLabel('费用周期（天）', { exact: false }).fill('90')
    await dialog.getByLabel('到期日期（UTC）', { exact: false }).fill(new Date(now + 5 * 86400000).toISOString().slice(0, 10))
    await dialog.getByLabel('每期流量额度', { exact: true }).fill('1.5')
    await dialog.getByLabel('流量额度单位').selectOption('GiB')
    await dialog.getByLabel('流量统计口径').selectOption('up')
    await dialog.getByLabel('每月重置日（UTC）', { exact: false }).fill('31')
    await dialog.getByLabel('统计网卡', { exact: false }).fill('eth*,!eth1')
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false)
    if (screenshots) { await dialog.getByRole('heading', { name: '成本与到期' }).scrollIntoViewIfNeeded(); await page.screenshot({ animations: 'disabled', path: resolve(screenshots, `asset-form-${width}.png`) }) }
    await dialog.getByRole('button', { name: '创建并继续' }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).waitFor()
    const created = writes.find(write => write.path === '/api/servers').body
    assert.equal(created.asset_settings.traffic_limit, '1610612736')
    assert.equal(created.asset_settings.price, '12.50')
    assert.equal(created.asset_settings.currency, 'USD')
    assert.equal(created.asset_settings.region, 'JP')
    assert.deepEqual(created.asset_settings.tags, ['线路:BGP', 'SSD'])
    assert.equal(created.asset_settings.reset_day, 31)
    await dialog.getByRole('button', { name: '查看服务器' }).click()
    await page.getByRole('heading', { name: '资产与流量额度' }).waitFor()
    await page.getByText('USD 12.50 / 90 天', { exact: true }).waitFor()
    await page.getByRole('button', { name: '编辑资产配置' }).click()
    assert.equal(await dialog.getByLabel('每期流量额度', { exact: true }).inputValue(), '1.5')
    assert.equal(await dialog.getByLabel('流量额度单位').inputValue(), 'GiB')
    await dialog.getByLabel('每期流量额度', { exact: true }).fill('18446744073709551615')
    await dialog.getByLabel('流量额度单位').selectOption('B')
    await dialog.getByRole('switch', { name: /自动顺延到期记录/ }).check()
    failedPatch = true
    await dialog.getByRole('button', { name: '保存修改' }).click()
    await dialog.getByRole('alert').filter({ hasText: '测试：资产保存失败' }).waitFor()
    assert.equal(await dialog.getByLabel('每期流量额度', { exact: true }).inputValue(), '18446744073709551615')
    failedPatch = false
    await dialog.getByRole('button', { name: '保存修改' }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.equal(entries[1].asset_settings.traffic_limit, '18446744073709551615')
    assert.equal(entries[1].asset_settings.auto_renewal, true)
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/overview`)
    const card = page.getByRole('link', { name: /东京资产，在线，查看详情/ })
    await card.waitFor()
    assert.match(await card.locator('.d-card-header strong').getAttribute('title'), /主力 · 线路:BGP · SSD/)
    assert.equal(await card.getByText('线路:BGP', { exact: true }).count(), 0)
    assert.equal(await card.locator('.d-data-grid > .d-data').count(), 3)
    assert.equal(await card.locator('.d-data[aria-label="剩余价值与到期"]').count(), 1)
    assert.equal(await page.getByRole('heading', { name: '服务器成本', exact: true }).count(), 0)
    assert.equal(await page.locator('.d-overview-item').filter({ has: page.locator('.d-overview-label').getByText('资产', { exact: true }) }).count(), 1)
    await page.getByRole('group', { name: '服务器分组', exact: true }).getByRole('button', { name: '主力', exact: true }).click()
    assert.equal(await page.locator('.d-card').count(), 1)
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    await page.getByLabel('地区', { exact: false }).selectOption('DE')
    await page.getByText('没有匹配的节点', { exact: true }).waitFor()
    await page.getByRole('button', { name: '清除筛选', exact: true }).first().click()
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    await page.getByRole('searchbox', { name: '搜索服务器' }).fill('SSD')
    await card.waitFor()
    assert.equal(await page.locator('.d-card').count(), 1)
    if (screenshots) await page.screenshot({ animations: 'disabled', path: resolve(screenshots, `asset-display-${width}.png`) })
    await card.click()
    await page.getByRole('heading', { name: '资产与流量额度' }).waitFor()
    await page.getByText('线路:BGP', { exact: true }).waitFor()
    await page.getByText(/统计网卡：eth\*,!eth1/).waitFor()
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/2`)
    await page.getByRole('button', { name: '编辑资产配置' }).click()
    await dialog.getByRole('switch', { name: /在展示页隐藏/ }).check()
    await dialog.getByLabel('每周期金额', { exact: false }).fill('')
    await dialog.getByLabel('到期日期（UTC）', { exact: false }).fill('')
    await dialog.getByRole('textbox', { name: /^标签/ }).fill('')
    assert.equal(await dialog.getByRole('switch', { name: /自动顺延到期记录/ }).isChecked(), false)
    await dialog.getByRole('button', { name: '保存修改' }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.equal(entries[1].asset_settings.price, null)
    assert.equal(entries[1].asset_settings.expires_at, null)
    assert.deepEqual(entries[1].asset_settings.tags, [])
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/overview`)
    await page.getByRole('link', { name: /备用服务器，在线，查看详情/ }).waitFor()
    assert.equal(await page.getByRole('link', { name: /东京资产，在线，查看详情/ }).count(), 0)
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers`)
    await page.getByRole('button', { name: /东京资产/ }).waitFor()
    assert.deepEqual(errors, [])
    assert.deepEqual(unexpected, [])
    results.push({ width, assets: 'passed', exactBytes: 'passed', editing: 'passed', filters: 'passed', hiding: 'passed', browserErrors: errors.length })
    await context.close()
  }
  console.log(JSON.stringify(results, null, 2))
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
