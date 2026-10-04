import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.webp': 'image/webp', '.txt': 'text/plain' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const content = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(content) }
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
    const context = await browser.newContext({ viewport: { width, height: 1000 }, colorScheme: 'light' })
    const page = await context.newPage(), errors = [], writes = [], requests = []
    const statValue = async label => (await page.locator('.d-overview-item').filter({ has: page.locator('.d-overview-label').getByText(label, { exact: true }) }).locator('.d-overview-value').innerText()).replace(/\s+/g, ' ')
    page.on('pageerror', error => errors.push(error.message))
    const now = Date.now(), GiB = 1024 ** 3
    const metrics = (cpu, rate) => ({ cpu_percent: cpu, memory_used: GiB * 1.2, disk_used: GiB * 16, swap_used: 0, swap_total: GiB, processes: 84, tcp_connections: 32, udp_connections: 5, load_1: .2, load_5: .3, load_15: .25, uptime_secs: 86400 * 28, network_interfaces: { eth0: { received_bytes: GiB * 48, transmitted_bytes: GiB * 16, receive_bytes_per_sec: rate * 2, transmit_bytes_per_sec: rate } }, disks: [{ name: 'vda', mount_point: '/', used_bytes: GiB * 16, total_bytes: GiB * 64, read_bytes_per_sec: null, write_bytes_per_sec: 0 }], gpus: [] })
    let entries = [
      ['东京 · 主节点', 'Ubuntu 24.04', 'x86_64', true, false, now, 'TEST_ONLY'],
      ['新加坡 · 边缘节点', 'Debian 12', 'aarch64', true, false, now, 'TEST_ONLY'],
      ['法兰克福 · 存储节点', 'FreeBSD 14', 'x86_64', true, true, now - 600_000, 'TEST_ONLY'],
      ['本地 · 开发设备', 'macOS', 'aarch64', true, false, null, 'TEST_ONLY'],
      ['伦敦 · 备用节点', 'Alpine Linux', 'x86_64', false, true, now - 3600_000, 'TEST_ONLY'],
      ['等待接入的服务器', undefined, undefined, false, false, null, null],
    ].map(([name, system, arch, online, metrics_stale, metrics_sampled_at, device_public_key], index) => ({ id: index + 1, name, device_public_key, static_info: { hostname: `fixture-${index + 1}`, system, arch, kernel: 'TEST_ONLY', cpu_model: '测试处理器', cpu_cores: 4, memory_total: GiB * 4, disk_total: GiB * 64, virtualization: 'KVM', agent_version: '0.3.0' }, online, metrics_stale, metrics_sampled_at, last_seen: Math.floor((metrics_sampled_at ?? now) / 1000), last_heartbeat_at: Math.floor(now / 1000), manifest_rev: 0, latest_metrics: index === 5 ? {} : metrics(index === 0 ? 0 : index * 12.5, (index < 2 ? index + 1 : 100) * 1024 ** 2) }))
    const samples = Array.from({ length: 120 }, (_, index) => ({ id: `sample-${index}`, sampled_at: now - (120 - index) * 5000, metrics: metrics(index === 44 ? 96 : 15 + Math.sin(index / 6) * 10, (1 + Math.sin(index / 4) * .5) * 1024 ** 2) })).filter((_, index) => index < 55 || index > 68)
    const definitions = [
      { id: 'probe-1', name: '测试目标', kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 10, carrier: '测试线路', enabled: true },
      { id: 'probe-2', name: '回显目标', kind: 'icmp', target: '::1', port: null, interval_secs: 10, carrier: '', enabled: true },
      { id: 'probe-3', name: '不可用目标', kind: 'icmp', target: '127.0.0.1', port: null, interval_secs: 10, carrier: '', enabled: true },
    ].map(spec => ({ ...spec, monitor: { network: 'other', region: '', address_family: 'any', authorization: { kind: 'owned', source: 'TEST_ONLY fixture owner', scope: 'TEST_ONLY loopback measurement display', enabled: true, expires_at: null, identity: { kind: spec.kind, target: spec.target, port: spec.port, address_family: 'any' } } } }))
    const probeResults = definition => Array.from({ length: 20 }, (_, index) => ({ id: `result-${definition.id}-${index}`, probe_id: definition.id, sampled_at: now - index * 10_000, latency_ms: definition.id === 'probe-2' && index === 0 ? null : index === 0 ? 0 : 20 + index, loss_percent: definition.id === 'probe-1' ? 0 : 100, error: definition.id === 'probe-3' ? 'permission denied' : null }))
    let failure = 0, signedIn = true, historyFailure = false, probeFailure = false, missing = false, reads = 0
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/dashboard/', '/api/')
      requests.push(path + url.search)
      if (request.method() !== 'GET') writes.push(path)
      if (path === '/api/exchange-rates' && request.method() === 'GET') return route.fulfill({ json: { base: 'CNY', rates: { CNY: 1 }, rate_dates: {}, rate_date: null, source: null, source_url: null, fetched_at: null, attempted_at: null, next_refresh_at: 0, stale: true, status: 'unavailable', error_code: null } })
      if (path === '/api/access') return route.fulfill({ json: { authenticated: signedIn && failure !== 401, public_dashboard: false } })
      if (path === '/api/me') { await route.fulfill({ status: signedIn ? 200 : 401, json: signedIn ? {} : { error: '登录已过期' } }); return }
      if (path === '/api/servers') {
        reads++
        await route.fulfill({ status: failure || 200, json: failure ? { error: '测试读取失败' } : entries }); return
      }
      if (/^\/api\/servers\/\d+$/.test(path)) {
        const entry = entries.find(entry => path.endsWith(`/${entry.id}`))
        await route.fulfill({ status: missing || !entry ? 404 : 200, json: missing || !entry ? { error: '服务器不存在' } : entry }); return
      }
      if (path.endsWith('/metrics')) { await route.fulfill({ status: historyFailure ? 403 : 200, json: historyFailure ? { error: '测试历史读取失败' } : samples.filter(sample => sample.sampled_at >= Number(url.searchParams.get('since'))) }); return }
      if (probeFailure && (path.endsWith('/probes') || path.endsWith('/probe-results') || path === '/api/probes/overview')) { await route.fulfill({ status: 403, json: { error: '测试拨测读取失败' } }); return }
      if (path === '/api/probes/overview') { await route.fulfill({ json: entries.filter(entry => entry.id < 4).flatMap(entry => definitions.map(probe => ({ server_id: entry.id, probe, results: probeResults(probe).map(result => ({ ...result, sampled_at: entry.id === 3 ? result.sampled_at - 600_000 : result.sampled_at })) }))) }); return }
      if (path.endsWith('/probes')) { await route.fulfill({ json: definitions }); return }
      if (path.endsWith('/probe-results')) { const selected = definitions.find(probe => probe.id === url.searchParams.get('probe_id')) ?? definitions[0]; await route.fulfill({ json: probeResults(selected) }); return }
      throw Error(`Unexpected API ${path}`)
    })
    await installControlCenterFixtures(page)
    await page.goto(origin)
    await page.getByRole('region', { name: '服务器总览', exact: true }).waitFor()
    await page.locator('.d-card').first().waitFor()
    assert.equal(await page.locator('.d-card').count(), 6)
    assert.equal(await statValue('实时上行'), '3.0 MiB/秒')
    assert.equal(await statValue('实时下行'), '6.0 MiB/秒')
    assert.match(await page.locator('.d-card').nth(0).innerText(), /0\.0%/)
    assert.match(await page.locator('.d-card').nth(2).innerText(), /指标已过期/)
    assert.match(await page.locator('.d-card').nth(3).innerText(), /采样时间未知/)
    await page.locator('.d-card').first().getByText('测试线路 · 测试目标', { exact: true }).first().waitFor()
    assert.match(await page.locator('.d-card').first().innerText(), /连接失败率/)
    assert.match(await page.locator('.d-card').first().innerText(), /100\.0%/)
    assert.match(await page.locator('.d-card').first().innerText(), /检测不可用/)
    assert.match(await page.locator('.d-card').nth(2).innerText(), /采样已过期/)
    assert.match(await page.locator('.d-card').last().innerText(), /尚未配置拨测/)
    assert.equal(await page.locator('.d-card').first().locator('.d-quality-bar').count(), 120)
    assert.equal(await page.locator('.d-card').first().locator('.d-metric').count(), 4)
    assert.equal(await page.locator('.d-card').first().locator('.d-metric').last().locator('div > span').innerText(), '流量')
    assert.equal(await page.getByRole('button', { name: /全屏看板|暂停自动刷新|更新汇率/ }).count(), 0)
    assert(!await page.locator('.sidebar').count())
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `display-light-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByLabel('搜索服务器', { exact: true }).fill('  deBIan ')
    assert.equal(await page.locator('.d-card').count(), 1)
    await page.getByLabel('搜索服务器', { exact: true }).fill('no-match')
    await page.getByText('没有匹配的节点', { exact: true }).waitFor()
    await page.getByRole('button', { name: '清除筛选', exact: true }).click()
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    await page.getByRole('button', { name: '待接入', exact: true }).click()
    assert.equal(await page.locator('.d-card').count(), 1)
    await page.getByRole('group', { name: '服务器状态筛选', exact: true }).getByRole('button', { name: '全部', exact: true }).click()
    await page.getByRole('button', { name: '筛选与视图', exact: true }).click()
    await page.getByRole('button', { name: '切换深色主题' }).click()
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `display-dark-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.reload()
    await page.locator('.d-card').first().waitFor()
    assert.equal(await page.locator('.server-display').getAttribute('data-theme'), 'dark')
    await page.getByRole('link', { name: '东京 · 主节点，在线，查看详情', exact: true }).click()
    await page.getByRole('heading', { name: /^东京 · 主节点/ }).waitFor()
    await page.locator('.d-chart svg[role="img"]').first().waitFor()
    await page.getByRole('heading', { name: '测试目标 · 延迟', exact: true }).waitFor()
    const chart = page.locator('.d-chart').first()
    const svg = chart.locator('svg[role="img"]')
    await svg.focus(); await page.keyboard.press('End')
    assert.match(await chart.locator('.d-chart-legend').innerText(), /0\.0%/)
    await chart.getByRole('button', { name: '使用率' }).click()
    await chart.getByText('已隐藏全部曲线', { exact: true }).waitFor()
    await chart.getByRole('button', { name: '使用率' }).click()
    const probe = page.locator('.d-probes')
    await probe.locator('svg[role="img"]').first().focus(); await page.keyboard.press('End')
    assert.match(await probe.locator('.d-chart-legend').first().innerText(), /0\.0 ms/)
    assert.match(await probe.locator('.d-probe-summary').innerText(), /连接失败率 0\.0%/)
    await page.getByLabel('拨测目标', { exact: true }).selectOption('probe-2')
    await probe.getByRole('heading', { name: '回显目标 · 丢包率', exact: true }).waitFor()
    await probe.locator('svg[role="img"]').last().focus(); await page.keyboard.press('End')
    assert.match(await probe.locator('.d-chart-legend').last().innerText(), /100\.0%/)
    await page.getByLabel('拨测目标', { exact: true }).selectOption('probe-3')
    await page.getByText('最近一次检测不可用：permission denied。该次结果以空缺显示。', { exact: true }).waitFor()
    assert(!/100\.0%/.test(await probe.locator('.d-probe-summary').innerText()))
    await probe.getByRole('group', { name: '拨测时间范围' }).getByRole('button', { name: '24 小时' }).click()
    await page.getByText('正在读取拨测结果…', { exact: true }).waitFor({ state: 'hidden' })
    assert(requests.some(path => path.includes('probe-results?probe_id=probe-3&hours=24')))
    probeFailure = true
    await page.reload()
    await page.getByText('暂时无法读取拨测配置', { exact: true }).waitFor()
    assert.equal(await page.getByText('尚无已配置的拨测项目', { exact: true }).count(), 0)
    probeFailure = false
    await page.locator('.d-probes').getByRole('button', { name: '重试', exact: true }).click()
    await page.getByRole('heading', { name: '测试目标 · 延迟', exact: true }).waitFor()
    await page.getByRole('group', { name: '资源时间范围' }).getByRole('button', { name: '2 小时' }).click()
    await page.getByText('正在读取历史采样…', { exact: true }).waitFor({ state: 'hidden' })
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    const scale = await page.locator('.d-chart svg[role="img"]').first().evaluate(element => element.getBoundingClientRect().width / element.viewBox.baseVal.width)
    assert(scale > .95 && scale < 1.05, 'Chart labels must retain their readable font size on mobile')
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `detail-dark-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '切换浅色主题' }).click()
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `detail-light-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('link', { name: '返回服务器看板', exact: true }).click()
    await page.getByRole('link', { name: '进入后台', exact: true }).click()
    await page.locator('.sidebar').waitFor()
    assert.equal(await page.locator('.server-display').count(), 0)
    assert.equal(await page.evaluate(() => document.body.classList.contains('has-server-display')), false)
    assert.equal(await page.locator('.sidebar').evaluate(element => getComputedStyle(element).backgroundColor), 'rgb(251, 252, 249)')
    await page.getByRole('link', { name: '服务器看板', exact: true }).click()
    await page.locator('.d-card').first().waitFor()
    probeFailure = true
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByRole('alert').getByText('拨测读取失败', { exact: true }).waitFor()
    assert((await page.locator('.d-card').first().locator('.d-quality-value').allTextContents()).every(value => value === '—'))
    probeFailure = false
    await page.getByRole('button', { name: '重试拨测', exact: true }).click()
    await page.getByRole('alert').waitFor({ state: 'hidden' })
    failure = 403
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByRole('alert').waitFor()
    assert.equal(await page.locator('.d-card').count(), 0)
    assert.equal(await statValue('实时上行'), '—')
    failure = 0
    await page.getByRole('button', { name: '重试', exact: true }).click()
    await page.getByRole('alert').waitFor({ state: 'hidden' })
    assert.equal(await statValue('实时上行'), '3.0 MiB/秒')
    await page.getByRole('link', { name: '法兰克福 · 存储节点，在线，查看详情', exact: true }).click()
    await page.getByText('指标已过期；在线心跳不代表指标仍在采集。', { exact: false }).waitFor()
    assert.equal(await page.locator('.d-live-strip > div').nth(2).locator('strong').innerText(), '—')
    historyFailure = true
    await page.getByRole('group', { name: '资源时间范围' }).getByRole('button', { name: '1 小时' }).click()
    await page.getByRole('alert').waitFor()
    assert.match(await page.getByRole('alert').innerText(), /历史采样刷新失败/)
    historyFailure = false
    missing = true
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/overview/999`)
    await page.getByRole('alert').waitFor()
    assert.equal(await page.locator('.d-detail-hero').count(), 0)
    missing = false
    const savedEntries = entries
    entries = []
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/overview`)
    await page.getByText('尚未添加节点', { exact: true }).waitFor()
    entries = savedEntries
    failure = 401
    await page.getByRole('button', { name: '刷新服务器', exact: true }).click()
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    assert.equal(await page.locator('.server-display').count(), 0)
    signedIn = false
    const before = reads
    await page.reload()
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    assert.equal(reads, before)
    assert.deepEqual(writes, [])
    assert.deepEqual(errors, [])
    results.push({ width, browserErrors: errors.length, writes: writes.length, checked: ['real-zero', 'missing-data', 'stale-rates-excluded', 'search', 'status-filter', 'theme-persistence', 'history-ranges', 'keyboard-chart', 'zero-latency', 'icmp-total-loss', 'unavailable-measurement', 'quality-bars', 'per-target-history', 'overview-read-failure', 'server-display-button', 'admin-unchanged', '403-recovery', '404', 'empty', '401-login', 'no-overflow'] })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
