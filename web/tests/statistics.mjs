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
  for (const width of [1440, 768, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], unexpected = [], requests = []
    page.on('pageerror', error => errors.push(error.message))
    let mode = 'observed'
    const generated_at = Math.floor(Date.now() / 1000), today = Math.floor(generated_at / 86400) * 86400
    const data = (days, business) => {
      const from = today - (days - 1) * 86400, empty = mode === 'empty'
      const points = Array.from({ length: days }, (_, index) => {
        const missing = empty || index === 1
        return { day: from + index * 86400, uploaded: missing ? null : String(index * 1073741824), downloaded: missing ? null : String(index * 536870912), total: missing ? null : String(index * 1610612736), incomplete: index === 2, sampled_servers: missing ? 0 : 2 }
      })
      const rows = empty ? [] : Array.from({ length: 8 }, (_, index) => ({ id: index + 1, name: `${business ? '代理' : '服务器'} ${index + 1} · 很长的测试名称用于检查手机布局`, uploaded: '2147483648', downloaded: '1073741824', total: '3221225472', deleted: business && index === 0, incomplete: index === 1 }))
      const traffic = { uploaded: empty ? null : '10737418240', downloaded: empty ? null : '5368709120', total: empty ? null : '16106127360', sampled_servers: empty ? 0 : 8, incomplete: !empty, last_sample_at: empty ? null : generated_at * 1000, recorded_users: empty ? 0 : 12, recorded_nodes: empty ? 0 : 8, last_record_at: empty ? null : generated_at }
      return business ? { generated_at, from, days, nodes: 8, users: 12, traffic, points, by_user: rows, by_node: rows } : { generated_at, from, days, servers: { total: 9, online: 5, offline: 3, pending: 1, hidden: 2 }, traffic, points, by_server: rows }
    }
    await page.route('**/api/**', async route => {
      const url = new URL(route.request().url()), path = url.pathname
      requests.push(path + url.search)
      if (path === '/api/dashboard/access') return route.fulfill({ json: { authenticated: true, public_dashboard: true } })
      if (path === '/api/statistics' && mode === 'failure') return route.fulfill({ status: 500, json: { error: '测试：暂时无法读取网卡统计' } })
      if (path === '/api/statistics' || path === '/api/plugins/sing-box/statistics') return route.fulfill({ json: data(Number(url.searchParams.get('days')), path.includes('sing-box')) })
      unexpected.push(path); return route.fulfill({ status: 500, json: { error: 'Unexpected request' } })
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/statistics`)
    await page.getByRole('heading', { name: '统计仪表盘', exact: true }).waitFor()
    await page.getByRole('heading', { name: '代理流量趋势', exact: true }).waitFor()
    const chart = page.getByRole('region', { name: '网卡流量趋势', exact: true })
    assert.equal(await chart.locator('.statistics-chart-bar').count(), 7)
    assert.equal(await chart.locator('[data-missing="true"]').count(), 1)
    await chart.locator('.statistics-chart-bar').first().focus()
    await page.keyboard.press('ArrowRight')
    assert.match(await chart.locator('.statistics-chart-selection').innerText(), /暂无数据/)
    await page.keyboard.press('End')
    assert.equal(await chart.locator('.statistics-chart-bar').last().getAttribute('aria-pressed'), 'true')
    const ranking = page.getByRole('region', { name: '服务器流量排行', exact: true })
    assert.equal(await ranking.getByRole('link').count(), 8)
    assert.equal(await ranking.getByRole('link').first().getAttribute('href'), '#/servers/1')
    assert.match(await page.getByRole('region', { name: '代理用户流量排行', exact: true }).innerText(), /已删除/)
    assert.match(await page.locator('.statistics-scope').first().innerText(), /不含账单周期流量矫正/)
    if (width <= 600) assert.equal(await page.locator('.statistics-traffic-totals').evaluate(element => getComputedStyle(element).gridTemplateColumns.split(' ').length), 1)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false)
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `statistics-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '近 30 天', exact: true }).click()
    await page.waitForFunction(() => document.querySelectorAll('.statistics-chart-bars')[0]?.children.length === 30)
    assert.equal(await chart.locator('.statistics-chart-bar').count(), 30)
    assert.ok(requests.includes('/api/statistics?days=30'))
    assert.ok(requests.includes('/api/plugins/sing-box/statistics?days=30'))
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false)
    mode = 'failure'
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByRole('alert').filter({ hasText: '暂时无法读取' }).waitFor()
    assert.match(await page.locator('.statistics-status-line').innerText(), /上次成功读取/)
    assert.equal(await chart.locator('.statistics-chart-bar').count(), 30)
    mode = 'empty'
    await page.getByRole('button', { name: '重试', exact: true }).click()
    await chart.getByText('此时间段暂无流量记录，等待数据上报。', { exact: true }).waitFor()
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByRole('region', { name: '代理流量趋势', exact: true }).getByText('此时间段暂无流量记录，等待数据上报。', { exact: true }).waitFor()
    assert.equal(await page.locator('.statistics-chart-bar').count(), 0)
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
    results.push({ width, charts: 'passed', ranges: 'passed', missing: 'passed', partialFailure: 'passed' })
    await context.close()
  }
  const context = await browser.newContext(), page = await context.newPage(), privateRequests = []
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/dashboard/access') return route.fulfill({ json: { authenticated: false, public_dashboard: true } })
    privateRequests.push(path); return route.fulfill({ status: 401, json: { error: '请先登录' } })
  })
  await installControlCenterFixtures(page)
  await page.goto(`${origin}/#/statistics`)
  await page.getByRole('heading', { name: '欢迎回来' }).waitFor()
  assert.deepEqual(privateRequests, [])
  assert.equal(await page.locator('.statistics-page').count(), 0)
  await context.close()
  console.log(JSON.stringify({ results, publicAccess: 'login required' }))
} finally { await browser.close(); server.close() }
