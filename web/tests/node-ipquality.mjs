// Render the actual built frontend; all API responses and third-party results are fixtures.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const now = Math.floor(Date.now() / 1000), ip = '2001:db8::2', nic = '192.0.2.1'
const id = '00000000-0000-4000-8000-000000000051'
const version = '87397e2c3196ec796f5477c83343c2354df601ea-node-r1'
const failed = { database: 'Netflix', label: 'Netflix', provider: 'ipquality-node/netflix-public-pages', target_ip: ip,
  status: 'failed', fields: [{ label: '状态', kind: 'text', value: '可用' }, { label: '地区', kind: 'country_code', value: 'ZZ' }],
  error: '来源拒绝请求（HTTP 403），本次状态未知', error_kind: 'http_403', http_status: 403,
  attempted_at: now, elapsed_ms: 3, last_attempt_at: now, last_success_at: now - 60,
  fresh_until: now + 3600, last_error: { kind: 'http_403', message: '来源拒绝请求（HTTP 403），本次状态未知', http_status: 403, attempted_at: now, elapsed_ms: 3 }, historical: true, available: true }
const record = { id, status: 'running', agent_completed: false, cancel_requested_at: null, cancel_error: null,
  job: { plugin: 'ipquality', version, options: { ip_version: '6' } }, report: null, error: null,
  created_at: now, updated_at: now, expires_at: now + 600, expected_sections: ['ipquality_result', 'environment'], report_completeness: 'partial',
  sections: [{ name: 'ipquality_result', revision: 2, complete: false, collected_at: now,
    text: JSON.stringify({ schema: 1, plugin: 'ipquality', version, job_id: id, ip_version: '6', started_at: now, finished_at: null, egress_ip: ip, upstream: null,
      attempts: [{ seq: 1, provider: 'netflix-public-pages', dataset: 'Netflix', target_ip: ip, url: 'https://www.netflix.com/title/81280792', status: 'failed', attempted_at: now, elapsed_ms: 3, http_status: 403, curl_exit: 0, response_bytes: 1, error_kind: 'http_403', error_message: '来源拒绝请求' }] }) }] }
let view, readFailure = false
const writes = []
function reset() {
  view = { server_id: 1, ip_addresses: [nic], public_ip_addresses: [nic], private_ip_addresses: [], providers: [],
    quality: [{ ip, provider: failed.provider, checked_at: now, expires_at: now + 3600, status: 'failed', databases: [structuredClone(failed)] }],
    node_quality: { ready: true, reason: null, version, cancel_supported: true, reports: [], observed_egress_ips: [ip], current_egress_ips: [ip] } }
  readFailure = false
}
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1440, 390]) {
    reset()
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    const errors = [], external = []
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url())
      if (url.origin !== origin) { external.push(url.href); return route.abort() }
      if (!url.pathname.startsWith('/api/')) return route.continue()
      const path = url.pathname
      let value = []
      if (path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (path === '/api/me') value = { authenticated: true }
      else if (path === '/api/servers/1') value = { id: 1, name: '节点出口自查夹具', online: true, static_info: { os: 'linux', arch: 'amd64' }, latest_metrics: {}, capabilities: [], manifest_rev: 0 }
      else if (path === '/api/servers/1/ip-quality' && readFailure) return route.fulfill({ status: 503, json: { error: '测试夹具：状态读取失败' } })
      else if (path === '/api/servers/1/ip-quality') value = view
      else if (path === '/api/servers/1/diagnostics/ipquality') {
        const body = request.postDataJSON()
        writes.push({ path, body })
        assert.deepEqual(body, { ip_version: '6' })
        view.node_quality = { ...view.node_quality, ready: false, reason: '同机已有诊断任务，等待设备完成或清理确认', reports: [structuredClone(record)] }
        value = record
      } else if (path === `/api/servers/1/diagnostics/${id}/cancel`) {
        writes.push({ path })
        view.node_quality.reports[0].status = 'cancel_requested'
        value = null
      }
      return route.fulfill({ json: value })
    })
    await page.goto(`${origin}/#/servers/1/ip-info`)
    await page.getByRole('heading', { name: '节点出口自查', exact: true }).waitFor()
    const results = page.locator('[aria-label="节点观察出口"]')
    assert.match(await results.innerText(), /最近查询出口/)
    const chapter = results.locator('details.quality-database')
    await chapter.locator('summary').click()
    assert.match(await chapter.innerText(), /历史结果/)
    assert.match(await chapter.innerText(), /HTTP 403/)
    assert.equal(await chapter.locator('dd').first().innerText(), '可用')
    assert.match(await results.innerText(), /当前没有有效成功结果/)
    assert.equal(await page.locator('[aria-label="公网地址"]').getByText(nic, { exact: true }).count(), 1)
    await page.getByLabel('出口 IP 版本', { exact: true }).selectOption('6')
    await page.getByRole('button', { name: '运行节点出口自查', exact: true }).click()
    await page.getByText('设备正在查询', { exact: true }).waitFor()
    await page.getByRole('button', { name: '运行节点出口自查', exact: true }).isDisabled().then(value => assert(value))
    await page.getByRole('button', { name: '请求取消节点自查', exact: true }).click()
    await page.getByText('等待设备确认取消', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '请求取消节点自查', exact: true }).count(), 0)
    assert.match(await page.locator('.node-ip-quality').innerText(), /部分结果/)
    view.node_quality.ready = false
    view.node_quality.reason = '匹配的签名制品尚未准备'
    view.node_quality.reports = []
    await page.reload()
    await page.getByText('匹配的签名制品尚未准备', { exact: true }).waitFor()
    assert(await page.getByRole('button', { name: '运行节点出口自查', exact: true }).isDisabled())
    view.node_quality.ready = true
    view.node_quality.reason = null
    readFailure = true
    await page.getByRole('button', { name: '重试', exact: true }).count().then(async count => {
      if (count) await page.getByRole('button', { name: '重试', exact: true }).click()
      else await page.waitForResponse(response => new URL(response.url()).pathname === '/api/servers/1/ip-quality' && response.status() === 503)
    })
    await page.getByText('测试夹具：状态读取失败', { exact: true }).waitFor()
    assert(await page.getByRole('button', { name: '运行节点出口自查', exact: true }).isDisabled())
    if (process.env.SINAN_SCREENSHOT_DIR) {
      await mkdir(process.env.SINAN_SCREENSHOT_DIR, { recursive: true })
      await page.screenshot({ path: resolve(process.env.SINAN_SCREENSHOT_DIR, `node-ipquality-${width}.png`), fullPage: true })
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1), false)
    assert.deepEqual(errors, [])
    assert.deepEqual(external, [])
    await page.close()
  }
  assert.equal(writes.filter(value => value.path.endsWith('/ipquality')).length, 2)
  assert.equal(writes.filter(value => value.path.endsWith('/cancel')).length, 2)
  console.log(JSON.stringify({ passed: true, widths: [1440, 390], cases: ['node-egress-independent-from-nic', 'failed-provider-preserves-history', 'single-family-create', 'duplicate-disabled', 'confirmed-cancel-pending', 'partial-report', 'missing-signed-artifact', 'stale-read-guard'], requests: writes.length }))
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
