import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Exercise the shipped bundle with controlled API responses; backend behavior is
// verified separately by the PostgreSQL/WebSocket/HTTP integration tests.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } })
  const errors = []
  page.on('pageerror', error => errors.push(error.message))
  const now = Math.floor(Date.now() / 1000)
  const id = '00000000-0000-0000-0000-000000000019'
  const report = '已完成的诊断报告片段'
  const record = { id, status: 'running', agent_completed: false, cancel_requested_at: null, cancel_error: null, job: { plugin: 'nodequality', options: { ip_version: 'ipv4', network_mode: 'low', upload_report: 'false' } }, report: { text: report }, error: null, created_at: now, updated_at: now, expires_at: now + 1800 }
  let supported = true, cancelPosts = 0
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    let value
    if (path === '/api/dashboard/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (path === '/api/me') value = { authenticated: true }
    else if (path === '/api/servers/1') value = { id: 1, name: '取消验收夹具', online: true, device_public_key: 'test-only-key', static_info: {}, latest_metrics: {}, last_seen: now, manifest_rev: 0, capabilities: [] }
    else if (path === '/api/plugins/sing-box/servers/1') value = { id: 1, name: '取消验收夹具', enabled: true, source: 'administrator', read_only: false, online: true, agent_supported: true }
    else if (path === '/api/plugins/sing-box/servers/1/deployments') value = { status: null, history: [] }
    else if (path === '/api/servers/1/agent-settings') value = { sample_interval_secs: 1, upload_interval_secs: 5, discover_public_ips: false, auto_update: false }
    else if (path === '/api/servers/1/telemetry-settings') value = { persist_interval_secs: 60 }
    else if (path === '/api/servers/1/node-quality/reports') value = { plugin_ready: true, plugin_reason: null, full_ready: false, daily_ready: true, cancel_supported: supported, reports: [record] }
    else if (path === `/api/servers/1/diagnostics/${id}/cancel`) {
      assert.equal(route.request().method(), 'POST')
      cancelPosts++
      record.status = 'cancel_requested'; record.cancel_requested_at = now
      await route.fulfill({ status: 202, json: record }); return
    } else if (['/api/plugins/sing-box/nodes', '/api/servers/1/probes', '/api/servers/1/probe-results', '/api/servers/1/commands'].includes(path)) value = []
    else { throw new Error(`Unexpected API request: ${path}`) }
    await route.fulfill({ json: value })
  })
  const origin = `http://127.0.0.1:${server.address().port}`
  await installControlCenterFixtures(page)
  await page.goto(`${origin}/#/servers/1/node-quality`)
  record.status = 'cleaning'
  record.error = '原执行结果：测试超时；清理原因：设备仍有活动进程或挂载'
  await page.reload()
  await page.getByText('等待设备确认清理', { exact: true }).waitFor()
  await page.getByText(record.error, { exact: true }).waitFor()
  assert.equal(await page.getByText('报告已完成', { exact: true }).count(), 0)
  assert.equal(await page.getByRole('button', { name: '日常检查', exact: true }).isDisabled(), true)
  if (!(await page.locator('details.quality-report-text').evaluate(element => element.open))) await page.getByText('查看报告文本', { exact: true }).click()
  assert.equal(await page.getByText(report, { exact: true }).isVisible(), true)
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true)
  await page.setViewportSize({ width: 1280, height: 900 })
  await page.getByRole('button', { name: '请求取消测试', exact: true }).click()
  await page.getByText('等待设备确认取消', { exact: true }).waitFor()
  assert.equal(cancelPosts, 1)
  assert.equal(await page.getByText('设备已确认取消', { exact: true }).count(), 0)
  if (!(await page.locator('details.quality-report-text').evaluate(element => element.open))) await page.getByText('查看报告文本', { exact: true }).click()
  assert.equal(await page.getByText(report, { exact: true }).isVisible(), true)
  record.cancel_error = '设备仍有活动进程或挂载，将继续重试'
  await page.reload()
  await page.getByText(record.cancel_error, { exact: true }).waitFor()
  assert.equal(await page.getByText('等待设备确认取消', { exact: true }).isVisible(), true)
  record.status = 'cancelled'; record.agent_completed = true; record.cancel_error = null; record.error = null
  // The existing page must pick up confirmation through its normal poll.
  await page.getByText('设备已确认取消', { exact: true }).waitFor({ timeout: 10_000 })
  if (!(await page.locator('details.quality-report-text').evaluate(element => element.open))) await page.getByText('查看报告文本', { exact: true }).click()
  assert.equal(await page.getByText(report, { exact: true }).isVisible(), true)
  record.status = 'running'; record.agent_completed = false; supported = false
  await page.reload()
  await page.getByText('此 Agent 或服务后端不支持确认式取消，请先升级。', { exact: true }).waitFor()
  assert.equal(await page.getByRole('button', { name: '请求取消测试', exact: true }).isDisabled(), true)
  assert.equal(cancelPosts, 1)
  record.status = 'cleaning'; record.error = '设备重启后继续等待清理'; supported = true
  await page.reload()
  await page.getByText('等待设备确认清理', { exact: true }).waitFor()
  record.status = 'succeeded'; record.agent_completed = true; record.error = null
  await page.getByText('报告已完成', { exact: true }).waitFor({ timeout: 10_000 })
  assert.equal(await page.getByRole('button', { name: '请求取消测试', exact: true }).count(), 0)
  assert.equal(await page.getByRole('button', { name: '日常检查', exact: true }).isEnabled(), true)
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true)
  assert.deepEqual(errors, [])
  console.log('PASS: bundled desktop/mobile UI, automatic cleanup pending/restart/final, cancellation pending/failed/confirmed/legacy states, reports preserved, no premature terminal state')
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
