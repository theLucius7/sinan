import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Use the committed bundle and loopback-only fixtures. Rust tests verify the
// creation/dispatch policies; this exercises their visible readiness contract.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
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
  const reason = '完整验机已暂停：离线受控工具链尚未就绪，旧工具链仍会下载在线代码、上传内层报告或修改宿主 swap。'
  const id = '00000000-0000-0000-0000-000000000028'
  const old = { id, status: 'failed', agent_completed: false, cancel_requested_at: null, cancel_error: null,
    job: { id, plugin: 'nodequality', options: { ip_version: 'both', network_mode: 'low', upload_report: 'false' } }, cleanup_pending: true,
    report: null, error: reason, created_at: now, updated_at: now, expires_at: now + 1800,
    expected_sections: ['hardware_quality'], report_completeness: 'partial',
    sections: [{ name: 'hardware_quality', text: '旧完整任务已保存的硬件章节', complete: true, revision: 1, collected_at: now }] }
  let records = [], dailyPosts = 0, fullPosts = 0, cancelPosts = 0, refreshPosts = 0
  let ready = true
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.replace('/api/dashboard/', '/api/')
    let value
    if (path === '/api/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (path === '/api/me') value = { authenticated: true }
    else if (path === '/api/servers/1') value = { id: 1, name: '工具链门禁夹具', online: true, device_public_key: 'TEST_ONLY', static_info: {}, latest_metrics: {}, last_seen: now, manifest_rev: 0, capabilities: [] }
    else if (path === '/api/servers/1/deployments') value = { status: null, history: [] }
    else if (path === '/api/servers/1/agent-settings') value = { sample_interval_secs: 1, upload_interval_secs: 3, discover_public_ips: false, auto_update: false }
    else if (path === '/api/servers/1/telemetry-settings') value = { persist_interval_secs: 60 }
    else if (path === '/api/servers/1/node-quality/reports' && request.method() === 'GET') value = { plugin_ready: ready, plugin_reason: ready ? null : 'Agent 当前离线', full_ready: false, full_reason: reason, cancel_supported: true, reports: records, proxy_activity: { state: 'unknown', reason: '代理流量状态未知', checked_at: now, last_positive_at: null } }
    else if (path === '/api/servers/1/node-quality/reports') {
      const body = request.postDataJSON()
      if (body.mode !== 'daily') { fullPosts++; await route.fulfill({ status: 409, json: { error: reason } }); return }
      dailyPosts++
      assert.equal(body.network_mode, 'low'); assert.equal(body.upload_report, false)
      value = { ...old, status: 'queued', error: null, job: { plugin: 'nodequality', options: { ...body } }, sections: [], expected_sections: ['net_quality', 'environment'] }
      records = [value]
    } else if (path === '/api/servers/1/ip-quality/refresh') {
      refreshPosts++; await route.fulfill({ status: 403, json: { error: 'IP 查询源返回 403；历史结果保留' } }); return
    } else if (path === `/api/servers/1/diagnostics/${id}/cancel`) {
      cancelPosts++; old.status = 'cancel_requested'; old.cancel_requested_at = now
      await route.fulfill({ status: 202, json: old }); return
    } else if (['/api/nodes', '/api/servers/1/probes', '/api/servers/1/probe-results', '/api/servers/1/commands'].includes(path)) value = []
    else throw new Error(`Unexpected API request: ${path}`)
    await route.fulfill({ json: value })
  })
  await page.goto(`http://127.0.0.1:${server.address().port}/#/servers/1/node-quality`)
  await page.getByText(reason, { exact: true }).waitFor()
  const full = page.getByRole('button', { name: '完整验机', exact: true })
  const daily = page.getByRole('button', { name: '日常检查', exact: true })
  assert.equal(await full.isDisabled(), true)
  assert.equal(await daily.isEnabled(), true)
  assert.equal(await page.getByRole('checkbox').first().isDisabled(), true)
  await daily.click()
  await page.getByText('IP 查询源返回 403；历史结果保留', { exact: true }).waitFor()
  // The independent IP response can arrive before the report read-back.
  await page.getByText('任务已保存，等待在线 Agent 领取。通常会在数秒内开始。', { exact: true }).waitFor()
  assert.equal(dailyPosts, 1); assert.equal(refreshPosts, 1); assert.equal(fullPosts, 0)
  assert.equal(await daily.isDisabled(), true)
  records = [old]
  await page.reload()
  await page.getByText('历史顶层上传设置关闭', { exact: false }).waitFor()
  await page.locator('summary').filter({ hasText: '硬件质量' }).click()
  assert.equal(await page.getByText('旧完整任务已保存的硬件章节', { exact: true }).isVisible(), true)
  await page.getByRole('button', { name: '请求取消测试', exact: true }).click()
  await page.getByText('等待设备确认取消', { exact: true }).waitFor()
  assert.equal(cancelPosts, 1)
  assert.equal(await page.getByRole('button', { name: '日常检查', exact: true }).isDisabled(), true)
  old.status = 'cancelled'; old.agent_completed = true; old.cleanup_pending = false
  await page.reload()
  await page.getByText('设备已确认取消', { exact: true }).waitFor()
  assert.equal(await daily.isEnabled(), true)
  ready = false
  await page.reload()
  await page.getByText('Agent 当前离线', { exact: true }).waitFor()
  assert.equal(await daily.isDisabled(), true)
  assert.equal(await full.isDisabled(), true)
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true)
  assert.deepEqual(errors, [])
  console.log('PASS: full gate/reason, daily + 403, legacy chapters/cancel, offline, desktop/mobile, zero full POSTs')
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
