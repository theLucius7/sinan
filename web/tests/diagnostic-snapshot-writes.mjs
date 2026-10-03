import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { extname, resolve, sep } from 'node:path'

// TEST_ONLY: actual built UI against owned loopback APIs. This does not certify
// native process cleanup, capabilities, providers, or diagnostic execution.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url)), base = '/api/servers/1'
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname, file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`, totals = { scenarios: 0, blocked: 0, recovered: 0, requests: 0, external: [], unexpected: [], errors: [] }
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const wait = async (condition, description) => { const deadline = Date.now() + 12000; while (!await condition()) { assert(Date.now() < deadline, description); await new Promise(resolve => setTimeout(resolve, 20)) } }
const forceClick = button => button.evaluate(element => {
  const disabled = element.disabled
  element.disabled = false
  try { element.click() } finally { element.disabled = disabled }
})
try {
  for (const width of [1440, 390]) for (const plugin of ['nodequality', 'tcpquality']) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(12000)
    page.on('pageerror', error => totals.errors.push(error.message))
    const readPath = plugin === 'nodequality' ? `${base}/node-quality/reports` : `${base}/diagnostics`
    const createPath = plugin === 'nodequality' ? readPath : `${base}/diagnostics/tcpquality`
    const targetPath = '/api/plugins/tcpquality/servers/1/targets'
    const now = Math.floor(Date.now() / 1000), id = 'a0000000-0000-0000-0000-000000000145'
    const target = { id: '00000000-0000-0000-0000-000000000146', name: 'TEST_ONLY 回环目标', target: '127.0.0.1', port: 443, carrier: '', region: 'east_asia' }
    const record = { id, status: 'succeeded', agent_completed: true, cancel_requested_at: null, cancel_error: null, job: { id, plugin, version: 'TEST_ONLY', options: { mode: 'daily', ip_version: plugin === 'nodequality' ? 'ipv6' : '6', network_mode: 'low', count: '4', concurrency: '1' }, ...(plugin === 'tcpquality' ? { tcpquality: { region: 'configured', targets: [target] } } : {}) }, report: { text: 'TEST_ONLY 已保存报告' }, error: null, created_at: now, updated_at: now, expires_at: now + 300 }
    const reports = [record], writes = [], pending = [], failures = new Set(), gates = new Map()
    let ready = true, cancelSupported = true
    const hold = path => { let release; const promise = new Promise(resolve => { release = resolve }); const gate = { promise, release, reached: 0 }; gates.set(path, gate); return gate }
    await page.route('**/*', route => {
      const task = (async () => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
        if (url.origin !== origin) { totals.external.push(url.href); return route.abort() }
        if (!path.startsWith('/api/')) return route.continue()
        ++totals.requests
        if (method === 'GET') {
          const gate = gates.get(path); if (gate) { ++gate.reached; await gate.promise }
          if (failures.has(path)) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 诊断刷新失败' } })
        }
        let value
        if (method === 'POST' && path === createPath) {
          writes.push({ path, body: request.postDataJSON() }); record.status = 'queued'; record.agent_completed = false; value = record
        } else if (method === 'POST' && path === `${base}/diagnostics/${id}/cancel`) {
          writes.push({ path }); record.status = 'cancel_requested'; record.cancel_requested_at = now; value = record
        } else if (method === 'POST' && plugin === 'nodequality' && path === `${base}/ip-quality/refresh`) value = []
        else if (method !== 'GET') { totals.unexpected.push(`${method} ${path}`); return route.fulfill({ status: 404, json: {} }) }
        else if (['/api/me', '/api/dashboard/access'].includes(path)) value = { authenticated: true, public_dashboard: false }
        else if (path === base) value = { id: 1, name: 'TEST_ONLY 诊断快照设备', online: true, static_info: {}, latest_metrics: {}, capabilities: [] }
        else if (path === readPath) {
          const currentReports = reports.map(record => ({ ...record, cleanup_pending: record.agent_completed === false && Object.prototype.hasOwnProperty.call(record.job, 'id') }))
          value = plugin === 'nodequality'
            ? { plugin_ready: ready, plugin_reason: ready ? null : 'TEST_ONLY 缺少完成确认能力', full_ready: false, full_reason: 'TEST_ONLY 完整验机保持关闭', cancel_supported: cancelSupported, reports: currentReports }
            : { plugins: [{ plugin, ready, reason: ready ? null : 'TEST_ONLY 缺少完成确认能力' }], cancel_supported: cancelSupported, reports: currentReports }
        }
        else if (path === targetPath && plugin === 'tcpquality') value = [target]
        else { totals.unexpected.push(`${method} ${path}`); return route.fulfill({ status: 404, json: {} }) }
        return route.fulfill({ json: value })
      })()
      pending.push(task); return task
    })
    const start = page.getByRole('button', { name: plugin === 'nodequality' ? '日常检查' : '开始 TCP 诊断', exact: true })
    const cancel = page.getByRole('button', { name: '请求取消测试', exact: true })
    const version = plugin === 'nodequality'
      ? page.getByRole('combobox', { name: /^测试 IP 版本/ })
      : page.getByLabel('IP 版本', { exact: true })
    const refreshFailed = async () => {
      const observed = page.waitForResponse(response => new URL(response.url()).pathname === readPath && response.request().method() === 'GET')
      await page.getByRole('button', { name: '重试', exact: true }).first().click(); await observed
    }
    const poll = async (condition = () => cancel.count().then(count => count > 0 ? cancel.isEnabled() : start.isEnabled())) => {
      const observed = page.waitForResponse(response => new URL(response.url()).pathname === readPath && response.request().method() === 'GET')
      const gate = hold(readPath); await wait(() => gate.reached > 0, 'The actual diagnostic poll starts')
      gate.release(); gates.delete(readPath)
      await observed
      await wait(condition, 'Successful diagnostic snapshot arrives')
    }
    const block = async (path, button) => {
      const baseline = writes.length, gate = hold(path)
      await wait(() => gate.reached > 0, 'The actual held GET starts')
      await forceClick(button); assert.equal(writes.length, baseline, 'Pending current snapshot sends zero writes'); ++totals.blocked
      failures.add(path); gate.release(); gates.delete(path)
      await page.getByText('TEST_ONLY 诊断刷新失败', { exact: true }).first().waitFor()
      await forceClick(button); assert.equal(writes.length, baseline, 'Failed snapshot sends zero writes'); ++totals.blocked
      assert.equal(await version.inputValue(), plugin === 'nodequality' ? 'ipv6' : '6')
      assert.equal(await page.locator('details.quality-report-text pre').textContent(), 'TEST_ONLY 已保存报告')
      failures.delete(path); await refreshFailed()
      await wait(() => button.isEnabled(), 'A successful snapshot restores the original action')
    }
    try {
      await page.goto(`${origin}/#/servers/1/${plugin === 'nodequality' ? 'node-quality' : 'tcp-quality'}`)
      await wait(() => start.isEnabled(), 'Initial diagnostic state is current')
      await version.selectOption(plugin === 'nodequality' ? 'ipv6' : '6')
      await block(readPath, start)
      if (plugin === 'tcpquality') await block(targetPath, start)
      ready = false; await page.reload(); await page.getByText('TEST_ONLY 缺少完成确认能力', { exact: true }).waitFor()
      assert.equal(await start.isDisabled(), true); await forceClick(start); assert.equal(writes.length, 0); ++totals.blocked
      ready = true; await page.reload(); await wait(() => start.isEnabled(), 'Current capability restored')
      await version.selectOption(plugin === 'nodequality' ? 'ipv6' : '6')
      await start.click(); await wait(() => writes.length === 1, 'Exactly one authorized create'); ++totals.recovered
      assert.equal(writes[0].body.ip_version, plugin === 'nodequality' ? 'ipv6' : '6')
      await wait(() => cancel.isEnabled(), 'Queued task can be cancelled')
      await block(readPath, cancel)
      record.status = 'failed'; record.error = 'TEST_ONLY 面板截止，尚无清理收据'; ready = false
      await poll()
      await page.getByText('已有执行结果尚未取得设备停止与清理确认，仍占用诊断位置。报告保留，可请求取消；确认清理完成前不能开始下一项诊断。', { exact: true }).waitFor()
      assert.equal(await start.isDisabled(), true); await forceClick(start); assert.equal(writes.length, 1); ++totals.blocked
      // Losing new-task capability must not prevent confirmed cancellation.
      assert.equal(await cancel.isEnabled(), true)
      ready = true; await poll()
      assert.equal(await start.isDisabled(), true); await forceClick(start); assert.equal(writes.length, 1); ++totals.blocked
      for (const identity of [null, id.toUpperCase(), 'TEST_ONLY malformed task identity']) {
        record.job.id = identity; await poll()
        assert.equal(await start.isDisabled(), true); await forceClick(start); assert.equal(writes.length, 1); ++totals.blocked
      }
      record.job.id = id
      await cancel.evaluate(element => {
        const key = Object.keys(element).find(key => key.startsWith('__reactProps$'))
        assertFunction(element[key]?.onClick)
        function assertFunction(value) { if (typeof value !== 'function') throw new Error('TEST_ONLY actual cancellation handler missing') }
        window.TEST_ONLY_cancel = element[key].onClick
      })
      reports.splice(0, 1); await poll(() => page.locator('article.quality-report').count().then(count => count === 0))
      await page.evaluate(() => window.TEST_ONLY_cancel())
      assert.equal(writes.length, 1, 'A removed entity never receives a cancellation POST'); ++totals.blocked
      reports.push(record); await poll()
      cancelSupported = false; await page.reload(); await wait(() => cancel.isDisabled(), 'Cancellation capability is reread')
      await forceClick(cancel); assert.equal(writes.length, 1); ++totals.blocked
      cancelSupported = true; await page.reload(); await wait(() => cancel.isEnabled(), 'Current cancellation capability restored')
      await cancel.click(); await wait(() => writes.length === 2, 'Exactly one cancellation request'); ++totals.recovered
      await page.getByText('等待设备确认取消', { exact: true }).first().waitFor()
      assert.equal(await start.isDisabled(), true)
      record.status = 'cancelled'; record.agent_completed = true; record.error = null; ready = true
      await poll(); await page.getByText('设备已确认取消', { exact: true }).waitFor()
      await wait(() => start.isEnabled(), 'Device cleanup confirmation releases the UI barrier')
      // Old text-only history lacks a task identity and must remain readable.
      record.status = 'failed'; record.agent_completed = false; delete record.job.id
      await poll(); await wait(() => start.isEnabled(), 'Text-only history remains readable without occupying diagnostics')
      if (process.env.SINAN_UI_SCREENSHOT_DIR) { await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true }); await page.screenshot({ path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `diagnostic-snapshot-${plugin}-${width}.png`), fullPage: true }) }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      ++totals.scenarios
    } finally { for (const gate of gates.values()) gate.release(); await Promise.all(pending); await page.close() }
  }
  assert.deepEqual(totals.external, []); assert.deepEqual(totals.unexpected, []); assert.deepEqual(totals.errors, [])
  console.log(JSON.stringify({ result: 'PASS', ...totals }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
