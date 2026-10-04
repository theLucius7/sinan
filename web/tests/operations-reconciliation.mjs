import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Consume the final shipped assets. Every API and side effect is an isolated
// fixture; successful UI review does not certify a real device cleanup.
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
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []
try {
  for (const width of [1280, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 950 }, timezoneId: 'UTC', serviceWorkers: 'block' })
    const page = await context.newPage()
    page.setDefaultTimeout(10000)
    const errors = [], external = [], requests = [], writes = []
    context.on('page', current => current.on('pageerror', error => errors.push(error.message)))
    page.on('pageerror', error => errors.push(error.message))
    context.on('request', request => { if (new URL(request.url()).origin !== origin) external.push(request.url()) })
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin !== origin) return route.abort()
      return route.continue()
    })
    const now = Math.floor(Date.now() / 1000)
    const job = '11111111-1111-4111-8111-111111111111'
    const original = '22222222-2222-4222-8222-222222222222'
    const oldInspection = '33333333-3333-4333-8333-333333333333'
    const newInspection = '44444444-4444-4444-8444-444444444444'
    const unknown = { succeeded: false, completed_at: now - 30, outcome: 'unknown', error: 'TEST_ONLY original unconfirmed device outcome' }
    const originalBytes = JSON.stringify(unknown)
    const detail = { job: { id: job, name: 'TEST_ONLY 未确认设备操作', status: 'uncertain', targets: [7], requested_by: 1,
      created_at: now - 40, updated_at: now - 30, failure_reason: 'TEST_ONLY 原结果未知，等待实际清理核对' },
      steps: [{ server_id: 7, position: 0, batch: 0, state: 'uncertain', execution_state: 'uncertain',
        execution_result: unknown, result: unknown, running_cancel_supported: false, fleet_operation_id: original, runtime_operation_id: null }],
      panel_steps: [], history: [{ id: 1, action: 'uncertain', recorded_at: now - 30, details: { original_operation: original, outcome: 'unknown' } }] }
    const actor = { id: 1, role: 'operator', display_name: 'TEST_ONLY 限定运维管理员', all_servers: false,
      capabilities: ['operations:read', 'operations:write', 'servers:read'], token_capabilities: null, token_servers: null }
    let inspections = 0, oldReads = 0, reauth = 0
    let heldOldRoute, signalHeld
    const oldHeld = new Promise(resolve => { signalHeld = resolve })
    let newReceipt = { id: newInspection, server_id: 7, reconciliation_of: original, status: 'queued', result: null }
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
      assert.equal(url.origin, origin)
      requests.push({ method, path })
      let value
      if (method === 'GET' && path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (method === 'GET' && path === '/api/control-center/me') value = actor
      else if (method === 'GET' && path.startsWith('/api/control-center/preferences/')) value = { value: path.endsWith('/recent') || path.endsWith('/favorite') ? [] : null, revision: 0, updated_at: 0 }
      else if (method === 'GET' && path === '/api/servers') value = [{ id: 7, name: 'TEST_ONLY 核对服务器', online: true, capabilities: ['fleet:operations:v1'], static_info: {}, latest_metrics: {} }]
      else if (method === 'GET' && path === '/api/operations/jobs') value = [detail.job]
      else if (method === 'GET' && path === `/api/operations/jobs/${job}`) value = detail
      else if (method === 'GET' && ['/api/operations/templates', '/api/operations/schedules', '/api/operations/maintenance', '/api/operations/remediation', '/api/operations/incidents', '/api/operations/cancellation-reminders'].includes(path)) value = []
      else if (method === 'POST' && path === '/api/control-center/reauth') {
        const body = request.postDataJSON(); reauth++
        writes.push({ path, body })
        assert.deepEqual(Object.keys(body).sort(), ['password', 'totp_code'])
        assert.equal(body.totp_code, null)
        if (body.password !== 'TEST_ONLY password') return route.fulfill({ status: 403, json: { error: 'TEST_ONLY 身份验证失败' } })
        value = { verified: true, expires_at: now + 300 }
      } else if (method === 'POST' && path === `/api/operations/jobs/${job}/inspection`) {
        const body = request.postDataJSON(); writes.push({ path, body })
        assert.deepEqual(body, { server_id: 7, operation_id: original })
        assert.ok(inspections < 2)
        inspections++
        value = { id: inspections === 1 ? oldInspection : newInspection, status: 'queued', reconciliation_of: original, read_only: true }
      } else if (method === 'GET' && path === `/api/fleet/operations/${oldInspection}`) {
        oldReads++
        if (oldReads === 1) { heldOldRoute = route; signalHeld(); return }
        value = { id: oldInspection, server_id: 7, reconciliation_of: original, status: 'queued', result: null }
      } else if (method === 'GET' && path === `/api/fleet/operations/${newInspection}`) value = newReceipt
      else if (method === 'POST' && path === `/api/operations/jobs/${job}/reconcile`) {
        const body = request.postDataJSON(); writes.push({ path, body })
        assert.equal(writes.filter(write => write.path.endsWith('/reconcile')).length, 1)
        assert.equal(body.server_id, 7); assert.equal(body.operation_id, original); assert.equal(body.inspection_id, newInspection)
        assert.equal(body.process_stopped, true); assert.equal(body.cleanup_confirmed, true)
        assert.ok(Number.isInteger(body.observed_at) && body.observed_at <= Math.floor(Date.now() / 1000) && body.observed_at >= Math.floor(Date.now() / 1000) - 600)
        assert.equal(body.evidence, 'TEST_ONLY 私有只读设备回执确认原进程停止与临时资源清理；原操作执行结论仍为未知。')
        assert.equal(JSON.stringify(detail.steps[0].execution_result), originalBytes)
        detail.job.status = 'cancelled'
        detail.history.push({ id: 2, action: 'reconciled', recorded_at: now, details: { inspection_id: newInspection, stopped_without_execution_claim: true } })
        value = { id: job, status: 'cancelled', original_outcome: 'unknown' }
      } else { errors.push(`Unexpected API: ${method} ${path}`); return route.fulfill({ status: 404, json: { error: 'Unexpected API' } }) }
      await route.fulfill({ json: value })
    })
    await page.goto(`${origin}/#/operations`)
    const row = page.getByRole('row').filter({ hasText: 'TEST_ONLY 未确认设备操作' })
    await row.getByRole('button', { name: '详情', exact: true }).click()
    await page.getByRole('button', { name: '核对日常操作进程停止', exact: true }).click()
    const review = page.locator('section.operations-review').filter({ has: page.getByRole('heading', { name: '核对服务器 7 的原日常操作', exact: true }) })
    const final = review.getByRole('button', { name: '验证身份并记录人工核对，停止后续步骤', exact: true })
    const create = review.getByRole('button', { name: '验证身份并发起新的只读核对', exact: true })
    const read = review.getByRole('button', { name: '读取实际只读回执', exact: true })
    const idle = () => page.waitForFunction(() => document.querySelector('.operations-page')?.getAttribute('aria-busy') === 'false')
    const proof = async password => {
      const dialog = page.getByRole('dialog', { name: '再次验证管理员身份', exact: true })
      await dialog.getByLabel('管理员密码', { exact: true }).fill(password)
      await dialog.getByRole('button', { name: '验证并继续', exact: true }).click()
    }
    assert.equal(await final.isDisabled(), true)
    await create.click()
    assert.equal(inspections, 0)
    await proof('TEST_ONLY wrong password')
    await page.getByRole('alert').filter({ hasText: 'TEST_ONLY 身份验证失败' }).waitFor()
    assert.equal(inspections, 0)
    await proof('TEST_ONLY password')
    await review.getByText(`检查任务：${oldInspection}`, { exact: false }).waitFor()
    assert.equal(inspections, 1)
    await review.getByLabel('已实际确认原操作进程停止', { exact: true }).check()
    await review.getByLabel('已实际核对并清理临时文件、监听与恢复资源', { exact: true }).check()
    await review.getByLabel('实际观察时间', { exact: true }).fill(new Date((now - 60) * 1000).toISOString().slice(0, 16))
    await review.getByLabel('核对方法、来源与失败或未知结论（32 至 4096 字节，不填凭据）', { exact: true }).fill('TEST_ONLY 旧检查草稿仍无有效回执，不能提前提交人工清理结论。')
    await read.click(); await oldHeld
    // A second independent read finishes while the first is delayed. This
    // permits the next proof action without pretending the old GET completed.
    await read.click(); await idle()
    await create.click(); await proof('TEST_ONLY password')
    await review.getByText(`检查任务：${newInspection}`, { exact: false }).waitFor()
    assert.equal(inspections, 2)
    assert.equal(await review.getByLabel('已实际确认原操作进程停止', { exact: true }).isChecked(), false)
    assert.equal(await review.getByLabel('已实际核对并清理临时文件、监听与恢复资源', { exact: true }).isChecked(), false)
    assert.equal(await review.getByLabel('实际观察时间', { exact: true }).inputValue(), '')
    assert.equal(await review.locator('textarea').inputValue(), '')
    const delayed = page.waitForResponse(response => new URL(response.url()).pathname === `/api/fleet/operations/${oldInspection}`)
    await heldOldRoute.fulfill({ json: { id: oldInspection, server_id: 7, reconciliation_of: original, status: 'succeeded', result: { succeeded: true, completed_at: now } } })
    await delayed; await idle()
    assert.equal(await final.isDisabled(), true)
    assert.equal(await review.getByText('已取得五分钟内的成功设备回执', { exact: false }).count(), 0)
    await review.getByRole('button', { name: '读取实际只读回执', exact: true }).waitFor()
    const observation = review.locator('details').filter({ has: page.locator('summary', { hasText: '查看设备观测' }) })
    await observation.locator('summary').click()
    assert.equal((await observation.locator('pre').textContent()).trim(), 'null')
    const base = { id: newInspection, server_id: 7, reconciliation_of: original, status: 'succeeded', result: { succeeded: true, completed_at: now } }
    for (const invalid of [
      { ...base, id: oldInspection }, { ...base, server_id: 8 }, { ...base, reconciliation_of: oldInspection },
      { ...base, status: 'failed' }, { ...base, result: { succeeded: false, completed_at: now } },
      { ...base, result: { succeeded: true, completed_at: now - 301 } },
      { ...base, result: { succeeded: true, completed_at: now + 600 } },
      { ...base, result: { succeeded: true, completed_at: null } },
    ]) {
      newReceipt = invalid
      await read.click(); await idle()
      assert.equal(await final.isDisabled(), true)
      assert.equal(await review.getByText('已取得五分钟内的成功设备回执', { exact: false }).count(), 0)
    }
    newReceipt = base; await read.click(); await idle()
    await review.getByText('已取得五分钟内的成功设备回执', { exact: false }).waitFor()
    assert.equal(await final.isDisabled(), true)
    const stopped = review.getByLabel('已实际确认原操作进程停止', { exact: true })
    const cleaned = review.getByLabel('已实际核对并清理临时文件、监听与恢复资源', { exact: true })
    const at = review.getByLabel('实际观察时间', { exact: true }), evidence = review.locator('textarea')
    await stopped.check(); assert.equal(await final.isDisabled(), true)
    await cleaned.check(); assert.equal(await final.isDisabled(), true)
    await evidence.fill('短'); assert.equal(await final.isDisabled(), true)
    for (const timestamp of [now - 1200, now + 600]) {
      await at.fill(new Date(timestamp * 1000).toISOString().slice(0, 16))
      await evidence.fill('TEST_ONLY 私有只读设备回执确认原进程停止与临时资源清理；原操作执行结论仍为未知。')
      assert.equal(await final.isDisabled(), true)
    }
    await at.fill(new Date((now - 60) * 1000).toISOString().slice(0, 16))
    await evidence.fill('测'.repeat(1400)); assert.equal(await final.isDisabled(), true)
    await evidence.fill('TEST_ONLY 私有只读设备回执确认原进程停止与临时资源清理；原操作执行结论仍为未知。')
    assert.equal(await final.isDisabled(), false)
    await final.click()
    assert.equal(writes.filter(write => write.path.endsWith('/reconcile')).length, 0)
    await proof('TEST_ONLY password')
    await page.getByRole('heading', { name: 'TEST_ONLY 未确认设备操作 · 已取消', exact: true }).waitFor()
    assert.equal(await review.count(), 0)
    assert.equal(inspections, 2); assert.equal(reauth, 4)
    assert.equal(writes.filter(write => write.path.endsWith('/reconcile')).length, 1)
    assert.equal(writes.filter(write => !write.path.endsWith('/reconcile') && !write.path.endsWith('/inspection') && write.path !== '/api/control-center/reauth').length, 0)
    assert.equal(JSON.stringify(detail.steps[0].execution_result), originalBytes)
    await page.getByText('TEST_ONLY 原结果未知，等待实际清理核对', { exact: true }).first().waitFor()
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    assert.deepEqual(external, []); assert.deepEqual(errors, [])
    results.push({ width, inspection_requests: inspections, reconciliation_writes: 1, reauth_requests: reauth, private_api_requests: requests.length, external_requests: external.length, page_errors: errors.length, original_outcome_preserved: true })
    await context.close()
  }
  console.log(JSON.stringify({ status: 'passed', scope: 'operations reconciliation full desktop/mobile, stale read identity and time gates, exact single write, original unknown preserved', results }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
