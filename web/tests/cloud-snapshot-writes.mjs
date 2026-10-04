import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { extname, resolve, sep } from 'node:path'

// TEST_ONLY: shipping UI and owned loopback API snapshots, without cloud calls.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url)), path = '/api/plugins/alicloud'
const server = createServer(async (request, response) => {
  const name = new URL(request.url, 'http://127.0.0.1').pathname, file = resolve(dist, name === '/' ? 'index.html' : `.${name}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`, totals = { scenarios: 0, blocked: 0, errors: [], external: [], unexpected: [] }
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const wait = async (condition, label) => { const until = Date.now() + 12000; while (!await condition()) { assert(Date.now() < until, label); await new Promise(resolve => setTimeout(resolve, 20)) } }
try {
  for (const width of [1440, 390]) for (const kind of ['account', 'resource', 'bandwidth', 'policy', 'power']) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(12000)
    page.on('pageerror', error => totals.errors.push(error.message))
    const now = Math.floor(Date.now() / 1000), policy = { enabled: false, stop_mode: 'KeepCharging', threshold_action: 'off', limit_gb: 100, threshold_percent: 95, schedule_enabled: false, start_time: '08:00', stop_time: '23:00', utc_offset_minutes: 480, keepalive: false }
    const account = { id: 'account', name: 'TEST_ONLY 云账号', site: 'china', enabled: true, auto_enabled: false, limit_gb: 100, revision: 1, bill: null, traffic: null, error_code: null, traffic_error: null, balance: null }
    const snapshot = { kind: 'ecs', cloud_id: 'i-testonly', region: 'cn-hangzhou', public_ip: '192.0.2.1', bandwidth_mbps: 10, charge_type: 'PayByTraffic', resource_charge_type: 'PostPaid', status: 'Running' }
    const resource = { id: 'resource', name: 'TEST_ONLY ECS', account_id: account.id, kind: 'ecs', cloud_id: snapshot.cloud_id, region: snapshot.region, auto_enabled: false, cap_mbps: 1, revision: 1, snapshot, checked_at: now, error_code: null, power_policy: policy, manual_hold: false, threshold_hold: false, power_state: { cloud_id: snapshot.cloud_id, region: snapshot.region, status: 'Running', locked: false, stopped_mode: null, public_ips: [snapshot.public_ip], spot_strategy: 'NoSpot' } }
    const overview = { accounts: [account], resources: [resource], operations: [], power_jobs: [], events: [] }, writes = [], pending = []
    let failure = false, gate = null
    await page.route('**/*', route => {
      const task = (async () => {
        const request = route.request(), url = new URL(request.url()), method = request.method()
        if (url.origin !== origin) { totals.external.push(url.href); return route.abort() }
        if (!url.pathname.startsWith('/api/')) return route.continue()
        if (url.pathname === '/api/dashboard/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
        if (method === 'GET' && url.pathname === path) {
          if (gate) { ++gate.reached; await gate.promise }
          return failure ? route.fulfill({ status: 503, json: { error: 'TEST_ONLY 云快照刷新失败' } }) : route.fulfill({ json: overview })
        }
        if (method !== 'GET') writes.push({ path: url.pathname, body: request.postData() ? request.postDataJSON() : null })
        if (url.pathname.endsWith('/preview')) {
          const operation = { id: 'preview', resource_id: resource.id, account_revision: account.revision, resource_revision: resource.revision, before_state: snapshot, target: request.postDataJSON().target, source: 'manual', status: 'preview', expires_at: now + 300, created_at: now, updated_at: now, request_id: null, error_code: null }
          overview.operations = [operation]; return route.fulfill({ json: operation })
        }
        if (url.pathname.endsWith('/power-preview')) {
          const job = { id: 'preview', resource_id: resource.id, account_revision: account.revision, resource_revision: resource.revision, before_state: resource.power_state, action: 'stop', stop_mode: request.postDataJSON().stop_mode, source: 'manual', status: 'preview', expires_at: now + 300, created_at: now, error_code: null, request_id: null }
          overview.power_jobs = [job]; return route.fulfill({ json: job })
        }
        totals.unexpected.push(`${method} ${url.pathname}`); return route.fulfill({ status: 500, json: { error: 'TEST_ONLY unexpected write' } })
      })()
      pending.push(task); return task
    })
    const refresh = page.getByRole('button', { name: '刷新', exact: true })
    const reread = async () => {
      const response = page.waitForResponse(response => new URL(response.url()).pathname === path)
      await refresh.evaluate(element => element.click()); await response
    }
    try {
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#/plugins/alicloud`)
      const names = { account: '编辑账号与策略', resource: '编辑策略', bandwidth: '调整带宽与计费', policy: '配置自动启停', power: '停机' }
      const opener = page.getByRole('button', { name: names[kind], exact: true })
      await wait(() => opener.isEnabled(), 'Initial owned cloud snapshot is current'); await opener.click()
      const dialog = page.getByRole('dialog'), form = dialog.locator('form'), submit = form.locator('footer button.button-primary')
      if (kind === 'account') await dialog.getByLabel('账号名称', { exact: true }).fill('TEST_ONLY 保留账号草稿')
      if (kind === 'resource') await dialog.getByLabel('资源名称', { exact: true }).fill('TEST_ONLY 保留资源草稿')
      if (kind === 'bandwidth') await dialog.getByRole('spinbutton', { name: /^公网出带宽/ }).fill('7')
      if (kind === 'policy') await dialog.getByLabel('抢占式实例保活', { exact: true }).check()
      if (kind === 'power') await dialog.getByRole('combobox', { name: '本次停机模式', exact: true }).selectOption('StopCharging')
      await wait(() => submit.isEnabled(), 'Original draft is writable')
      await form.evaluate(element => {
        const key = Object.keys(element).find(key => key.startsWith('__reactProps$'))
        const handler = element[key]?.onSubmit
        assertHandler(handler)
        window.TEST_ONLY_submit = () => handler({ preventDefault() {}, currentTarget: element })
        function assertHandler(value) { if (typeof value !== 'function') throw new Error('TEST_ONLY actual submit handler missing') }
      })
      let release; gate = { promise: new Promise(resolve => { release = resolve }), reached: 0 }
      gate.release = release
      await refresh.evaluate(element => { element.click(); window.TEST_ONLY_submit() })
      await wait(() => gate.reached > 0, 'Held current GET starts')
      assert.equal(writes.length, 0, 'Same-event refresh rejects the captured old submit handler'); ++totals.blocked
      failure = true; release(); gate = null
      await page.getByText('TEST_ONLY 云快照刷新失败', { exact: true }).waitFor()
      await page.evaluate(() => window.TEST_ONLY_submit()); assert.equal(writes.length, 0); ++totals.blocked
      failure = false; await reread(); await wait(() => submit.isEnabled(), 'Valid original snapshot recovers without replacing draft')
      if (kind === 'account') assert.equal(await dialog.getByLabel('账号名称', { exact: true }).inputValue(), 'TEST_ONLY 保留账号草稿')
      if (kind === 'resource') assert.equal(await dialog.getByLabel('资源名称', { exact: true }).inputValue(), 'TEST_ONLY 保留资源草稿')
      if (kind === 'bandwidth') assert.equal(await dialog.getByRole('spinbutton', { name: /^公网出带宽/ }).inputValue(), '7')
      if (kind === 'policy') assert.equal(await dialog.getByLabel('抢占式实例保活', { exact: true }).isChecked(), true)
      if (kind === 'power') assert.equal(await dialog.getByRole('combobox', { name: '本次停机模式', exact: true }).inputValue(), 'StopCharging')
      account.revision++; await reread(); await wait(() => submit.isDisabled(), 'Account revision alone invalidates the original draft')
      await page.evaluate(() => window.TEST_ONLY_submit()); assert.equal(writes.length, 0); ++totals.blocked
      await dialog.getByRole('button', { name: '取消', exact: true }).click()
      if (['bandwidth', 'power'].includes(kind)) {
        await opener.click(); await page.getByRole('dialog').locator('footer button.button-primary').click()
        const confirmation = page.getByRole('dialog'), confirm = confirmation.locator('footer button.button-primary')
        await confirmation.getByRole('checkbox').check(); await wait(() => confirm.isEnabled(), 'Current matching preview becomes confirmable')
        assert.equal(writes.length, 1, 'Only the read-only preview was requested')
        if (kind === 'bandwidth') overview.operations[0].target = { ...overview.operations[0].target, bandwidth_mbps: 9 }
        else overview.power_jobs[0].stop_mode = overview.power_jobs[0].stop_mode === 'KeepCharging' ? 'StopCharging' : 'KeepCharging'
        await reread(); await wait(() => confirm.isDisabled(), 'Changed current preview cannot inherit the original confirmation')
        await confirmation.locator('form').evaluate(element => { const key = Object.keys(element).find(key => key.startsWith('__reactProps$')); element[key].onSubmit({ preventDefault() {}, currentTarget: element }) })
        assert.equal(writes.length, 1, 'No billing or power confirmation POST follows changed preview'); ++totals.blocked
      }
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      ++totals.scenarios
    } finally { gate?.release(); gate = null; await Promise.all(pending); await page.close() }
  }
  assert.deepEqual(totals.errors, []); assert.deepEqual(totals.external, []); assert.deepEqual(totals.unexpected, [])
  console.log(JSON.stringify({ result: 'PASS', ...totals }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
