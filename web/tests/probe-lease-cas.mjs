import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { extname, resolve, sep } from 'node:path'

// TEST_ONLY: revision/CAS and lease explanation are exercised on the actual built UI.
// The API and targets belong to a private loopback fixture; no real probes are sent.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url)), base = '/api/servers/1'
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname, file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`, totals = { widths: [], writes: 0, conflicts: 0, blocked: 0, requests: 0, external: [], unexpected: [], errors: [] }
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const wait = async (condition, message) => { const deadline = Date.now() + 12000; while (!await condition()) { assert(Date.now() < deadline, message); await new Promise(resolve => setTimeout(resolve, 20)) } }
const forceForm = form => form.evaluate(element => element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
const forceClick = button => button.evaluate(element => { element.disabled = false; element.click() })
try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(12000)
    page.on('pageerror', error => totals.errors.push(error.message))
    const now = Math.floor(Date.now() / 1000), id = '00000000-0000-0000-0000-000000000001', legacyId = '00000000-0000-0000-0000-000000000002'
    const identity = { kind: 'tcp', target: '127.0.0.1', port: 443, address_family: 'ipv4' }
    const authorization = { kind: 'owned', source: 'TEST_ONLY owned loopback asset', scope: 'TEST_ONLY TCP four attempts, server 1, at least 30 second interval', expires_at: null, enabled: true, identity }
    let configured = { id, revision: 4, name: 'TEST_ONLY 当前拨测', kind: 'tcp', target: identity.target, port: identity.port, interval_secs: 30, carrier: '', enabled: true, execution_authorized: true, monitor: { network: 'telecom', region: 'TEST_ONLY 回环地区', address_family: 'ipv4', authorization } }
    const legacy = { id: legacyId, name: 'TEST_ONLY 旧拨测', kind: 'tcp', target: '127.0.0.1', port: 8443, interval_secs: 30, carrier: '', enabled: false, monitor: null, execution_authorized: false }
    const samples = [{ id: '00000000-0000-0000-0000-000000000101', probe_id: id, sampled_at: now * 1000, latency_ms: null, loss_percent: 100, error: 'TEST_ONLY 历史 TCP 连接失败', attempts: 4, address_family: 'ipv4' }]
    const writes = [], pending = [], gates = new Map(); let failed = false
    const hold = () => { let release; const promise = new Promise(resolve => { release = resolve }); const gate = { promise, release, reached: 0 }; gates.set('probes', gate); return gate }
    await page.route('**/*', route => {
      const task = (async () => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
        if (url.origin !== origin) { totals.external.push(url.href); return route.abort() }
        if (!path.startsWith('/api/')) return route.continue()
        ++totals.requests
        if (path === `${base}/probes` && method === 'GET') {
          const gate = gates.get('probes'); if (gate) { ++gate.reached; await gate.promise }
          return failed ? route.fulfill({ status: 503, json: { error: 'TEST_ONLY 拨测读取失败，原快照保留' } }) : route.fulfill({ json: [...(configured ? [configured] : []), legacy] })
        }
        if (path === `${base}/probes/${id}` && ['PATCH', 'DELETE'].includes(method)) {
          const body = request.postDataJSON(); writes.push({ method, path, body }); ++totals.writes
          if (body.revision !== configured.revision) { ++totals.conflicts; return route.fulfill({ status: 409, json: { error: 'TEST_ONLY 拨测已被修改，请刷新后重试' } }) }
          if (method === 'DELETE') { assert.deepEqual(body, { revision: configured.revision }); configured = null; return route.fulfill({ status: 204 }) }
          assert.equal(body.id, id); assert.equal(body.kind, identity.kind); assert.equal(body.target, identity.target); assert.equal(body.port, identity.port)
          assert.deepEqual(body.monitor.authorization.identity, identity)
          configured = { ...body, execution_authorized: Boolean(body.enabled && body.monitor.authorization.enabled), revision: body.revision + 1 }
          return route.fulfill({ json: configured })
        }
        let value
        if (method !== 'GET') { totals.unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { error: 'Unexpected write' } }) }
        if (['/api/dashboard/access', '/api/me'].includes(path)) value = { authenticated: true, public_dashboard: false }
        else if (path === base) value = { id: 1, name: 'TEST_ONLY 拨测修订设备', online: true, device_public_key: 'TEST_ONLY', static_info: {}, latest_metrics: {}, last_seen: now, manifest_rev: 0, capabilities: [] }
        else if (path === `${base}/agent-settings`) value = { sample_interval_secs: 1, upload_interval_secs: 5, discover_public_ips: false, auto_update: false }
        else if (path === `${base}/telemetry-settings`) value = { persist_interval_secs: 60 }
        else if (path === `${base}/probe-results`) value = url.searchParams.get('probe_id') ? samples.filter(item => item.probe_id === url.searchParams.get('probe_id')) : samples
        else if (path === `${base}/commands`) value = []
        else if (path === '/api/plugins/sing-box/servers/1') value = { id: 1, name: 'TEST_ONLY 拨测修订设备', enabled: false, source: null, online: true, read_only: false, agent_supported: false }
        else { totals.unexpected.push(`${method} ${path}`); return route.fulfill({ status: 404, json: { error: 'Unexpected API' } }) }
        return route.fulfill({ json: value })
      })()
      pending.push(task); return task
    })
    try {
      await page.goto(`${origin}/#/servers/1`)
      const panel = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: '持续网络拨测', exact: true }) }), form = panel.locator('form')
      const row = () => panel.getByRole('row').filter({ has: page.getByRole('button', { name: configured?.name ?? 'TEST_ONLY 当前拨测', exact: true }) })
      const legacyRow = panel.getByRole('row').filter({ hasText: 'TEST_ONLY 旧拨测' })
      await wait(() => row().getByRole('button', { name: '编辑', exact: true }).isEnabled(), 'Current persisted revision is editable')
      await panel.getByText(/执行许可绑定设备、连接会话和配置修订，最长 90 秒/).waitFor()
      for (const label of ['编辑', '启用', '删除']) { const button = legacyRow.getByRole('button', { name: label, exact: true }); assert.equal(await button.isDisabled(), true); await forceClick(button); ++totals.blocked }
      assert.equal(writes.length, 0); await legacyRow.getByText('未取得执行授权', { exact: false }).waitFor()
      await row().getByRole('button', { name: '编辑', exact: true }).click(); await form.getByLabel('名称', { exact: true }).fill('TEST_ONLY 409 保留草稿')
      configured = { ...configured, revision: 5, name: 'TEST_ONLY 另一管理员版本' }
      await form.getByRole('button', { name: '保存拨测', exact: true }).click()
      await panel.getByText('TEST_ONLY 拨测已被修改，请刷新后重试', { exact: true }).waitFor()
      assert.equal(writes.length, 1); assert.equal(writes[0].body.revision, 4); assert.equal(await form.getByLabel('名称', { exact: true }).inputValue(), 'TEST_ONLY 409 保留草稿')
      await panel.getByText('此拨测已不存在或目标、版本已变化，请刷新后重新确认；当前草稿已保留。', { exact: true }).waitFor()
      await forceForm(form); assert.equal(writes.length, 1); ++totals.blocked
      await form.getByRole('button', { name: '取消编辑', exact: true }).click(); await row().getByRole('button', { name: '编辑', exact: true }).click()
      await form.getByLabel('名称', { exact: true }).fill('TEST_ONLY 409 保留草稿'); await form.getByRole('button', { name: '保存拨测', exact: true }).click()
      await wait(() => configured.revision === 6 && row().getByRole('button', { name: '编辑', exact: true }).isEnabled(), 'Explicit reread/reselect sends revision 5')
      assert.equal(writes.length, 2); assert.equal(writes[1].body.revision, 5); assert.equal(Object.hasOwn(writes[1].body, 'execution_authorized'), false)
      await row().getByRole('button', { name: '编辑', exact: true }).click(); await form.getByLabel('名称', { exact: true }).fill('TEST_ONLY 读取故障草稿')
      const gate = hold(); await wait(() => gate.reached > 0, 'The actual five-second probe poll starts the held GET')
      const blockedWrites = writes.length
      const forceAll = async () => { await forceForm(form); await forceClick(row().getByRole('button', { name: '暂停', exact: true })); await forceClick(row().getByRole('button', { name: '删除', exact: true })); totals.blocked += 3 }
      await forceAll(); assert.equal(writes.length, blockedWrites); assert.equal(await form.getByLabel('名称', { exact: true }).inputValue(), 'TEST_ONLY 读取故障草稿')
      failed = true; gate.release(); gates.delete('probes'); await panel.getByText('TEST_ONLY 拨测读取失败，原快照保留', { exact: true }).waitFor()
      await forceAll(); assert.equal(writes.length, blockedWrites); assert.equal(await form.getByLabel('名称', { exact: true }).inputValue(), 'TEST_ONLY 读取故障草稿')
      await row().getByRole('button', { name: configured.name, exact: true }).click()
      await panel.getByRole('heading', { name: '最近 60 次测量', exact: true }).waitFor(); await panel.getByText('TEST_ONLY 历史 TCP 连接失败', { exact: true }).last().waitFor()
      if (process.env.SINAN_UI_SCREENSHOT_DIR) { await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true }); await page.screenshot({ path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `probe-lease-cas-failure-${width}.png`), fullPage: true }) }
      failed = false; await wait(() => form.getByRole('button', { name: '保存拨测', exact: true }).isEnabled(), 'Only a successful probe read restores the draft')
      await form.getByRole('button', { name: '保存拨测', exact: true }).click(); await wait(() => configured.revision === 7 && row().getByRole('button', { name: '暂停', exact: true }).isEnabled(), 'Recovered draft writes once with revision 6')
      assert.equal(writes.length, blockedWrites + 1); assert.equal(writes.at(-1).body.revision, 6); assert.equal(writes.at(-1).body.name, 'TEST_ONLY 读取故障草稿')
      await row().getByRole('button', { name: '暂停', exact: true }).click(); await wait(() => configured.revision === 8 && row().getByRole('button', { name: '启用', exact: true }).isEnabled(), 'Pause PATCH includes the current revision')
      assert.equal(writes.at(-1).body.revision, 7); assert.equal(writes.at(-1).body.enabled, false)
      configured = { ...configured, revision: 9 }; await row().getByRole('button', { name: '删除', exact: true }).click()
      await panel.getByText('TEST_ONLY 拨测已被修改，请刷新后重试', { exact: true }).waitFor(); assert.deepEqual(writes.at(-1).body, { revision: 8 })
      const observed = page.waitForResponse(response => new URL(response.url()).pathname === `${base}/probes` && response.request().method() === 'GET')
      await observed; await wait(() => row().getByRole('button', { name: '删除', exact: true }).isEnabled(), 'Delete rereads the latest server revision')
      await row().getByRole('button', { name: '删除', exact: true }).click(); await wait(() => configured === null, 'Explicit delete sends revision 9')
      assert.deepEqual(writes.at(-1).body, { revision: 9 }); assert.equal(writes.length, 6)
      await panel.getByRole('heading', { name: '最近 60 次测量', exact: true }).waitFor(); await panel.getByText('TEST_ONLY 历史 TCP 连接失败', { exact: true }).last().waitFor()
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
      totals.widths.push(width)
    } finally { for (const gate of gates.values()) gate.release(); await Promise.all(pending); await page.close() }
  }
  assert.deepEqual(totals.external, []); assert.deepEqual(totals.unexpected, []); assert.deepEqual(totals.errors, [])
  console.log(JSON.stringify({ result: 'PASS', ...totals }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
