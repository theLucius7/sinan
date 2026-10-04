import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const http = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${http.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []

try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], writes = [], unexpected = []
    page.on('pageerror', error => errors.push(error.message))
    await page.clock.install()
    const second = Math.floor(Date.now() / 1000)
    const entry = { id: 1, name: '测试离线服务器', device_public_key: 'TEST_ONLY', online: false, last_seen: second, last_heartbeat_at: second, metrics_sampled_at: null, metrics_stale: true, static_info: {}, latest_metrics: {}, capabilities: [], manifest_rev: 0 }
    let probes = [{ id: 'probe-1', name: '旧回环目标', kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 30, carrier: '', enabled: true, monitor: null, revision: 1 }]
    let readMode = 'ready', releasePending, createFailure = true
    await page.route('**/api/**', async route => {
      const request = route.request(), rawPath = new URL(request.url()).pathname, path = rawPath.replace('/api/dashboard/', '/api/'), method = request.method()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/access') return respond({ authenticated: true, public_dashboard: false })
      if (path === '/api/me') return respond({ id: 1 })
      if (path === '/api/servers') return respond([entry])
      if (path === '/api/servers/1') return respond(entry)
      if (method !== 'GET') writes.push({ path, method, body: request.postDataJSON() })
      if (path === '/api/servers/1/probes' && method === 'GET') {
        if (readMode === 'failure') return respond({ error: 'TEST_ONLY 拨测读取失败' }, 503)
        if (readMode === 'pending') await new Promise(resolve => { releasePending = resolve })
        return respond(probes)
      }
      if (path === '/api/servers/1/probes' && method === 'POST') {
        if (createFailure) return respond({ error: 'TEST_ONLY 创建失败' }, 409)
        probes.push({ ...request.postDataJSON(), id: 'probe-2', revision: 1 })
        return respond(probes.at(-1), 201)
      }
      if (path.startsWith('/api/servers/1/probes/') && method === 'PATCH') {
        const index = probes.findIndex(item => item.id === path.split('/').at(-1)), body = request.postDataJSON()
        if (index < 0 || body.revision !== probes[index].revision) return respond({ error: 'TEST_ONLY 版本冲突' }, 409)
        probes[index] = { ...body, id: probes[index].id, revision: probes[index].revision + 1 }
        return respond(probes[index])
      }
      if (path.startsWith('/api/servers/1/probes/') && method === 'DELETE') {
        const current = probes.find(item => item.id === path.split('/').at(-1))
        if (!current || current.revision !== request.postDataJSON().revision) return respond({ error: 'TEST_ONLY 版本冲突' }, 409)
        probes = probes.filter(item => item.id !== current.id)
        return route.fulfill({ status: 204 })
      }
      if (path === '/api/servers/1/probe-results') return respond([{ id: 'old-point', probe_id: 'probe-1', sampled_at: Date.now(), latency_ms: 0, loss_percent: 0, error: null }])
      if (path === '/api/servers/1/telemetry-settings') return respond({ persist_interval_secs: 60 })
      if (path === '/api/servers/1/agent-settings') return respond({ sample_interval_secs: 1, upload_interval_secs: 3, auto_update: false, discover_public_ips: false })
      if (path === '/api/plugins/sing-box/servers/1') return respond({ id: 1, name: entry.name, enabled: false, read_only: false, online: false, agent_supported: false, installation: { state: 'not_enabled', reason: '未启用', target_rev: 0, applied_rev: 0 } })
      if (path === '/api/servers/1/commands' || path === '/api/servers/1/metrics' || path === '/api/probes/overview') return respond([])
      unexpected.push(`${method} ${path}`); return respond({ error: 'Unexpected request' }, 500)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/1`)
    const panel = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: '持续网络拨测', exact: true }) })
    await panel.getByText('未取得执行授权', { exact: false }).waitFor()
    const oldRow = panel.getByRole('row').filter({ hasText: '旧回环目标' })
    assert.equal(await oldRow.getByRole('cell').nth(2).innerText(), '—', 'Legacy successful zero measurement is historical, not current authorization')
    await panel.getByLabel('名称', { exact: true }).fill('保留的新拨测')
    await panel.getByLabel('目标地址', { exact: true }).fill('127.0.0.1')
    await panel.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await panel.getByRole('alert').filter({ hasText: '授权' }).waitFor()
    assert.equal(writes.length, 0, 'Loopback does not automatically authorize the target')
    await panel.getByLabel('目标授权依据').selectOption('owned')
    await panel.getByLabel('授权来源', { exact: false }).fill('TEST_ONLY 自有服务')
    await panel.getByLabel('授权适用范围', { exact: false }).fill('TEST_ONLY 管理记录')
    await panel.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    readMode = 'failure'
    await page.clock.runFor(5001)
    await panel.getByRole('alert').filter({ hasText: '读取失败' }).waitFor()
    await panel.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    assert.equal(writes.length, 0, 'The real callback rejects a failed refreshed source list')
    assert.equal(await panel.getByLabel('名称', { exact: true }).inputValue(), '保留的新拨测')
    readMode = 'ready'
    await page.clock.runFor(5001)
    await page.waitForFunction(() => !Array.from(document.querySelectorAll('button')).find(button => button.textContent === '添加拨测')?.disabled)
    readMode = 'pending'
    await page.clock.runFor(5001)
    await panel.getByRole('alert').filter({ hasText: '正在刷新' }).waitFor()
    await panel.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    assert.equal(writes.length, 0, 'The real callback rejects a pending GET with old data retained')
    readMode = 'ready'; releasePending()
    await page.waitForFunction(() => !Array.from(document.querySelectorAll('button')).find(button => button.textContent === '添加拨测')?.disabled)
    await panel.getByRole('button', { name: '添加拨测', exact: true }).click()
    await panel.getByRole('alert').filter({ hasText: '创建失败' }).waitFor()
    assert.equal(writes.length, 1)
    assert.equal(await panel.getByLabel('名称', { exact: true }).inputValue(), '保留的新拨测')
    createFailure = false
    await panel.getByRole('button', { name: '添加拨测', exact: true }).click()
    await panel.getByRole('row').filter({ hasText: '保留的新拨测' }).waitFor()
    assert.equal(writes.length, 2)
    assert.equal(Object.keys(writes[1].body).length, 9, 'Creation has the original eight fields plus main monitor identity')
    assert.equal(writes[1].body.monitor.authorization.scope, 'TEST_ONLY 管理记录')
    assert.equal(entry.online, false, 'Offline server configuration is accepted')
    await panel.getByRole('row').filter({ hasText: '保留的新拨测' }).getByRole('button', { name: '编辑', exact: true }).click()
    await panel.getByLabel('名称', { exact: true }).fill('旧版本草稿')
    probes[1] = { ...probes[1], revision: 2 }
    await page.clock.runFor(5001)
    await panel.getByRole('alert').filter({ hasText: '版本已变化' }).waitFor()
    await panel.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    assert.equal(writes.length, 2, 'A changed revision blocks the preserved editor')
    assert.equal(await panel.getByLabel('名称', { exact: true }).inputValue(), '旧版本草稿')
    await panel.getByRole('button', { name: '取消编辑', exact: true }).click()
    await panel.getByRole('row').filter({ hasText: '保留的新拨测' }).getByRole('button', { name: '编辑', exact: true }).click()
    await panel.getByLabel('名称', { exact: true }).fill('按新版本保存')
    await panel.getByRole('button', { name: '保存拨测', exact: true }).click()
    await panel.getByRole('row').filter({ hasText: '按新版本保存' }).waitFor()
    assert.equal(writes[2].body.revision, 2)
    await panel.getByRole('row').filter({ hasText: '按新版本保存' }).getByRole('button', { name: '删除', exact: true }).click()
    await panel.getByRole('row').filter({ hasText: '按新版本保存' }).waitFor({ state: 'detached' })
    assert.deepEqual(writes[3].body, { revision: 3 })
    assert.match(await panel.innerText(), /最长 90 秒/)
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
    results.push({ width, legacy: 'historical only', unknownAuthorization: 'zero writes', readGates: 'zero writes', revisions: 'revalidated', offlineConfiguration: 'accepted', delete: 'CAS body' })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally { await browser.close(); http.close() }
