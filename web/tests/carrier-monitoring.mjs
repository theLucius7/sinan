import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const receipts = []
const id = suffix => `00000000-0000-0000-0000-${String(suffix).padStart(12, '0')}`
const authorization = { kind: 'owned', enabled: true, source: 'TEST_ONLY owned loopback fixture', scope: 'TEST_ONLY loopback TCP/ICMP, four attempts, interval at least 30 seconds, fixture server 1', expires_at: null }
const monitored = (network, suffix, extra = {}) => {
  const spec = { id: id(suffix), name: `TEST_ONLY ${network}`, kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 30, carrier: '', enabled: extra.enabled !== false, monitor: { network, region: 'TEST_ONLY 回环地区', address_family: 'ipv4', authorization: { ...authorization, ...extra, identity: { kind: 'tcp', target: '127.0.0.1', port: 443, address_family: 'ipv4' } } } }
  return spec
}


try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], unexpected = [], external = [], writes = []
    page.on('pageerror', error => errors.push(error.message))
    let tasks = [{ id: id(1), spec: { id: id(1), name: '旧任务历史', kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 30, carrier: '', enabled: false }, default_enabled: false, server_ids: [1], revision: 2 }]
    let rows = [], failing = false
    const now = Date.now()
    const servers = [{ id: 1, name: 'TEST_ONLY 回环节点', online: true }, { id: 2, name: 'TEST_ONLY 未配置节点', online: true }]
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
      if (url.origin !== origin) { external.push(request.url()); return route.abort() }
      if (!path.startsWith('/api/')) return route.continue()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/dashboard/access' && method === 'GET') return respond({ authenticated: true, public_dashboard: false })
      if (path === '/api/servers' && method === 'GET') return respond(servers)
      if (path === '/api/probes/overview' && method === 'GET') return respond(failing ? { error: 'TEST_ONLY overview unavailable' } : rows, failing ? 503 : 200)
      if (method !== 'GET') writes.push({ path, method, body: request.postDataJSON() })
      if (path === '/api/latency-tasks' && method === 'GET') return respond(tasks)
      if (path === '/api/latency-tasks' && method === 'POST') {
        const body = request.postDataJSON(), task = { ...body, id: id(2), spec: { ...body.spec, id: id(2) }, revision: 1 }
        tasks.push(task)
        const telecom = { ...task.spec, id: id(12) }, unicom = monitored('unicom', 13, { enabled: false }), mobile = { ...monitored('mobile', 14, { expires_at: Math.floor(now / 1000) - 1 }), kind: 'icmp', target: '::1', port: null }
        mobile.monitor.address_family = 'ipv6'
        mobile.monitor.authorization.identity = { kind: 'icmp', target: '::1', port: null, address_family: 'ipv6' }
        rows = [
          { server_id: 1, probe: telecom, results: [{ id: id(101), probe_id: telecom.id, sampled_at: now - 1000, latency_ms: null, loss_percent: 100, error: 'TEST_ONLY TCP connection refused', attempts: 4, address_family: 'ipv4' }] },
          { server_id: 1, probe: unicom, results: [{ id: id(102), probe_id: unicom.id, sampled_at: now - 1000, latency_ms: 0, loss_percent: 0, error: null, attempts: 4, address_family: 'ipv4' }] },
          { server_id: 1, probe: mobile, results: [{ id: id(103), probe_id: mobile.id, sampled_at: now - 1000, latency_ms: 0, loss_percent: 0, error: null, attempts: 4, address_family: 'ipv6' }] },
        ]
        return respond(task, 201)
      }
      if (path === `/api/latency-tasks/${id(2)}` && method === 'PATCH') {
        const body = request.postDataJSON(); assert.equal(body.revision, tasks[1].revision)
        tasks[1] = { ...body, id: id(2), revision: body.revision + 1 }
        rows[0].probe = { ...tasks[1].spec, id: id(12) }
        return respond(tasks[1])
      }
      unexpected.push(`${method} ${path}`); return respond({ error: 'Unexpected fixture API' }, 500)
    })
    await page.goto(`${origin}/#/latency`)
    await page.getByRole('heading', { name: '延迟检测', exact: true }).waitFor()
    const network = label => page.getByRole('region', { name: `${label}周期观测`, exact: true })
    for (const label of ['电信', '联通', '移动']) await network(label).getByText('未配置', { exact: true }).waitFor()
    await page.getByText('未取得执行授权', { exact: true }).waitFor()
    assert.equal(writes.length, 0)
    await page.getByRole('button', { name: '添加任务', exact: true }).click()
    let dialog = page.getByRole('dialog')
    assert.equal(await dialog.getByLabel('目标地址', { exact: false }).inputValue(), '')
    assert.equal(await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false)
    assert.equal(await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isDisabled(), true)
    await dialog.getByLabel('任务名称').fill('TEST_ONLY 电信周期')
    await dialog.getByLabel('目标地址', { exact: false }).fill('127.0.0.1')
    await dialog.getByLabel('运营商线路').selectOption('telecom')
    await dialog.getByLabel('目标地区', { exact: false }).fill('TEST_ONLY 回环地区')
    await dialog.getByLabel('网络版本').selectOption('ipv4')
    await dialog.getByLabel('目标授权依据').selectOption('owned')
    await dialog.getByLabel('授权来源', { exact: false }).fill(authorization.source)
    await dialog.getByLabel('授权适用范围', { exact: false }).fill(authorization.scope)
    await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    await dialog.getByLabel('搜索服务器').fill('回环节点')
    await dialog.getByRole('button', { name: '全选当前结果' }).click()
    await dialog.getByRole('button', { name: '保存任务' }).click()
    await dialog.waitFor({ state: 'detached' })
    assert.equal(writes[0].method, 'POST')
    assert.deepEqual(writes[0].body.server_ids, [1])
    assert.deepEqual(writes[0].body.spec.monitor, { network: 'telecom', region: 'TEST_ONLY 回环地区', address_family: 'ipv4', authorization: { ...authorization, identity: { kind: 'tcp', target: '127.0.0.1', port: 443, address_family: 'ipv4' } } })
    await network('电信').getByText('TEST_ONLY TCP connection refused', { exact: true }).waitFor()
    assert.match(await network('电信').innerText(), /100\.0%/)
    assert.match(await network('电信').innerText(), /IPv4/)
    assert.match(await network('电信').innerText(), /TCP 连接/)
    assert.doesNotMatch(await network('电信').innerText(), /0\.0 ms/)
    assert.match(await network('联通').innerText(), /授权已撤销|未取得执行授权/)
    assert.doesNotMatch(await network('联通').innerText(), /0\.0 ms|0\.0%/)
    assert.match(await network('移动').innerText(), /授权已过期/)
    assert.doesNotMatch(await network('移动').innerText(), /0\.0 ms|0\.0%/)
    await page.getByLabel('观测服务器', { exact: true }).selectOption('2')
    for (const label of ['电信', '联通', '移动']) await network(label).getByText('未配置', { exact: true }).waitFor()
    await page.getByLabel('观测服务器', { exact: true }).selectOption('0')
    const taskTable = page.locator('section.panel').filter({ has: page.getByRole('heading', { name: '延迟任务', exact: true }) })
    const row = taskTable.locator('tbody tr').filter({ hasText: 'TEST_ONLY 电信周期' })
    await row.getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    for (const label of ['目标地址', '运营商线路', '目标地区', '网络版本']) assert.equal(await dialog.getByLabel(label, { exact: false }).isDisabled(), true)
    await dialog.getByLabel('授权来源', { exact: false }).fill('TEST_ONLY replacement permission record')
    assert.equal(await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false, 'Changing evidence requires confirmation again')
    await dialog.getByRole('button', { name: '保存任务' }).click()
    await dialog.waitFor({ state: 'detached' })
    await network('电信').getByText('授权已撤销', { exact: false }).waitFor()
    assert.equal(writes.at(-1).body.spec.enabled, false)
    assert.equal(writes.at(-1).body.spec.monitor.authorization.enabled, false)
    assert.equal(writes.at(-1).body.spec.monitor.authorization.source, 'TEST_ONLY replacement permission record')
    assert.deepEqual(writes.at(-1).body.spec.monitor.authorization.identity, { kind: 'tcp', target: '127.0.0.1', port: 443, address_family: 'ipv4' })
    assert.equal(rows[0].probe.id, id(12), 'Revocation preserves measurement identity')
    assert.equal(rows[0].results[0].id, id(101), 'Revocation preserves fixture history')
    assert.doesNotMatch(await network('电信').innerText(), /100\.0%/)
    // The same immutable IPv6 ICMP definition receives new authorization/results.
    rows[2].probe.monitor.authorization.expires_at = null
    rows[2].results = [{ id: id(104), probe_id: id(14), sampled_at: now - 1000, latency_ms: null, loss_percent: 100, error: 'TEST_ONLY ICMP permission denied' }]
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await network('移动').getByText('检测不可用', { exact: false }).waitFor()
    assert.match(await network('移动').innerText(), /ICMP 回显/)
    assert.match(await network('移动').innerText(), /IPv6（配置）/)
    assert.match(await network('移动').innerText(), /TEST_ONLY ICMP permission denied/)
    assert.doesNotMatch(await network('移动').innerText(), /100\.0%|0\.0 ms/)
    rows[2].results = [{ id: id(105), probe_id: id(14), sampled_at: now - 1000, latency_ms: 0, loss_percent: 0, error: null, attempts: 4, address_family: 'ipv6' }]
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await network('移动').getByText('0.0 ms', { exact: true }).waitFor()
    assert.match(await network('移动').innerText(), /IPv6/)
    assert.doesNotMatch(await network('移动').innerText(), /IPv6（配置）/)
    rows[2].results[0].sampled_at = now - 300_000
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await network('移动').getByText('采样已过期', { exact: true }).waitFor()
    assert.doesNotMatch(await network('移动').innerText(), /0\.0 ms|0\.0%/)
    rows[2].results = []
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await network('移动').getByText('等待采样', { exact: true }).waitFor()
    failing = true
    await page.getByRole('button', { name: /刷新/ }).click()
    await page.getByRole('alert').filter({ hasText: 'TEST_ONLY overview unavailable' }).waitFor()
    for (const label of ['电信', '联通', '移动']) assert.match(await network(label).innerText(), /状态未知/)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Page overflows at ${width}`)
    if (screenshots) await page.screenshot({ fullPage: true, animations: 'disabled', path: resolve(screenshots, `carrier-monitoring-${width}.png`) })
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.deepEqual(external, [])
    receipts.push({ width, writes: writes.length, errors: 0, unexpectedAPI: 0, externalRequests: 0 })
    await context.close()
  }
  console.log(JSON.stringify({ suite: 'carrier-monitoring', receipts }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
