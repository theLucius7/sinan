import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Read final assets with scoped private fixtures; no real network target,
// diagnostic start, provider mutation, notification or credential is used.
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
    const context = await browser.newContext({ viewport: { width, height: 950 }, serviceWorkers: 'block' })
    const page = await context.newPage()
    page.setDefaultTimeout(10000)
    const errors = [], external = [], requests = [], sideEffects = []
    page.on('pageerror', error => errors.push(error.message))
    context.on('request', request => { if (new URL(request.url()).origin !== origin) external.push(request.url()) })
    await context.route('**/*', route => new URL(route.request().url()).origin === origin ? route.continue() : route.abort())
    const now = Math.floor(Date.now() / 1000)
    const target = '11111111-1111-4111-8111-111111111111', run = '22222222-2222-4222-8222-222222222222'
    const account = '33333333-3333-4333-8333-333333333333', intent = '44444444-4444-4444-8444-444444444444'
    const check = { kind: 'tcp', target_id: target, port: 443, family: 'ipv4', samples: 1 }
    const raw = { schema: 1, source: '服务器 7', target: 'target.example.test', method: 'tcp', tool: 'builtin', tool_version: '1.0.0',
      parameters: check, collected_at: now - 20, status: 'unknown', data: { reason: 'TEST_ONLY 未取得实际连接证据' }, raw_output: '', error: null,
      cleanup: { process_stopped: false, files_removed: false, listeners_closed: false } }
    const report = { id: run, status: 'failed', error: null, physical_acceptance: 'pending',
      summary: { step_count: 1, result_count: 1, succeeded: 0, failed: 0, cleanup_pending: 1 },
      snapshot: { plan: { name: 'TEST_ONLY 未确认报告', steps: [{ name: 'TEST_ONLY TCP', source: { kind: 'server', server_id: 7 }, check }] } },
      results: [{ id: '55555555-5555-4555-8555-555555555555', step_index: 0, source_server: 7, role: 'source:7', job_id: intent,
        status: 'unknown', observation: raw, cleanup_confirmed: false, cleanup_origin: 'agent', error: null,
        sections: [{ name: 'workbench_scope', text: 'TEST_ONLY 原任务输入与未知证据保持', complete: true, collected_at: now - 20 }] }] }
    const frozenReport = JSON.stringify(report)
    const dns = { id: intent, status: 'unknown', error_code: 'intent_committed', request: { operation: 'create' }, previous: null,
      observed: null, occurred_at: now - 15 }
    let reconciliations = 0
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), method = request.method(), path = url.pathname
      assert.equal(url.origin, origin); requests.push({ method, path })
      let value
      if (method === 'GET' && path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (method === 'GET' && path === '/api/control-center/me') value = { id: 1, role: 'viewer', display_name: 'TEST_ONLY 限定读取', all_servers: false,
        capabilities: ['diagnostics:read', 'dns:read'], token_capabilities: null, token_servers: null }
      else if (method === 'GET' && path.startsWith('/api/control-center/preferences/')) value = { value: path.endsWith('/recent') || path.endsWith('/favorite') ? [] : null, revision: 0, updated_at: 0 }
      else if (method === 'GET' && path === '/api/network-workbench/targets') value = [{ id: target, name: 'TEST_ONLY 授权目标', host: 'target.example.test', region: 'TEST_ONLY 地区', carrier: 'TEST_ONLY 运营商', purpose: '隔离读数', authorization: 'TEST_ONLY 原固定授权', authorized_until: now + 300 }]
      else if (method === 'GET' && ['/api/network-workbench/tools', '/api/network-workbench/providers', '/api/network-workbench/plans'].includes(path)) value = []
      else if (method === 'GET' && path === '/api/network-workbench/runs') value = [{ id: run, name: 'TEST_ONLY 未确认报告', status: 'failed', current_step: 0, error: null, created_at: now - 20 }]
      else if (method === 'GET' && path === `/api/network-workbench/runs/${run}`) value = report
      else if (method === 'GET' && path === '/api/plugins/ddns/rules') value = []
      else if (method === 'GET' && path === '/api/plugins/ddns/servers') value = [{ id: 7, name: 'TEST_ONLY DNS服务器', enabled: true }]
      else if (method === 'GET' && path === '/api/plugins/ddns/accounts') value = [{ id: account, revision: 3, record_management_available: true, unavailable_reason: null,
        config: { name: 'TEST_ONLY 私有DNS账号', provider: 'cloudflare', enabled: true, credential_id: '66666666-6666-4666-8666-666666666666', zone_ids: ['TEST_ONLY_ZONE'], server_ids: [7], region: null } }]
      else if (method === 'GET' && path === `/api/plugins/ddns/accounts/${account}/records`) {
        assert.equal(url.searchParams.get('zone_id'), 'TEST_ONLY_ZONE'); assert.equal(url.searchParams.get('page'), '1')
        value = { records: [], pagination: { total_pages: 1 }, checked_at: now }
      } else if (method === 'GET' && path === `/api/plugins/ddns/accounts/${account}/records/history`) value = [dns]
      else if (method === 'GET' && path === `/api/plugins/ddns/accounts/${account}/observations`) value = []
      else if (method === 'POST' && path === `/api/plugins/ddns/accounts/${account}/records/${intent}/reconcile`) {
        assert.equal(request.postData(), null); reconciliations++
        dns.status = 'observed'; dns.error_code = 'write_ownership_unknown'
        dns.observed = { id: 'TEST_ONLY found record', name: 'target.example.test', type: 'A', content: '192.0.2.1', ttl: 300 }
        value = { status: 'observed', error_code: 'write_ownership_unknown' }
      } else {
        if (method !== 'GET') sideEffects.push({ method, path })
        errors.push(`Unexpected API: ${method} ${path}`)
        return route.fulfill({ status: 404, json: { error: 'Unexpected API' } })
      }
      await route.fulfill({ json: value })
    })
    await page.goto(`${origin}/#/network-workbench`)
    const workbench = page.locator('section.network-workbench')
    await workbench.getByRole('heading', { name: '网络检测与验机', exact: true }).waitFor()
    await workbench.getByText('当前权限不包含服务器列表读取；可使用面板来源或当前服务器详情上下文。', { exact: true }).waitFor()
    assert.equal(await workbench.getByRole('button', { name: '预览后提交执行', exact: true }).isDisabled(), true)
    await workbench.getByRole('button', { name: '授权目标', exact: true }).click()
    await workbench.getByText('TEST_ONLY 原固定授权', { exact: false }).waitFor()
    await workbench.getByLabel('筛选地区', { exact: true }).fill('不存在的地区')
    await workbench.getByText('当前筛选 0 / 1 个获准目标；计划中的已选目标不会随筛选改变。', { exact: true }).waitFor()
    await workbench.getByLabel('筛选地区', { exact: true }).fill('')
    await workbench.getByRole('button', { name: '任务与报告', exact: true }).click()
    await workbench.getByRole('button', { name: /TEST_ONLY 未确认报告 · failed/ }).click()
    const resultRow = workbench.getByRole('row').filter({ hasText: 'TEST_ONLY TCP' })
    await resultRow.getByText('unknown', { exact: true }).waitFor()
    await resultRow.getByText('等待设备确认', { exact: true }).waitFor()
    assert.equal(await resultRow.getByText('已确认', { exact: true }).count(), 0)
    const originalDetails = workbench.locator('details').filter({ has: page.locator('summary', { hasText: '第1步 · source:7 · 参数、原始指标与环境' }) })
    await originalDetails.locator('summary').first().click()
    await originalDetails.getByText('TEST_ONLY 未取得实际连接证据', { exact: false }).waitFor()
    assert.equal(JSON.stringify(report), frozenReport)
    assert.equal(requests.some(request => request.path === '/api/servers'), false)
    assert.equal(requests.some(request => request.method !== 'GET'), false)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await page.goto(`${origin}/#/plugins/ddns`)
    await page.getByRole('heading', { name: 'DNS 账号与普通记录', exact: true }).waitFor()
    await page.getByText('TEST_ONLY 私有DNS账号 · Cloudflare', { exact: true }).waitFor()
    await page.getByRole('button', { name: '记录、传播观测与历史', exact: true }).click()
    const dialog = page.getByRole('dialog', { name: 'DNS 记录 · TEST_ONLY 私有DNS账号', exact: true })
    await dialog.getByRole('heading', { name: '记录变更历史', exact: true }).waitFor()
    const history = dialog.locator('article.ddns-rule').filter({ has: page.getByRole('button', { name: '只读核对远端结果', exact: true }) })
    await history.getByText('结果未知', { exact: true }).waitFor()
    for (const expected of [1, 2]) {
      const response = page.waitForResponse(response => response.request().method() === 'POST'
        && new URL(response.url()).pathname === `/api/plugins/ddns/accounts/${account}/records/${intent}/reconcile`)
      await history.getByRole('button', { name: '只读核对远端结果', exact: true }).click()
      await response
      await dialog.getByText('远端符合期望，但新建记录的归属无法确认，禁止自动回退删除。', { exact: true }).waitFor()
      await history.getByText('期望值已观测，归属未确认', { exact: true }).waitFor()
      assert.equal(reconciliations, expected)
      assert.equal(await dialog.getByRole('button', { name: '核对远端并回退此变更', exact: true }).count(), 0)
      assert.equal(await dialog.getByText('提供方已确认', { exact: true }).count(), 0)
    }
    assert.equal(dns.status, 'observed'); assert.equal(dns.previous, null)
    assert.equal(requests.filter(request => request.method !== 'GET').length, 2)
    assert.deepEqual(sideEffects, []); assert.deepEqual(external, []); assert.deepEqual(errors, [])
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    results.push({ width, private_api_requests: requests.length, readonly_reconciliations: reconciliations, provider_side_effects: 0, external_requests: 0, page_errors: 0, original_unknown_preserved: true })
    await context.close()
  }
  console.log(JSON.stringify({ status: 'passed', scope: 'workbench scoped reads and DNS unresolved intent read-only observation desktop/mobile', results }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
