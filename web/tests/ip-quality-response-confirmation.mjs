import { installControlCenterFixtures } from './control-center-fixtures.mjs'
// Actual dist over private loopback HTTP. Fixtures are panel API outputs, not raw provider responses.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const now = Math.floor(Date.now() / 1000), successAt = now - 120, freshUntil = successAt + 86400
// Documentation addresses represent the server-classified public group; no provider is contacted.
const ip = '192.0.2.1', scoreLabel = '欺诈评分（上游原值）', proxyLabel = '代理'
const schemaError = '质量查询响应没有可信的有效字段或未确认成功，此数据库信息未知'
const officialReason = '未配置 SINAN_ABUSEIPDB_API_KEY，正式接口未启用，信息未知'
const nodeReason = '正式节点认证适配与完整工具链授权、验收尚未就绪，节点出口和流媒体信息未知；面板正式接口凭证仅用于面板查询'
const databases = [['maxmind', 'MaxMind 地理与 ASN'], ['ipapi', 'IPAPI'], ['scamalytics', 'Scamalytics'], ['abuseipdb', 'AbuseIPDB'], ['ip2location', 'IP2Location'], ['ipdata', 'IPData'], ['ipqualityscore', 'IPQualityScore']]
const zeroFields = [{ label: scoreLabel, kind: 'score', value: 0 }, { label: proxyLabel, kind: 'boolean', value: false }]
const savedFields = [{ label: scoreLabel, kind: 'score', value: 17 }, { label: proxyLabel, kind: 'boolean', value: true }]
const officialFields = [{ label: 'Tor', kind: 'boolean', value: false }, { label: '滥用置信度（0–100 原值）', kind: 'score', value: 0 }]
const failure = (kind, message, httpStatus = null, attemptedAt = now, elapsed = 21) => ({ kind, message, http_status: httpStatus, attempted_at: attemptedAt, elapsed_ms: elapsed })

function failedDatabase(database, label, problem = failure('schema_mismatch', schemaError)) {
  return { database, label, status: 'failed', fields: [], error: problem.message, provider: 'check-place', target_ip: ip,
    attempted_at: problem.attempted_at, elapsed_ms: problem.elapsed_ms, error_kind: problem.kind, http_status: problem.http_status,
    last_attempt_at: problem.attempted_at, last_success_at: null, fresh_until: null, last_error: problem,
    historical: false, available: true, unavailable_reason: null }
}
function successfulDatabase(fields = zeroFields) {
  return { ...failedDatabase('ipqualityscore', 'IPQualityScore'), status: 'succeeded', fields: structuredClone(fields),
    error: null, error_kind: null, http_status: null, last_error: null, last_success_at: successAt, fresh_until: freshUntil }
}
function quality(entries, provider = 'check-place') {
  const succeeded = entries.filter(entry => entry.status === 'succeeded').length
  const times = entries.map(entry => entry.last_success_at).filter(value => value !== null)
  const until = entries.every(entry => entry.fields.length && entry.fresh_until !== null) ? Math.min(...entries.map(entry => entry.fresh_until)) : null
  return { ip, provider, checked_at: now, expires_at: until ?? 0,
    status: succeeded === 0 ? 'failed' : succeeded === entries.length ? 'succeeded' : 'partial', databases: entries,
    last_attempt_at: Math.max(...entries.map(entry => entry.last_attempt_at ?? 0)) || null,
    last_success_at: times.length ? Math.max(...times) : null, fresh_until: until,
    last_error: Object.fromEntries(entries.filter(entry => entry.last_error).map(entry => [entry.database, entry.last_error])) }
}
function checkPlace(selected) {
  return quality(databases.map(([database, label]) => database === 'ipqualityscore' ? selected : failedDatabase(database, label)))
}
function providers(officialEnabled = false) {
  return [
    { provider: 'check-place', label: 'check-place 聚合入口', kind: 'aggregator', execution: 'panel', enabled: true, reason: null, databases: databases.map(([database, label]) => ({ database, label })) },
    { provider: 'abuseipdb-api', label: 'AbuseIPDB 官方接口', kind: 'credential_api', execution: 'panel', enabled: officialEnabled, reason: officialEnabled ? null : officialReason, databases: [{ database: 'abuseipdb-v2', label: 'AbuseIPDB 官方 IP 查询' }] },
    { provider: 'ipquality-node', label: 'IPQuality 节点自查', kind: 'node_self', execution: 'node', enabled: false, reason: nodeReason, databases: [] },
  ]
}
function view(results, officialEnabled = false) {
  return { ip_addresses: [ip], public_ip_addresses: [ip], private_ip_addresses: [], quality: results, providers: providers(officialEnabled) }
}

// fields.rs filters these raw fields/statuses. query_database then returns SchemaMismatch;
// persist/read return fields:[], failed, no success time/freshness and expires_at:0.
// The browser receives those normalized outputs. Rust HTTP/PostgreSQL regressions cover parsing.
const invalidRawCases = [
  ['empty-object', {}], ['missing-known-fields', { unrelated: 'fixture' }],
  ['null-fields', { fraud_score: null, proxy: null }],
  ['object-fields', { fraud_score: {}, proxy: {} }], ['array-fields', { fraud_score: [], proxy: [] }],
  ['wrong-score-bool-and-proxy-text', { fraud_score: true, proxy: 'false' }],
  ['blank-score-and-proxy-number', { fraud_score: '', proxy: 0 }],
  ['whitespace-score', { fraud_score: '   ', proxy: '   ' }],
  ['explicit-failure-defaults', { success: false, fraud_score: 0, proxy: false }],
  ['uncertain-success', { success: 'true', fraud_score: 0, proxy: false }],
  ['failed-status-defaults', { status: 'failed', fraud_score: 0, proxy: false }],
  ['explicit-errors-defaults', { errors: [{ detail: 'fixture' }], fraud_score: 0, proxy: false }],
]
const legacyCases = [
  ['legacy-null', null, null], ['legacy-object', {}, {}], ['legacy-array', [], []],
  ['legacy-wrong-scalars', true, 0], ['legacy-blank', '', '   '],
  ['legacy-text-proxy', '17', 'false'],
]
const sourceProblems = [
  failure('http_403', '查询入口拒绝访问（HTTP 403），此数据库信息未知', 403),
  failure('http_429', '查询入口限制请求频率（HTTP 429），此数据库信息未知', 429),
  failure('timeout', '质量查询超时', null, now, 6001),
]
const errorLabels = { schema_mismatch: '字段不匹配', http_403: '访问被拒绝（403）', http_429: '请求被限流（429）', timeout: '查询超时' }
let state = { view: view([]), refreshView: null }
const requests = [], unexpected = []
const server = createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1'), path = url.pathname
  if (path.startsWith('/api/')) {
    requests.push({ method: request.method, path })
    let value
    if (request.method === 'GET' && path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
    else if (request.method === 'GET' && path === '/api/me') value = {}
    else if (request.method === 'GET' && path === '/api/servers/1') value = { id: 1, name: 'IP 响应确认验收夹具', online: true, static_info: {}, latest_metrics: {}, capabilities: [] }
    else if (request.method === 'GET' && path === '/api/servers/1/ip-quality') value = state.view
    else if (request.method === 'POST' && path === '/api/servers/1/ip-quality/refresh' && state.refreshView) {
      state.view = state.refreshView; state.refreshView = null; value = state.view.quality
    } else { unexpected.push(`${request.method} ${path}`); response.writeHead(404, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: '未知夹具接口' })); return }
    response.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(value))
    return
  }
  const file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []

try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } }), page = await context.newPage()
    const pageErrors = [], external = [], cases = []
    page.on('pageerror', error => pageErrors.push(error.message))
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin === origin) return route.continue()
      external.push(route.request().url()); return route.abort()
    })
    async function load(fixture) {
      state = { view: fixture, refreshView: null }
      const answer = page.waitForResponse(response => new URL(response.url()).pathname === '/api/servers/1/ip-quality' && response.request().method() === 'GET')
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#/servers/1/ip-info`)
      await page.reload()
      assert.deepEqual(await (await answer).json(), fixture)
      await page.getByRole('heading', { name: '服务器 IP 信息', exact: true }).waitFor()
      await page.getByText(ip, { exact: true }).waitFor()
    }
    async function chapter(label = 'IPQualityScore') {
      const value = page.locator('details.quality-database').filter({ has: page.locator('summary').getByText(label, { exact: true }) })
      await value.locator('summary').waitFor()
      await value.locator('summary').click()
      return value
    }
    async function field(value, label) { return value.locator('dl > div').filter({ has: page.locator('dt').getByText(label, { exact: true }) }).locator('dd').innerText() }
    async function unknown(value, problem) {
      assert.match(await value.locator('summary').innerText(), /未知/)
      assert.equal(await value.locator('dl').count(), 0)
      assert(await value.getByText('没有已保存的成功结果，信息未知。', { exact: true }).isVisible())
      assert(await value.getByText(problem.message, { exact: true }).isVisible())
      const text = await value.innerText()
      assert(text.includes(`当前失败类别：${errorLabels[problem.kind]}`))
      assert(text.includes(`目标 IP：${ip}`))
      assert(text.includes(`耗时 ${problem.elapsed_ms} 毫秒`))
      if (problem.http_status !== null) assert(text.includes(`HTTP ${problem.http_status}`))
      assert.equal(await page.locator('.quality-result > .quality-summary .badge').innerText(), '质量未知')
      assert.equal(await value.getByText('本次已查询', { exact: true }).count(), 0)
    }
    for (const [name] of invalidRawCases) {
      const problem = failure('schema_mismatch', schemaError)
      await load(view([checkPlace(failedDatabase('ipqualityscore', 'IPQualityScore', problem))]))
      await unknown(await chapter(), problem)
      cases.push(name)
    }

    // Old payloads with a missing dataset row may bypass cache.rs field normalization.
    // This compatibility path uses registered Chinese labels and kind:null, not new API output.
    for (const [name, score, proxy] of legacyCases) {
      const fields = [{ label: '国家代码', kind: null, value: 'ZZ' }, { label: scoreLabel, kind: null, value: score }, { label: proxyLabel, kind: null, value: proxy }]
      const legacy = { ...successfulDatabase(fields), attempted_at: null, elapsed_ms: null, last_attempt_at: null, last_success_at: null, fresh_until: null }
      await load(view([quality([legacy])]))
      const value = await chapter()
      assert.equal(await field(value, '国家代码'), 'ZZ')
      assert.equal(await field(value, scoreLabel), name === 'legacy-text-proxy' ? '17' : '未知')
      assert.equal(await field(value, proxyLabel), '未知')
      assert.match(await value.locator('summary').innerText(), /历史结果/)
      assert((await value.innerText()).includes('旧记录未保存成功时间'))
      assert.equal(await value.getByText('本次已查询', { exact: true }).count(), 0)
      cases.push(name)
    }

    await load(view([checkPlace(successfulDatabase())]))
    let value = await chapter()
    assert.equal(await field(value, scoreLabel), '0'); assert.equal(await field(value, proxyLabel), '否')
    assert.match(await value.locator('summary').innerText(), /本次已查询/)
    assert((await value.innerText()).includes('最近成功结果'))
    assert.equal(await page.locator('.quality-result > .quality-summary .badge').innerText(), '1 / 7 项数据有当前成功结果')
    cases.push('confirmed-zero-false')

    // A partially valid raw response retains only its valid field; wrong fields do not become defaults.
    await load(view([checkPlace(successfulDatabase([{ label: '国家代码', kind: 'country_code', value: 'ZZ' }]))]))
    value = await chapter()
    assert.equal(await field(value, '国家代码'), 'ZZ')
    assert.equal(await value.locator('dt').getByText(scoreLabel, { exact: true }).count(), 0)
    assert.equal(await value.locator('dt').getByText(proxyLabel, { exact: true }).count(), 0)
    assert.match(await value.locator('summary').innerText(), /本次已查询/)
    cases.push('partially-valid-response')

    const official = { ...successfulDatabase(officialFields), database: 'abuseipdb-v2', label: 'AbuseIPDB 官方 IP 查询', provider: 'abuseipdb-api' }
    await load(view([quality([official], 'abuseipdb-api')], true))
    value = await chapter(official.label)
    assert.equal(await field(value, '滥用置信度（0–100 原值）'), '0'); assert.equal(await field(value, 'Tor'), '否')
    assert.match(await value.locator('summary').innerText(), /本次已查询/)
    cases.push('official-confirmed-zero-false')

    for (const problem of sourceProblems) {
      await load(view([checkPlace(failedDatabase('ipqualityscore', 'IPQualityScore', problem))]))
      await unknown(await chapter(), problem)
      cases.push(`${problem.kind}-without-history`)
    }
    for (const problem of [...sourceProblems, failure('schema_mismatch', schemaError)]) {
      await load(view([checkPlace(successfulDatabase(savedFields))]))
      const oldSuccess = await page.evaluate(value => new Date(value * 1000).toLocaleString('zh-CN', { hour12: false }), successAt)
      const historical = { ...failedDatabase('ipqualityscore', 'IPQualityScore', problem), fields: structuredClone(savedFields), last_success_at: successAt, fresh_until: freshUntil, historical: true }
      const fixture = view([checkPlace(historical)]), before = requests.filter(request => request.method === 'POST').length
      state.refreshView = fixture
      const readback = page.waitForResponse(response => new URL(response.url()).pathname === '/api/servers/1/ip-quality' && response.request().method() === 'GET')
      await page.getByRole('button', { name: '刷新 IP 质量', exact: true }).click()
      assert.deepEqual(await (await readback).json(), fixture)
      value = await chapter()
      await value.getByText(problem.message, { exact: true }).waitFor()
      assert.equal(await field(value, scoreLabel), '17'); assert.equal(await field(value, proxyLabel), '是')
      assert.match(await value.locator('summary').innerText(), /历史结果/)
      assert.equal(await page.locator('.quality-result > .quality-summary .badge').innerText(), '当前没有有效成功结果 · 1 项历史结果')
      const text = await value.innerText()
      assert(text.includes('正在显示历史结果')); assert(text.includes(`上次成功于 ${oldSuccess}`))
      assert(text.includes(`当前失败类别：${errorLabels[problem.kind]}`)); assert(text.includes(problem.message))
      assert.equal(requests.filter(request => request.method === 'POST').length, before + 1)
      cases.push(`${problem.kind}-preserves-history-after-refresh`)
    }

    const expired = { ...successfulDatabase(), fresh_until: now - 1, historical: true }
    await load(view([checkPlace(expired)])); value = await chapter()
    assert.equal(await field(value, scoreLabel), '0'); assert.equal(await field(value, proxyLabel), '否')
    assert.match(await value.locator('summary').innerText(), /历史结果/)
    assert((await value.innerText()).includes('数据已过期'))
    cases.push('expired-success-is-historical')

    const disabled = { ...official, available: false, unavailable_reason: officialReason, historical: true }
    await load(view([quality([disabled], 'abuseipdb-api')]))
    value = await chapter(official.label)
    assert.equal(await field(value, '滥用置信度（0–100 原值）'), '0'); assert.equal(await field(value, 'Tor'), '否')
    assert.match(await value.locator('summary').innerText(), /历史结果/)
    assert((await value.innerText()).includes(`入口当前不可用：${officialReason}；已保存字段仅作为历史结果。`))
    assert.equal(await value.getByText('本次已查询', { exact: true }).count(), 0)
    assert.equal(await value.getByText(/当前失败类别/).count(), 0)
    cases.push('disabled-source-preserves-success-as-history')

    const writes = requests.filter(request => request.method !== 'GET').length
    await load(view([]))
    const providerCards = page.locator('.quality-body > .quality-databases > .quality-database')
    for (const [label, reason] of [['AbuseIPDB 官方接口', officialReason], ['IPQuality 节点自查', nodeReason]]) {
      const card = providerCards.filter({ has: page.getByText(label, { exact: true }) })
      assert(await card.getByText('未启用 · 信息未知', { exact: true }).isVisible())
      assert(await card.getByText(reason, { exact: true }).isVisible())
    }
    assert.equal(await page.locator('.quality-result').count(), 0)
    assert(await page.getByText('尚未查询质量。点击“刷新 IP 质量”查询已启用入口。', { exact: true }).isVisible())
    assert(await page.getByText('流媒体解锁：未知。当前出口尚未确认，不能据此判断流媒体是否解锁。', { exact: true }).isVisible())
    assert(await page.getByRole('button', { name: '运行节点出口自查', exact: true }).isDisabled())
    assert.equal(requests.filter(request => request.method !== 'GET').length, writes)
    cases.push('disabled-and-unlicensed-without-history-send-nothing')

    assert.deepEqual(pageErrors, []); assert.deepEqual(external, []); assert.deepEqual(unexpected, [])
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    results.push({ width, cases, normalizedRawCases: invalidRawCases.length, legacyCompatibilityCases: legacyCases.length,
      browserErrors: pageErrors.length, externalRequests: external.length, unexpectedApis: unexpected.length })
    await context.close()
  }
  console.log(JSON.stringify({ results, rawFixtureInputs: invalidRawCases, loopbackHttpRequests: requests.length,
    refreshPosts: requests.filter(request => request.method === 'POST').length }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
