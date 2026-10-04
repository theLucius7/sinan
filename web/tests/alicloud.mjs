import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const results = []
try {
 for (const width of [1440, 390, 340]) {
  const context = await browser.newContext({ viewport: { width, height: 1000 } })
  const page = await context.newPage(), errors = [], unexpected = [], writes = []
  page.on('pageerror', e => errors.push(e.message))
  const now = Math.floor(Date.now() / 1000), month = new Date((now + 28800) * 1000).toISOString().slice(0, 7)
  let overview = { accounts: [], resources: [], operations: [], power_jobs: [], events: [] }, failRead = false, failConfirm = true, failPowerConfirm = true
  const credentialId = 'a0000000-0000-4000-8000-000000000160'
  const powerPolicy = { enabled: false, stop_mode: 'KeepCharging', threshold_action: 'off', limit_gb: 100, threshold_percent: 95, schedule_enabled: false, start_time: '08:00', stop_time: '23:00', utc_offset_minutes: 480, keepalive: false }
  const powerState = { cloud_id: 'i-testonly', region: 'cn-hangzhou', status: 'Running', stopped_mode: 'KeepCharging', charge_type: 'PostPaid', network_type: 'vpc', spot_strategy: 'SpotAsPriceGo', interruption_behavior: 'Stop', public_ips: ['192.0.2.1'], locked: false }
  const snap = { kind: 'ecs', cloud_id: 'i-testonly', region: 'cn-hangzhou', public_ip: '192.0.2.1', bandwidth_mbps: 10, charge_type: 'PayByTraffic', resource_charge_type: 'PostPaid', status: 'Running' }
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method(), body = request.postData() ? request.postDataJSON() : null
    const respond = (json, status = 200) => route.fulfill({ status, json })
    if (path === '/api/dashboard/access') return respond({ authenticated: true, public_dashboard: false })
    if (path === '/api/plugins/alicloud' && method === 'GET') return failRead ? respond({ error: '测试：云状态不可用' }, 503) : respond(overview)
    if (method !== 'GET') writes.push({ path, method, body })
    if (path === '/api/plugins/alicloud/accounts' && method === 'POST') {
      assert.equal(body.auto_enabled, false)
      assert.equal(body.credential_id, credentialId)
      for (const field of ['access_key_id', 'access_key_secret', 'legacy_credentials']) assert.equal(Object.hasOwn(body, field), false, 'New cloud accounts contain only the encrypted credential reference')
      overview.accounts.push({ ...body, access_key_id: undefined, access_key_secret: undefined, id: 'account', revision: 1, balance: { available: '1234.5600', currency: 'USD', queried_at: now }, balance_error: null, error_code: null, traffic_error: null, next_run_at: now + 300, traffic: { queried_at: now, mainland_bytes: '1073741824', overseas_bytes: '2147483648', regions: [{ region: 'cn-hangzhou', bytes: '1073741824' }] }, bill: { month, queried_at: now, usage_micro_gb: 10000000, rows: [{ instance_id: 'test', region: '测试地域', billing_item: '公网流量', product_type: 'cdt', usage: '10', unit: 'GB', amount: '0.00', currency: 'CNY' }] } })
      return respond({ id: 'account' }, 201)
    }
    if (path === '/api/plugins/alicloud/accounts/account' && method === 'PATCH') {
      assert.equal(body.revision, overview.accounts[0].revision)
      for (const field of ['access_key_id', 'access_key_secret']) assert.equal(Object.hasOwn(body, field), false, 'An unchanged credential never replays plaintext')
      if (Object.hasOwn(body, 'credential_id')) assert.equal(body.credential_id, credentialId)
      else assert.equal(body.legacy_credentials, true)
      overview.accounts[0] = { ...overview.accounts[0], ...body, revision: body.revision + 1 }
      return route.fulfill({ status: 204 })
    }
    if (path === '/api/plugins/alicloud/resources' && method === 'POST') {
      assert.equal(body.auto_enabled, false)
      overview.resources.push({ ...body, id: 'resource', revision: 1, snapshot: snap, checked_at: now, error_code: null, power_policy: { ...powerPolicy }, power_state: powerState, power_checked_at: now, manual_hold: false, threshold_hold: false, instance_bill: { month, queried_at: now, rows: [{ item: 'PayAsYouGoBill', amount: '12.3456', currency: 'CNY' }] } })
      return respond({ id: 'resource' }, 201)
    }
    if (path === '/api/plugins/alicloud/resources/resource/preview') {
      assert.equal(method, 'POST'); assert.equal(body.revision, 1)
      const operation = { id: 'operation', resource_id: 'resource', account_revision: overview.accounts[0].revision, resource_revision: overview.resources[0].revision, before_state: snap, target: body.target, source: 'manual', billing_cycle: null, status: 'preview', created_at: now, updated_at: now, expires_at: now + 300, error_code: null, request_id: null }
      overview.operations = [operation]; return respond(operation)
    }
    if (path === '/api/plugins/alicloud/operations/operation/confirm') {
      if (failConfirm) return respond({ error: '测试：预览状态变化，请重试' }, 409)
      overview.operations[0].status = 'uncertain'; overview.operations[0].error_code = 'awaiting_confirmation'
      return respond(overview.operations[0], 202)
    }
    if (path === '/api/plugins/alicloud/operations/operation/dismiss') {
      overview.operations[0].status = 'dismissed'; overview.resources[0].auto_enabled = false; overview.resources[0].power_policy.enabled = false; overview.resources[0].manual_hold = true; overview.resources[0].revision++
      return route.fulfill({ status: 204 })
    }
    if (path === '/api/plugins/alicloud/resources/resource/power-policy') {
      assert.equal(method, 'PATCH'); assert.equal(body.revision, overview.resources[0].revision)
      overview.resources[0].power_policy = body.policy; overview.resources[0].revision++
      return route.fulfill({ status: 204 })
    }
    if (path === '/api/plugins/alicloud/resources/resource/power-preview') {
      assert.equal(body.revision, overview.resources[0].revision)
      const job = { id: 'power', resource_id: 'resource', account_revision: overview.accounts[0].revision, resource_revision: overview.resources[0].revision, action: body.action, stop_mode: body.stop_mode, before_state: powerState, source: 'manual', status: 'preview', created_at: now, expires_at: now + 300, error_code: null, request_id: null }
      overview.power_jobs = [job]; return respond(job)
    }
    if (path === '/api/plugins/alicloud/power-jobs/power/confirm') {
      if (failPowerConfirm) return respond({ error: '测试：启停配置已变化' }, 409)
      overview.power_jobs[0].status = 'uncertain'; overview.power_jobs[0].error_code = 'awaiting_confirmation'
      overview.resources[0].manual_hold = true
      return respond(overview.power_jobs[0], 202)
    }
    if (path === '/api/plugins/alicloud/power-jobs/power/dismiss') {
      overview.power_jobs[0].status = 'dismissed'; overview.resources[0].power_policy.enabled = false; overview.resources[0].revision++
      return route.fulfill({ status: 204 })
    }
    if (path === '/api/plugins/alicloud/resources/resource/power-resume') {
      assert.equal(body.revision, overview.resources[0].revision)
      overview.resources[0].manual_hold = false; return route.fulfill({ status: 204 })
    }
    unexpected.push(`${method} ${path}`); return respond({ error: 'Unexpected request' }, 500)
  })
  await installControlCenterFixtures(page)
  await page.goto(`${origin}/#/plugins/alicloud`)
  await page.getByRole('heading', { name: '阿里云 CDT 与带宽', exact: true }).waitFor()
  await page.getByRole('button', { name: '添加云账号' }).click()
  let dialog = page.getByRole('dialog')
  await dialog.getByLabel('账号名称').fill('测试云账号')
  await dialog.getByLabel(/^云凭据标识/).fill(credentialId)
  assert.equal(await dialog.getByLabel(/^凭据来源/).inputValue(), 'center')
  assert.equal(await dialog.getByLabel(/访问密钥/).count(), 0)
  assert.equal(await dialog.getByLabel('达到阈值时').isChecked(), false)
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  await page.getByRole('heading', { name: '测试云账号' }).waitFor()
  assert.equal((await page.locator('body').innerText()).includes('TEST_ONLY_SECRET'), false)
  await page.getByRole('button', { name: '编辑账号与策略' }).click()
  dialog = page.getByRole('dialog')
  assert.equal(await dialog.getByLabel(/^云凭据标识/).inputValue(), credentialId)
  assert.equal(await dialog.getByLabel(/访问密钥/).count(), 0)
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  // Re-read an existing legacy account, retain both stored credentials without
  // exposing them, then explicitly move it back to the encrypted reference.
  overview.accounts[0].credential_id = null; overview.accounts[0].revision++
  await page.reload()
  await page.getByRole('button', { name: '编辑账号与策略', exact: true }).click()
  dialog = page.getByRole('dialog')
  assert.equal(await dialog.getByLabel(/^凭据来源/).inputValue(), 'legacy')
  assert.equal(await dialog.getByLabel(/^旧兼容访问密钥 ID/).inputValue(), '')
  assert.equal(await dialog.getByLabel(/^旧兼容访问密钥 Secret/).inputValue(), '')
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  const legacyWrite = writes.at(-1).body
  assert.equal(legacyWrite.legacy_credentials, true)
  for (const field of ['credential_id', 'access_key_id', 'access_key_secret']) assert.equal(Object.hasOwn(legacyWrite, field), false)
  await page.getByRole('button', { name: '编辑账号与策略', exact: true }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByLabel(/^凭据来源/).selectOption('center')
  await dialog.getByLabel(/^云凭据标识/).fill(credentialId)
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  assert.equal(overview.accounts[0].credential_id, credentialId)
  await page.getByRole('button', { name: '登记资源', exact: true }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByLabel('资源名称').fill('测试 ECS')
  await dialog.getByLabel('地域标识').fill('cn-hangzhou')
  await dialog.getByLabel('ECS 实例 ID').fill('i-testonly')
  await dialog.getByRole('button', { name: '保存', exact: true }).click()
  await page.getByRole('heading', { name: '测试 ECS' }).waitFor()
  await page.getByRole('button', { name: '调整带宽与计费' }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByLabel('公网出带宽').fill('1')
  await dialog.getByRole('button', { name: '预览变更' }).click()
  const confirm = dialog.getByRole('button', { name: '确认调整并授权扣款' })
  assert.equal(await confirm.isDisabled(), true)
  assert.equal(writes.filter(w => w.path.endsWith('/confirm')).length, 0)
  await dialog.getByLabel('确认此资源与目标配置').check()
  await confirm.click()
  await dialog.getByText('测试：预览状态变化，请重试').waitFor()
  assert.equal(await dialog.getByText('当前配置', { exact: true }).count(), 1)
  failConfirm = false
  await confirm.click()
  await page.getByText('结果待核对', { exact: true }).waitFor()
  assert.equal(await page.getByRole('button', { name: '调整带宽与计费' }).isDisabled(), true)
  await page.getByRole('button', { name: '已人工核对' }).click()
  dialog = page.getByRole('dialog')
  assert.equal(await dialog.getByRole('button', { name: '结束跟踪并暂停资源策略' }).isDisabled(), true)
  await dialog.getByLabel('已核对云端结果，确认结束跟踪').check()
  await dialog.getByRole('button', { name: '结束跟踪并暂停资源策略' }).click()
  await page.getByText('已人工结束跟踪', { exact: true }).waitFor()
  await page.getByRole('button', { name: '配置自动启停' }).click()
  dialog = page.getByRole('dialog')
  assert.equal(await dialog.getByLabel('启用自动启停策略').isChecked(), false)
  await dialog.getByLabel('启用自动启停策略').check()
  await dialog.getByLabel('自动停机模式').selectOption('StopCharging')
  await dialog.getByLabel('流量阈值动作').selectOption('stop')
  await dialog.getByLabel('账号 CDT 月流量额度').fill('100')
  await dialog.getByLabel('触发百分比').fill('95')
  await dialog.getByLabel('每日定时开关机').check()
  await dialog.getByLabel('每日开机时间').fill('23:58')
  await dialog.getByLabel('每日停机时间').fill('08:00')
  await dialog.getByLabel('抢占式实例保活').check()
  if (screenshots) await page.screenshot({ path: `${screenshots}/alicloud-policy-${width}.png`, fullPage: true })
  await dialog.getByRole('button', { name: '保存启停策略' }).click()
  await dialog.waitFor({ state: 'hidden' })
  assert.equal(overview.resources[0].power_policy.threshold_percent, 95)
  await page.getByRole('button', { name: '停机', exact: true }).click()
  dialog = page.getByRole('dialog')
  await dialog.getByRole('button', { name: '预览启停操作' }).click()
  const powerConfirm = dialog.getByRole('button', { name: '确认执行启停' })
  assert.equal(await powerConfirm.isDisabled(), true)
  assert.equal(writes.filter(w => w.path === '/api/plugins/alicloud/power-jobs/power/confirm').length, 0)
  await dialog.getByLabel('已核对实例，确认执行').check()
  await powerConfirm.click(); await dialog.getByText('测试：启停配置已变化').waitFor()
  failPowerConfirm = false; await powerConfirm.click()
  await dialog.waitFor({ state: 'hidden' })
  await page.getByRole('button', { name: '核对并结束跟踪' }).waitFor()
  assert.equal(await page.getByRole('button', { name: '开机', exact: true }).isDisabled(), true)
  assert.equal(await page.getByRole('button', { name: '调整带宽与计费' }).isDisabled(), true)
  await page.getByRole('button', { name: '核对并结束跟踪' }).click()
  dialog = page.getByRole('dialog'); await dialog.getByRole('button', { name: '结束跟踪', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  await page.getByRole('button', { name: '恢复自动开机', exact: true }).click()
  dialog = page.getByRole('dialog'); await dialog.getByRole('button', { name: '恢复自动开机', exact: true }).click()
  await dialog.waitFor({ state: 'hidden' })
  assert.equal(overview.resources[0].manual_hold, false)
  assert.equal(await page.getByText('1234.5600 USD', { exact: true }).count(), 1)
  const overflow = await page.evaluate(() => ({ viewport: innerWidth, width: document.documentElement.scrollWidth, elements: [...document.querySelectorAll('body *')].map(el => ({ tag: el.tagName, class: el.className, width: el.getBoundingClientRect().width, right: el.getBoundingClientRect().right })).filter(el => el.right > innerWidth + 1).slice(0, 15) }))
  if (overflow.width > width) { console.log(JSON.stringify(overflow)); await page.screenshot({ path: `/tmp/sinan-alicloud-overflow-${width}.png`, fullPage: true }) }
  assert.equal(overflow.width <= width, true)
  if (screenshots) await page.screenshot({ path: `${screenshots}/alicloud-${width}.png`, fullPage: true })
  failRead = true; await page.getByRole('button', { name: '刷新', exact: true }).click()
  await page.getByText('测试：云状态不可用').waitFor()
  assert.equal(await page.getByRole('button', { name: '添加云账号' }).isDisabled(), true)
  assert.equal(await page.getByRole('button', { name: '调整带宽与计费' }).isDisabled(), true)
  assert.equal(await page.getByRole('button', { name: '开机', exact: true }).isDisabled(), true)
  assert.equal(await page.getByRole('button', { name: '配置自动启停' }).isDisabled(), true)
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  results.push({ width, writes: writes.length, passed: true })
  await context.close()
 }
 console.log(JSON.stringify(results))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
