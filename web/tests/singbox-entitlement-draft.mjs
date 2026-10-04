import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// TEST_ONLY read-only resources; no device execution or secret template content is claimed.
const diagnosisFixture = user => ({ user_id: user.id, account: { user_id: user.id, name: user.name, portal_created: false, keys: 0, active_sessions: 0, activation_expires_at: null },
  subscription: { status: 'empty', message: 'TEST_ONLY 真实设备状态未验证。', granted_nodes: 0, ready_managed_nodes: 0, ready_external_nodes: 0 },
  permissions: [], external_authorizations: [], ledger: [], quota_credits: [], package_history: [], rotations: [], events: [],
  limitations: { credentials_read: { available: false, reason: 'TEST_ONLY 敏感内容未读取；此处仅为独立只读诊断快照。' } } })
const templateFixture = { template: null, definition_redacted: false, credential_access_reason: 'TEST_ONLY 完整模板未读取。', supported_client: 'singbox', supported_version: '1.14.2', schema_validation: true, runtime_validation: false, limitations: 'TEST_ONLY 没有保存的模板，未执行真实客户端验证。' }

// Serve the actual built dist; all business requests use private API fixtures.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(dist, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})

let browser
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  const origin = `http://127.0.0.1:${server.address().port}`
  for (const width of [1280, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    const errors = [], writes = [], policyReads = [], usageReads = [], mutations = [], groupWrites = [], userWrites = [], accessWrites = []
    const failures = new Set(), heldReads = new Map(), directIds = new Set()
    const previews = [], applications = [], operationSnapshots = new Map()
    let previewSequence = 0, operationRevision = 0, heldPreview = null
    const prefix = '/api/plugins/sing-box'
    let groupIds = [1], packageId = 1
    let chainEntries = []
    const policies = [
      { id: 1, name: '原策略', node_ids: [1], chain_ids: [], member_count: 1 },
      { id: 2, name: '新策略', node_ids: [2], chain_ids: [], member_count: 0 },
    ]
    const packages = [
      { id: 1, name: '原套餐', monthly_bytes: '1073741824', reset_day: 1, reset_hour: 0, reset_minute: 0, timezone: 'UTC', duration_days: 30 },
      { id: 2, name: '新套餐', monthly_bytes: '2147483648', reset_day: 15, reset_hour: 8, reset_minute: 30, timezone: 'UTC', duration_days: 60 },
    ]
    const nodes = [1, 2].map(id => ({ id, name: `节点 ${id}`, server_id: id, protocol: 'vless-reality', public_host: 'proxy.example.com', port: 20000 + id, sni: 'www.example.com', public_key: 'TEST_ONLY', short_id: '0123abcd' }))
    const servers = [1, 2].map(id => ({ id, name: `服务器 ${id}`, enabled: true, online: false, read_only: false }))
    const proxyResources = () => {
      const missingIds = [...new Set(chainEntries.flatMap(chain => [chain.entry_node_id, chain.exit_node_id]))].filter(id => !nodes.some(node => node.id === id))
      const retired = missingIds.map((id, index) => ({ id, name: `已删除历史节点 ${id}`, server_id: index % 2 + 1, protocol: 'vless-reality', public_host: 'retired.example.com', port: 20000 + id, sni: 'www.example.com', node_deleted: true }))
      return flatResourceFixtures([...nodes, ...retired], servers, chainEntries)
    }
    const user = { id: 1, name: '测试代理用户', subscription_token: 'TEST_ONLY', subscription_url: 'https://panel.example.com/s/TEST_ONLY' }
    const usage = { uplink: '10', downlink: '20', total: '30', by_user: [{ user_id: 1, name: user.name, deleted: false, uplink: '10', downlink: '20' }], by_node: [] }
    const ledger = JSON.stringify(usage)
    const operationState = () => JSON.stringify({ operationRevision, groupIds, packageId, policies, packages, nodes, chainEntries, user, usage })
    const entitlement = () => ({
      user_id: 1, package_group_id: packageId, package_name: packages.find(p => p.id === packageId).name,
      ...packages.find(p => p.id === packageId), starts_at: 1790812800, expires_at: 1795996800,
      cycle_start: 1790812800, next_reset: 1793491200, used_bytes: '30', status: 'active', allowed: true,
    })
    const enabled = async locator => {
      await locator.waitFor()
      const deadline = Date.now() + 5000
      while (await locator.isDisabled() && Date.now() < deadline) await page.waitForTimeout(25)
      assert.equal(await locator.isDisabled(), false)
    }
    const failedRead = async (pathname, trigger) => {
      const response = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'GET' && response.status() === 500)
      failures.add(pathname)
      if (trigger) await trigger()
      await response
      await page.getByRole('alert').filter({ hasText: `夹具读取失败：${pathname}` }).first().waitFor()
    }
    const recoverRead = async (pathname, retry, pending) => {
      failures.delete(pathname)
      let enter, release
      const arrived = new Promise(resolve => { enter = resolve })
      const released = new Promise(resolve => { release = resolve })
      heldReads.set(pathname, { enter, released })
      const response = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'GET' && response.status() === 200)
      // Some editors use the page refresh callback rather than a dialog retry button.
      void response.catch(() => {})
      let triggered = false
      try {
        if (typeof retry === 'function') await retry()
        else if (retry) await retry.click()
        triggered = true
        await arrived; await page.waitForTimeout(25); await pending()
      } finally { release(); if (triggered) await response }
    }
    const blockedForm = async (dialog, label) => {
      assert.equal(await dialog.getByRole('button', { name: label, exact: true }).isDisabled(), true)
      assert.equal(await dialog.getByRole('button', { name: '取消', exact: true }).isDisabled(), false)
      const count = mutations.length
      await dialog.locator('form').evaluate(form => form.requestSubmit())
      await page.waitForTimeout(75)
      assert.equal(mutations.length, count, 'a submit event must not write an invalid or refreshing snapshot')
    }
    const blockedPolicySave = async save => {
      assert.equal(await save.isDisabled(), true)
      const count = mutations.length
      await save.evaluate(button => {
        const disabled = button.disabled
        try { button.disabled = false; button.click() } finally { button.disabled = disabled }
        const key = Object.keys(button).find(key => key.startsWith('__reactProps$'))
        const props = key && button[key]
        if (typeof props?.onClick !== 'function') throw new Error('actual policy assignment callback was not found in this dist')
        props.onClick()
      })
      await page.waitForTimeout(75)
      assert.equal(mutations.length, count, 'stale and pending assignment callbacks must send zero preview or apply requests')
    }
    const reviewDialog = operation => page.getByRole('dialog').filter({ has: page.getByRole('heading', { name: operation === 'policy_batch' ? '策略组分配预览' : '套餐更换预览', exact: true }) })
    const assertUnconfirmed = async review => {
      const apply = review.getByRole('button', { name: '确认应用', exact: true })
      assert.equal(await apply.isDisabled(), true)
      const count = applications.length
      await apply.evaluate(button => { const disabled = button.disabled; try { button.disabled = false; button.click() } finally { button.disabled = disabled } })
      assert.equal(applications.length, count, 'a forced callback cannot apply an unconfirmed or pending preview')
    }
    const confirmReview = async review => {
      await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).check()
      await review.getByRole('button', { name: '确认应用', exact: true }).click()
    }
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), pathname = url.pathname, method = request.method()
      if (method !== 'GET') mutations.push({ pathname, method, payload: request.postDataJSON() })
      if (method === 'GET' && failures.has(pathname)) { await route.fulfill({ status: 500, json: { error: `夹具读取失败：${pathname}` } }); return }
      if (method === 'GET' && heldReads.has(pathname)) {
        const gate = heldReads.get(pathname)
        heldReads.delete(pathname); gate.enter(); await gate.released
      }
      let value
      if (pathname === '/api/dashboard/access' && method === 'GET') value = { authenticated: true, public_dashboard: false }
      else if (pathname === '/api/me' && method === 'GET') value = { authenticated: true }
      else if (pathname === `${prefix}/users/1/portal` && method === 'GET') value = { configuration: { enabled: false, reason: 'TEST_ONLY 未启用', origin }, keys: 0, url: null, activation_expires_at: null }
      else if (pathname === `${prefix}/users/1/diagnosis` && method === 'GET' && !url.search) value = diagnosisFixture(user)
      else if (pathname === `${prefix}/users/1/client-template` && method === 'GET' && !url.search) value = templateFixture
      else if (pathname === `${prefix}/users` && method === 'GET') value = [user]
      else if (pathname === `${prefix}/users/1` && method === 'PATCH') {
        const payload = request.postDataJSON()
        assert.deepEqual(payload, { name: '已保留的用户草稿' })
        userWrites.push(payload); Object.assign(user, payload); value = user
      }
      else if (pathname === `${prefix}/proxy-resources` && method === 'GET') value = proxyResources()
      else if (pathname === `${prefix}/ordered-proxy-resources` && method === 'GET') value = []
      else if (pathname === `${prefix}/nodes` && method === 'GET') value = nodes
      else if (pathname === `${prefix}/chains` && method === 'GET') value = chainEntries
      else if (pathname === `${prefix}/policy-groups` && method === 'GET') value = policies
      else if (pathname === `${prefix}/policy-groups` && method === 'POST') {
        const payload = request.postDataJSON()
        assert.deepEqual(payload, { name: '已保留的策略草稿', node_ids: [1], chain_ids: [] })
        groupWrites.push({ pathname, method, payload }); value = { id: 3, ...payload, member_count: 0 }; policies.push(value)
      }
      else if (pathname === `${prefix}/policy-groups/1` && method === 'PUT') {
        const payload = request.postDataJSON()
        assert.deepEqual(payload, { name: '原策略', node_ids: [1], chain_ids: [] })
        groupWrites.push({ pathname, method, payload }); Object.assign(policies[0], payload); value = policies[0]
      }
      else if (pathname === `${prefix}/package-groups` && method === 'GET') value = packages
      else if (pathname === `${prefix}/package-groups/2` && method === 'PUT') {
        const payload = request.postDataJSON()
        assert.deepEqual(payload, { name: '已保留的套餐草稿', monthly_bytes: '2147483648', reset_day: 15, reset_hour: 8, reset_minute: 30, timezone: 'UTC', duration_days: 60 })
        groupWrites.push({ pathname, method, payload }); Object.assign(packages[1], payload); value = packages[1]
      }
      else if (pathname === `${prefix}/package-groups/2` && method === 'DELETE') {
        groupWrites.push({ pathname, method }); packages.splice(1, 1); value = {}
      }
      else if (pathname === `${prefix}/usage` && method === 'GET') { usageReads.push(Date.now()); value = usage }
      else if (pathname === `${prefix}/users/1/external-accesses` && method === 'GET') value = { revision: 0, accesses: [], available_nodes: [] }
      else if (pathname === `${prefix}/users/1/accesses` && method === 'GET') value = [...new Set([...groupIds, ...directIds])].map(id => ({ user_id: 1, node_id: id, uuid: 'TEST_ONLY', stat_name: `fixture_${id}`, direct_grant: directIds.has(id) }))
      else if (pathname === `${prefix}/users/1/accesses` && method === 'POST') {
        const payload = request.postDataJSON(); assert.deepEqual(payload, { node_id: 1 })
        directIds.add(1); accessWrites.push(payload); value = { user_id: 1, node_id: 1, uuid: 'TEST_ONLY', stat_name: 'fixture_1', direct_grant: true }
      }
      else if (pathname === `${prefix}/users/1/policy-groups` && method === 'GET') { policyReads.push([...groupIds]); value = { group_ids: [...groupIds] } }
      else if (pathname === `${prefix}/users/1/entitlement` && method === 'GET') value = entitlement()
      else if (pathname === `${prefix}/users/1/subscription` && method === 'GET') {
        const format = new URL(request.url()).searchParams.get('format')
        assert(['singbox', 'links'].includes(format))
        value = {
          format, status: 'ready', message: '私有夹具订阅已就绪', subscription_url: user.subscription_url,
          available_formats: ['singbox', 'links'], granted_nodes: groupIds.length, eligible_nodes: groupIds.length,
          ready_nodes: nodes.filter(node => groupIds.includes(node.id)),
          content: format === 'singbox' ? JSON.stringify({ outbounds: [{ tag: 'TEST_ONLY 当前用户节点' }] }) : 'vless://TEST_ONLY@proxy.example.com:20002',
          filename: format === 'singbox' ? 'sinan-subscription.json' : 'sinan-subscription.txt',
          content_type: format === 'singbox' ? 'application/json' : 'text/plain', entitlement: entitlement(),
        }
      }
      else if (pathname === `${prefix}/operations/preview` && method === 'POST') {
        const payload = request.postDataJSON()
        assert(['policy_batch', 'replace_package'].includes(payload.operation))
        if (payload.operation === 'policy_batch') assert.deepEqual(payload, { operation: 'policy_batch', user_ids: [1], group_ids: [2] })
        else assert.deepEqual(payload, { operation: 'replace_package', user_id: 1, package_group_id: 2 })
        const id = `00000000-0000-4000-8000-${String(++previewSequence).padStart(12, '0')}`
        const fixed = { id, request: structuredClone(payload), state: operationState() }
        previews.push(fixed); operationSnapshots.set(id, fixed)
        const gate = heldPreview; heldPreview = null
        if (gate) { gate.enter(); await gate.released }
        value = { id, expires_at: Math.floor(Date.now() / 1000) + 300, summary: payload.operation === 'policy_batch'
          ? { effect: 'TEST_ONLY 固定策略范围，历史账本与单独授权保留', users: [{ id: 1, name: user.name }], differences: [{ user_id: 1, added_nodes: [2], removed_nodes: [1], effective_nodes: [2] }] }
          : { effect: 'TEST_ONLY 更换固定套餐，历史用量保留', plan: packages[1], new_cycle: { cycle_start: 1790812800, next_reset: 1793491200, used_bytes: usage.total } } }
      } else if (new RegExp(`^${prefix}/operations/[^/]+/apply$`).test(pathname) && method === 'POST') {
        const payload = request.postDataJSON(), fixed = operationSnapshots.get(pathname.split('/').at(-2))
        assert.deepEqual(payload, { confirm: true }); assert(fixed, 'apply must bind an existing exact preview')
        applications.push({ pathname, method, payload, request: fixed.request })
        if (fixed.state !== operationState()) { await route.fulfill({ status: 409, json: { error: 'TEST_ONLY 固定预览版本冲突，请重新预览' } }); return }
        assert.equal(JSON.stringify(usage), ledger, 'preview and apply must preserve the full original ledger')
        writes.push({ pathname, method, payload, request: fixed.request })
        if (fixed.request.operation === 'policy_batch') groupIds = [...fixed.request.group_ids]
        else packageId = fixed.request.package_group_id
        operationSnapshots.delete(fixed.id); value = { applied: true }
      } else {
        errors.push(`Unexpected API: ${method} ${pathname}`)
        await route.fulfill({ status: 404, json: { error: '测试拒绝未知接口' } }); return
      }
      await route.fulfill({ json: value })
    })

    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/sing-box/users`)
    await page.getByRole('heading', { name: '可用范围与套餐', exact: true }).waitFor()
    const previous = page.getByRole('checkbox', { name: /原策略/ })
    const next = page.getByRole('checkbox', { name: /新策略/ })
    await previous.waitFor()
    assert.equal(await previous.isChecked(), true)
    assert.equal(await next.isChecked(), false)
    const readCount = policyReads.length
    const usageCount = usageReads.length
    await previous.uncheck()
    await next.check()
    const policyFailure = failedRead(`${prefix}/policy-groups`)
    const editedAt = Date.now()
    await page.waitForTimeout(5600)
    await policyFailure
    assert(Date.now() - editedAt >= 5500)
    assert(usageReads.length > usageCount, 'other resource polling must remain active')
    assert.equal(policyReads.length, readCount, 'unsaved assigned-policy snapshots must not be refreshed by polling')
    assert.equal(await previous.isChecked(), false)
    assert.equal(await next.isChecked(), true)
    assert.deepEqual(groupIds, [1], 'editing a draft must not mutate the fixture server')
    const savePolicies = page.getByRole('button', { name: '保存策略组分配', exact: true })
    assert.equal(await savePolicies.isDisabled(), true)
    assert.equal(await previous.isEnabled(), true, 'local policy drafts remain editable while writes are blocked')
    await blockedPolicySave(savePolicies)
    assert.equal(await previous.isChecked(), false)
    assert.equal(await next.isChecked(), true)
    assert.equal(writes.length, 0)
    await recoverRead(`${prefix}/policy-groups`, page.getByRole('button', { name: '重试', exact: true }).first(), async () => {
      assert.equal(await savePolicies.isDisabled(), true)
      assert.equal(await previous.isChecked(), false)
      assert.equal(await next.isChecked(), true)
      assert.equal(writes.length, 0)
      await blockedPolicySave(savePolicies)
      assert.equal(await previous.isChecked(), false)
      assert.equal(await next.isChecked(), true)
    })
    await enabled(savePolicies)
    assert.equal(await previous.isChecked(), false, 'successful explicit refresh must preserve the unsaved draft')
    assert.equal(await next.isChecked(), true)
    // Preview itself must remain read-only; its pending/unchecked callback cannot apply.
    let entered, releasePreview
    const previewArrived = new Promise(resolve => { entered = resolve })
    const previewReleased = new Promise(resolve => { releasePreview = resolve })
    heldPreview = { enter: entered, released: previewReleased }
    await savePolicies.click()
    await previewArrived
    let review = reviewDialog('policy_batch')
    await review.waitFor()
    try {
      await assertUnconfirmed(review)
      assert.equal(writes.length, 0); assert.deepEqual(groupIds, [1]); assert.equal(JSON.stringify(usage), ledger)
    } finally { releasePreview() }
    await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).waitFor()
    await assertUnconfirmed(review)
    await review.getByRole('button', { name: '返回草稿', exact: true }).click()
    await review.waitFor({ state: 'hidden' })
    assert.equal(await previous.isChecked(), false); assert.equal(await next.isChecked(), true)
    assert.equal(writes.length, 0, 'returning from a fixed preview preserves the unsaved policy draft')
    await savePolicies.click()
    review = reviewDialog('policy_batch')
    await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).waitFor()
    ++operationRevision
    await confirmReview(review)
    await review.getByRole('alert').filter({ hasText: '固定预览版本冲突' }).waitFor()
    assert.equal(writes.length, 0); assert.deepEqual(groupIds, [1]); assert.equal(JSON.stringify(usage), ledger)
    const freshPreview = page.waitForResponse(response => new URL(response.url()).pathname === `${prefix}/operations/preview` && response.request().method() === 'POST' && response.status() === 200)
    await review.getByRole('button', { name: '重新预览', exact: true }).click()
    await freshPreview
    await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).waitFor()
    assert.equal(await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).isChecked(), false)
    await assertUnconfirmed(review)
    // Assigned snapshots intentionally do not poll; only confirmed apply reloads them.
    await failedRead(`${prefix}/users/1/policy-groups`, () => confirmReview(review))
    await page.getByText('变更已确认保存；历史账本保留，请继续查看设备应用与订阅状态。', { exact: true }).waitFor()
    assert.equal(await savePolicies.isDisabled(), true)
    assert.equal(await previous.isChecked(), false)
    assert.equal(await next.isChecked(), true)
    const readback = page.waitForResponse(response => new URL(response.url()).pathname === `${prefix}/users/1/policy-groups` && response.request().method() === 'GET' && response.status() === 200)
    await recoverRead(`${prefix}/users/1/policy-groups`, page.getByRole('button', { name: '重试', exact: true }).first(), async () => {
      assert.equal(await savePolicies.isDisabled(), true)
      assert.equal(await previous.isChecked(), false)
      assert.equal(await next.isChecked(), true)
    })
    await enabled(savePolicies)
    assert.equal(await previous.isChecked(), false)
    assert.equal(await next.isChecked(), true)
    assert.deepEqual(await (await readback).json(), { group_ids: [2] })
    assert.equal(writes.length, 1)
    assert.deepEqual(writes[0].request, { operation: 'policy_batch', user_ids: [1], group_ids: [2] })
    assert.deepEqual(writes[0].payload, { confirm: true })
    assert.equal(applications.length, 2, 'one stale fixed apply was refused before the one successful apply')
    assert(policyReads.length > readCount, 'saving must explicitly reload authoritative assignments')
    assert.deepEqual(policyReads.at(-1), [2])
    assert.equal(await previous.isChecked(), false)
    assert.equal(await next.isChecked(), true)

    await page.getByRole('button', { name: '分配或更换套餐', exact: true }).click()
    await page.locator('select[name="package_group_id"]').selectOption('2')
    let dialog = page.getByRole('dialog')
    await failedRead(`${prefix}/package-groups`)
    await blockedForm(dialog, '确认分配')
    assert.equal(await dialog.locator('select[name="package_group_id"]').inputValue(), '2')
    await recoverRead(`${prefix}/package-groups`, () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click()), async () => {
      await blockedForm(dialog, '确认分配')
      assert.equal(await dialog.locator('select[name="package_group_id"]').inputValue(), '2')
    })
    await enabled(dialog.getByRole('button', { name: '确认分配', exact: true }))
    await failedRead(`${prefix}/users/1/entitlement`)
    await blockedForm(dialog, '确认分配')
    await recoverRead(`${prefix}/users/1/entitlement`, () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click()), async () => {
      await blockedForm(dialog, '确认分配')
      assert.equal(await dialog.locator('select[name="package_group_id"]').inputValue(), '2')
    })
    await page.getByRole('button', { name: '确认分配', exact: true }).click()
    review = reviewDialog('replace_package')
    await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).waitFor()
    await assertUnconfirmed(review)
    assert.equal(packageId, 1); assert.equal(writes.length, 1); assert.equal(JSON.stringify(usage), ledger)
    await review.getByRole('button', { name: '返回草稿', exact: true }).click()
    await review.waitFor({ state: 'hidden' })
    assert.equal(await dialog.locator('select[name="package_group_id"]').inputValue(), '2', 'returning to the package editor preserves its explicit selected target')
    await dialog.getByRole('button', { name: '确认分配', exact: true }).click()
    review = reviewDialog('replace_package')
    await review.getByRole('checkbox', { name: '已核对目标与影响，确认执行', exact: true }).waitFor()
    await confirmReview(review)
    await review.waitFor({ state: 'hidden' })
    await page.getByText('变更已确认保存；历史账本保留，请继续查看设备应用与订阅状态。', { exact: true }).waitFor()
    await page.getByText('新套餐', { exact: true }).waitFor()
    assert.equal(packageId, 2)
    assert.deepEqual(writes[1].request, { operation: 'replace_package', user_id: 1, package_group_id: 2 })
    assert.equal(writes.filter(w => w.request.operation === 'replace_package').length, 1)
    assert.equal(JSON.stringify(usage), ledger)
    await page.getByRole('button', { name: '订阅链接', exact: true }).click()
    assert.equal(await page.getByRole('combobox', { name: '订阅格式', exact: true }).inputValue(), 'singbox')
    await page.getByRole('dialog').getByText('可以获取', { exact: true }).waitFor()
    await page.getByRole('region', { name: '订阅地址', exact: true }).locator('code').waitFor()
    assert.equal(await page.getByRole('region', { name: '订阅地址', exact: true }).locator('code').textContent(), `${user.subscription_url}?format=singbox`)
    await page.getByRole('combobox', { name: '订阅格式', exact: true }).selectOption('links')
    await page.getByRole('dialog').getByText('可以获取', { exact: true }).waitFor()
    await page.getByRole('region', { name: '订阅地址', exact: true }).locator('code').waitFor()
    assert.equal(await page.getByRole('region', { name: '订阅地址', exact: true }).locator('code').textContent(), `${user.subscription_url}?format=links`)
    await page.getByRole('button', { name: '完成', exact: true }).click()
    assert.equal(writes.length, 2, 'subscription display must not write credentials or grants')

    const direct = page.getByRole('checkbox', { name: '授权 节点 1', exact: true })
    // A clean snapshot is also unwritable while the real header refresh is pending.
    assert.equal(failures.size, 0)
    await enabled(direct)
    await recoverRead(`${prefix}/proxy-resources`, page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }), async () => {
      assert.equal(await direct.isDisabled(), true)
      assert.equal(await direct.isChecked(), false)
      assert.equal(accessWrites.length, 0)
    })
    await enabled(direct)
    // Each direct-grant dependency must independently block writes after a failed GET.
    for (const dependency of [`${prefix}/users`, `${prefix}/proxy-resources`, `${prefix}/users/1/accesses`]) {
      await failedRead(dependency, () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click())
      assert.equal(await direct.isDisabled(), true)
      assert.equal(await direct.isChecked(), false)
      assert.equal(await page.getByText(user.name, { exact: true }).count() > 0, true, 'last good data remains visible')
      await recoverRead(dependency, page.getByRole('button', { name: '重试', exact: true }).first(), async () => {
        assert.equal(await direct.isDisabled(), true)
        assert.equal(accessWrites.length, 0)
      })
      await enabled(direct)
    }
    // A metrics-only failure has no authority over access edits.
    await failedRead(`${prefix}/usage`, () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click())
    await enabled(direct)
    const grantSaved = page.waitForResponse(response => new URL(response.url()).pathname === `${prefix}/users/1/accesses` && response.request().method() === 'POST' && response.status() === 200)
    const grantReadback = page.waitForResponse(async response => new URL(response.url()).pathname === `${prefix}/users/1/accesses` && response.request().method() === 'GET' && response.status() === 200 && (await response.json()).some(access => access.user_id === 1 && access.node_id === 1 && access.direct_grant === true))
    await direct.click()
    await grantSaved
    await grantReadback
    await page.getByText('授权已保存，设备应用新配置后会出现在订阅中。', { exact: true }).waitFor()
    await enabled(direct)
    const grantDeadline = Date.now() + 5000
    while (!await direct.isChecked() && Date.now() < grantDeadline) await page.waitForTimeout(25)
    assert.equal(await direct.isChecked(), true, 'the real successful access readback must select the controlled switch')
    assert.deepEqual(accessWrites, [{ node_id: 1 }])
    failures.delete(`${prefix}/usage`)
    await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click()

    await page.getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByRole('textbox', { name: '代理用户名称', exact: true }).fill('已保留的用户草稿')
    await failedRead(`${prefix}/users`)
    await blockedForm(dialog, '保存修改')
    await recoverRead(`${prefix}/users`, () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click()), async () => {
      await blockedForm(dialog, '保存修改')
      assert.equal(await dialog.getByRole('textbox', { name: '代理用户名称', exact: true }).inputValue(), '已保留的用户草稿')
    })
    await dialog.getByRole('button', { name: '保存修改', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.deepEqual(userWrites, [{ name: '已保留的用户草稿' }])

    await page.getByRole('link', { name: '管理策略与套餐', exact: true }).click()
    await page.getByRole('button', { name: '创建策略组', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByRole('textbox', { name: '名称', exact: true }).fill('已保留的策略草稿')
    await dialog.locator('input[name="node_ids"][value="2"]').check()
    // Let the actual periodic GET begin; no prior error or click behind the open dialog.
    assert.equal(failures.size, 0)
    await enabled(dialog.getByRole('button', { name: '保存', exact: true }))
    await recoverRead(`${prefix}/proxy-resources`, null, async () => {
      await blockedForm(dialog, '保存')
      assert.equal(await dialog.getByRole('textbox', { name: '名称', exact: true }).inputValue(), '已保留的策略草稿')
      assert.equal(await dialog.locator('input[name="node_ids"][value="2"]').isChecked(), true)
    })
    await enabled(dialog.getByRole('button', { name: '保存', exact: true }))
    await failedRead(`${prefix}/proxy-resources`)
    await blockedForm(dialog, '保存')
    await recoverRead(`${prefix}/proxy-resources`, dialog.getByRole('button', { name: '重试', exact: true }), async () => {
      await blockedForm(dialog, '保存')
      assert.equal(await dialog.getByRole('textbox', { name: '名称', exact: true }).inputValue(), '已保留的策略草稿')
      assert.equal(await dialog.locator('input[name="node_ids"][value="2"]').isChecked(), true)
      chainEntries = [{ id: 1, name: '恢复后的链路身份', entry_node_id: 2, exit_node_id: 1, available: true }]
    })
    await enabled(dialog.locator('input[name="node_ids"][value="2"]'))
    assert.equal(await dialog.locator('input[name="node_ids"][value="2"]').isChecked(), true, 'a changed node identity must not silently drop the draft selection')
    assert.equal(await dialog.getByRole('button', { name: '保存', exact: true }).isDisabled(), true)
    assert.equal(groupWrites.length, 0)
    const unavailableNode = dialog.locator('input[name="node_ids"][value="2"]')
    const nodeDraftMutations = mutations.length
    await unavailableNode.click()
    await unavailableNode.waitFor({ state: 'hidden' })
    assert.equal(await unavailableNode.count(), 0, 'explicitly cancelling an unavailable node removes only that draft choice')
    await enabled(dialog.getByRole('button', { name: '保存', exact: true }))
    assert.equal(mutations.length, nodeDraftMutations, 'cancelling a draft selection must not write')
    await dialog.locator('input[name="node_ids"][value="1"]').check()
    await dialog.getByRole('button', { name: '保存', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.deepEqual(groupWrites[0].payload, { name: '已保留的策略草稿', node_ids: [1], chain_ids: [] })

    // Existing unavailable IDs remain visible when opening, and after recovery removes them.
    policies[0].chain_ids = [42]
    chainEntries.push({ id: 42, name: '已不可用旧链路', entry_node_id: 99, exit_node_id: 100, available: false })
    await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click()
    const originalPolicyRow = page.getByRole('row').filter({ has: page.getByText('原策略', { exact: true }) })
    await originalPolicyRow.getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    assert.equal(await dialog.locator('input[name="chain_ids"][value="42"]').isChecked(), true)
    assert.equal(await dialog.getByRole('button', { name: '保存', exact: true }).isDisabled(), true)
    await failedRead(`${prefix}/proxy-resources`)
    await blockedForm(dialog, '保存')
    await recoverRead(`${prefix}/proxy-resources`, dialog.getByRole('button', { name: '重试', exact: true }), async () => {
      await blockedForm(dialog, '保存')
      assert.equal(await dialog.locator('input[name="chain_ids"][value="42"]').isChecked(), true)
      chainEntries = chainEntries.filter(chain => chain.id !== 42)
    })
    await enabled(dialog.locator('input[name="chain_ids"][value="42"]'))
    assert.equal(await dialog.locator('input[name="chain_ids"][value="42"]').isChecked(), true)
    assert.equal(await dialog.getByRole('button', { name: '保存', exact: true }).isDisabled(), true)
    assert.equal(groupWrites.length, 1)
    const unavailableChain = dialog.locator('input[name="chain_ids"][value="42"]')
    const chainDraftMutations = mutations.length
    await unavailableChain.click()
    await unavailableChain.waitFor({ state: 'hidden' })
    assert.equal(await unavailableChain.count(), 0, 'explicitly cancelling a missing chain removes only that draft choice')
    await enabled(dialog.getByRole('button', { name: '保存', exact: true }))
    assert.equal(mutations.length, chainDraftMutations, 'cancelling a draft selection must not write')
    await dialog.getByRole('button', { name: '保存', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.deepEqual(groupWrites[1].payload.chain_ids, [])

    await page.getByRole('button', { name: '套餐组', exact: true }).click()
    const packageRow = page.getByRole('row').filter({ has: page.getByText('新套餐', { exact: true }) })
    await packageRow.getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByRole('textbox', { name: '名称', exact: true }).fill('已保留的套餐草稿')
    await failedRead(`${prefix}/package-groups`)
    await blockedForm(dialog, '保存')
    await recoverRead(`${prefix}/package-groups`, dialog.getByRole('button', { name: '重试', exact: true }), async () => {
      await blockedForm(dialog, '保存')
      assert.equal(await dialog.getByRole('textbox', { name: '名称', exact: true }).inputValue(), '已保留的套餐草稿')
      assert.equal(await dialog.locator('input[name="duration_days"]').inputValue(), '60')
    })
    await dialog.getByRole('button', { name: '保存', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    const renamedPackageRow = page.getByRole('row').filter({ has: page.getByText('已保留的套餐草稿', { exact: true }) })
    await renamedPackageRow.getByRole('button', { name: '删除', exact: true }).click()
    dialog = page.getByRole('dialog')
    await failedRead(`${prefix}/package-groups`)
    assert.equal(await dialog.getByRole('button', { name: '确认删除', exact: true }).isDisabled(), true)
    assert.equal(groupWrites.length, 3)
    await recoverRead(`${prefix}/package-groups`, dialog.getByRole('button', { name: '重试', exact: true }), async () => {
      assert.equal(await dialog.getByRole('button', { name: '确认删除', exact: true }).isDisabled(), true)
      assert.equal(await dialog.getByRole('button', { name: '取消', exact: true }).isDisabled(), false)
      assert.equal(groupWrites.length, 3)
      packages.splice(1, 1)
    })
    await dialog.getByText('此资源已不可用，暂不能提交。草稿已保留，可关闭窗口后重新选择。', { exact: true }).waitFor()
    assert.equal(await dialog.getByRole('button', { name: '确认删除', exact: true }).isDisabled(), true)
    assert.equal(groupWrites.length, 3, 'successful GET recovery must not reopen writes for a removed entity')
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.equal(groupWrites.length, 3)
    assert.equal(previews.length, 5, 'two return-to-draft paths and one stale CAS use fresh exact preview identities')
    assert.equal(applications.length, 3, 'only one rejected stale apply and two confirmed entitlement changes reached the private API')
    assert.equal(JSON.stringify(usage), ledger, 'all editor and entitlement operations preserve historical usage')
    assert.deepEqual(errors, [])
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await page.close()
  }
  console.log('PASS: dist desktop/mobile, real polling and refresh preserve drafts; failed/pending dependencies block direct grants and open dialogs; fixed policy/package preview requires explicit confirmation, stale CAS refuses apply, return/re-preview preserve drafts and ledger; subscription display remains read-only')
} finally {
  try { await browser?.close() }
  finally { await new Promise(resolve => server.close(resolve)) }
}
