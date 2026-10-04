import { installControlCenterFixtures } from './control-center-fixtures.mjs'
// TEST_ONLY: exercise real admin pages against isolated, controllable API reads.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// TEST_ONLY read-only contract for the newly mounted UserDiagnostics resource.
// Device state and sensitive template content remain explicitly unavailable.
const diagnosisFixture = user => ({ user_id: user.id, account: { user_id: user.id, name: user.name, portal_created: false, keys: 0, active_sessions: 0, activation_expires_at: null },
  subscription: { status: 'empty', message: 'TEST_ONLY 真实设备状态未验证。', granted_nodes: 0, ready_managed_nodes: 0, ready_external_nodes: 0 },
  permissions: [], external_authorizations: [], ledger: [], quota_credits: [], package_history: [], rotations: [], events: [],
  limitations: { credentials_read: { available: false, reason: 'TEST_ONLY 敏感内容未读取；此处仅为独立只读诊断快照。' } } })
const templateFixture = { template: null, definition_redacted: false, credential_access_reason: 'TEST_ONLY 完整模板未读取。', supported_client: 'singbox', supported_version: '1.14.2', schema_validation: true, runtime_validation: false, limitations: 'TEST_ONLY 没有保存的模板，未执行真实客户端验证。' }

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = process.env.SINAN_WEB_DIST ?? fileURLToPath(new URL('../dist/', import.meta.url))
const prefix = '/api/plugins/sing-box'
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const host = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
const settle = () => new Promise(done => setTimeout(done, 40))
const wait = async (condition, description) => {
  const deadline = Date.now() + 8000
  while (!await condition()) { assert(Date.now() < deadline, description); await settle() }
}
const forceSubmit = dialog => dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
let browser
const summary = []
try {
  await new Promise(done => host.listen(0, '127.0.0.1', done))
  const origin = `http://127.0.0.1:${host.address().port}`
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  for (const width of [1440, 390]) for (const pageName of ['groups', 'users']) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    const errors = [], writes = [], gates = new Map(), reads = new Map()
    const row = { id: 1, name: 'TEST_ONLY 原策略', node_ids: [1], chain_ids: [], member_count: 1 }
    const user = { id: 1, name: 'TEST_ONLY 原用户', subscription_token: 'TEST_ONLY', subscription_url: 'http://127.0.0.1/s/TEST_ONLY' }
    const node = { enabled: true, id: 1, name: 'TEST_ONLY 节点', server_id: 1, protocol: 'vless-reality', public_host: '127.0.0.1', port: 24443, sni: 'localhost', public_key: 'TEST_ONLY', short_id: '0123abcd' }
    const resource = { ...node, kind: 'direct', server_name: 'TEST_ONLY 服务器', role: 'direct', entry_node_id: null, tcp: true, udp: true, available: true, enabled: true, stage: 'direct', reference_count: 0, entry_eligible: true }
    const servers = [{ id: 1, name: resource.server_name, enabled: true, online: true, read_only: false }]
    const usage = { uplink: '10', downlink: '20', total: '30', by_user: [], by_node: [] }
    const hold = path => {
      let release
      const promise = new Promise(done => { release = done })
      const gate = { promise, release, reached: 0, fail: false }
      gates.set(path, gate)
      return gate
    }
    const finish = (path, fail = false) => { const gate = gates.get(path); gates.delete(path); gate.fail = fail; gate.release() }
    page.on('pageerror', error => errors.push(error.message))
    await page.clock.install({ time: new Date('2026-10-03T00:00:00Z') })
    await page.clock.pauseAt(new Date('2026-10-03T00:00:00Z'))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
      assert.equal(url.origin, origin, 'No external requests are permitted')
      if (!path.startsWith('/api/')) return route.continue()
      if (method === 'GET') {
        reads.set(path, (reads.get(path) ?? 0) + 1)
        const gate = gates.get(path)
        if (gate) {
          gate.reached++; await gate.promise
          if (gate.fail) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 后台刷新失败' } }).catch(() => {})
        }
      } else {
        writes.push({ path, method, body: request.postDataJSON() })
        assert.equal(path, `${prefix}/${pageName === 'groups' ? 'policy-groups' : 'users'}/1`)
        return route.fulfill({ json: pageName === 'groups' ? row : { ...user, name: request.postDataJSON().name } })
      }
      let value
      if (path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (path === `${prefix}/policy-groups`) value = [row]
      else if (path === `${prefix}/package-groups`) value = []
      else if (path === `${prefix}/proxy-resources`) value = [resource]
      else if (path === `${prefix}/ordered-proxy-resources`) value = proxyResourceFixtures([node], servers)
      else if (path === `${prefix}/nodes`) value = [node]
      else if (path === `${prefix}/users`) value = [user]
      else if (path === `${prefix}/usage`) value = usage
      else if (path === `${prefix}/users/1/accesses`) value = []
      else if (path === `${prefix}/users/1/external-accesses`) value = { revision: 0, accesses: [], available_nodes: [] }
      else if (path === `${prefix}/users/1/entitlement`) value = { user_id: 1, package_group_id: null, package_name: null, monthly_bytes: null, starts_at: null, expires_at: null, cycle_start: null, next_reset: null, used_bytes: '0', status: 'unlimited', allowed: true }
      else if (path === `${prefix}/users/1/policy-groups`) value = { group_ids: [] }
      else if (path === `${prefix}/users/1/portal`) value = { configuration: { enabled: false, reason: 'TEST_ONLY 尚未启用', origin }, keys: 0, url: null, activation_expires_at: null }
      else if (method === 'GET' && !url.search && path === `${prefix}/users/1/diagnosis`) value = diagnosisFixture(user)
      else if (method === 'GET' && !url.search && path === `${prefix}/users/1/client-template`) value = templateFixture
      else assert.fail(`Unexpected read: ${path}`)
      await route.fulfill({ json: value }).catch(() => {})
    })
    try {
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#/plugins/sing-box/${pageName}`)
      const edit = pageName === 'groups' ? page.getByRole('row').filter({ hasText: row.name }).getByRole('button', { name: '编辑', exact: true }) : page.locator('.user-heading').getByRole('button', { name: '编辑', exact: true })
      await wait(() => edit.isEnabled(), 'Initial snapshots must finish')
      await edit.click()
      const dialog = page.getByRole('dialog'), input = dialog.locator('input[name="name"]'), save = dialog.getByRole('button', { name: pageName === 'groups' ? '保存' : '保存修改', exact: true })
      await input.fill('TEST_ONLY 未保存草稿')
      await input.evaluate(input => {
        window.testInput = input; window.testShell = document.querySelector('.app-shell'); window.testNotices = []
        window.testObserver = new MutationObserver(records => {
          for (const record of records) for (const added of record.addedNodes) if (added instanceof Element) {
            for (const notice of [added, ...added.querySelectorAll('.notice-error, .loading')]) if (notice.matches('.notice-error, .loading')) window.testNotices.push(notice.textContent)
          }
        })
        window.testObserver.observe(document.querySelector('.content'), { childList: true, subtree: true })
      })
      const readPath = `${prefix}/${pageName === 'groups' ? 'policy-groups' : 'users'}`
      const brief = hold(readPath)
      await page.clock.runFor(5000); await wait(() => brief.reached > 0, 'Automatic poll must start')
      await settle()
      await forceSubmit(dialog)
      assert.equal(writes.length, 0, 'A short background request blocks writes before any delayed presentation')
      await page.clock.runFor(100)
      assert.equal(await dialog.getByRole('alert').count(), 0, 'A brief concurrent read must not flash an alert')
      assert.equal(await page.locator('.content .loading').count(), 0, `A background read must keep existing content: ${pageName}/${width}; ${await page.locator('.content .loading').evaluateAll(items => items.map(item => item.parentElement?.outerHTML).join('\n'))}`)
      finish(readPath)
      await wait(() => save.isEnabled(), 'Completed equal snapshots must restore write readiness')
      await page.clock.runFor(300)
      assert.deepEqual(await page.evaluate(() => window.testNotices), [], 'Short polling must not insert transient notices or loading panels')
      assert(await input.evaluate(input => input === window.testInput && document.querySelector('.app-shell') === window.testShell), 'Polling must not remount the draft or shell')
      assert.equal(await input.inputValue(), 'TEST_ONLY 未保存草稿')

      let extraDependencies = 0
      if (pageName === 'groups') for (const path of ['package-groups', 'proxy-resources', 'ordered-proxy-resources'].map(name => `${prefix}/${name}`)) {
        const dependency = hold(path)
        // Start this read on the next poll boundary before measuring its 100ms hold.
        await page.clock.runFor(5000 - (await page.evaluate(() => Date.now())) % 5000)
        await wait(() => dependency.reached > 0, `Current dependency must be read: ${path}`)
        await forceSubmit(dialog)
        assert.equal(writes.length, 0, `Every shared dependency blocks the original submit callback immediately: ${path}`)
        await page.clock.runFor(100)
        assert.equal(await dialog.getByRole('alert').count(), 0, `A short dependency read retains the presentation: ${path}`)
        finish(path)
        await wait(() => save.isEnabled(), `Equal recovered dependency restores the original draft: ${path}`)
        assert.equal(await input.inputValue(), 'TEST_ONLY 未保存草稿')
        extraDependencies++
      }

      const slow = hold(readPath)
      await page.clock.runFor(5000); await wait(() => slow.reached > 0, 'Next automatic poll must run')
      await page.clock.runFor(600); await settle()
      assert.equal(await dialog.getByRole('alert').count(), 1, 'A slow dependency must eventually show its warning despite fast sibling responses')
      assert(await save.isDisabled())
      assert.equal(await page.locator('.content .loading').count(), 0, 'Slow background reads retain existing data instead of skeletons')
      await forceSubmit(dialog); assert.equal(writes.length, 0)
      finish(readPath, true)
      await page.getByText('TEST_ONLY 后台刷新失败', { exact: true }).waitFor()
      await forceSubmit(dialog); assert.equal(writes.length, 0, 'Failed reads remain write-blocked')
      assert.equal(await input.inputValue(), 'TEST_ONLY 未保存草稿')

      const manual = hold(readPath)
      const portalPath = `${prefix}/users/1/portal`
      const portal = pageName === 'users' ? hold(portalPath) : undefined
      await dialog.locator('form').evaluate(form => {
        document.querySelector('.page-header button').click()
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      })
      await wait(() => manual.reached > 0, 'Manual reload must start immediately')
      assert.equal(writes.length, 0, 'Same-event manual reload must invalidate old form callbacks')
      if (portal) {
        await wait(() => portal.reached > 0, 'Manual reload must include the selected user access panel')
        const panel = page.locator('.panel').filter({ has: page.getByRole('heading', { name: '用户 Passkey 入口' }) })
        assert.equal(await panel.locator('.loading').count(), 0, 'A known portal snapshot remains visible during its explicit refresh')
        assert.equal(await panel.getByText('尚未开通用户入口。', { exact: true }).count(), 1, 'The original access state is retained while its current read is held')
        assert.equal(await panel.getByText('TEST_ONLY 尚未启用', { exact: true }).count(), 1, 'The disabled configuration reason remains readable')
        assert(await panel.getByRole('button', { name: '生成开通链接', exact: true }).isDisabled(), 'Retained access data must not enable a current write')
        assert.equal(await input.inputValue(), 'TEST_ONLY 未保存草稿')
        finish(portalPath)
      }
      finish(readPath)
      await wait(() => save.isEnabled(), 'A successful manual reload must restore writes')
      await save.click(); await wait(() => writes.length === 1, 'Exactly one explicit recovered write must succeed')
      assert.equal(writes[0].body.name, 'TEST_ONLY 未保存草稿')
      await dialog.waitFor({ state: 'hidden' })
      await settle()
      const count = reads.get(readPath)
      await page.evaluate(() => Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }))
      await page.clock.runFor(10_000); await settle()
      assert.equal(reads.get(readPath), count, 'Hidden pages pause automatic reads')
      assert.deepEqual(errors, [])
      summary.push({ width, page: pageName, short_reads_stable: true, slow_reads_visible: true, blocked_writes: 4 + extraDependencies, recovered_writes: writes.length })
    } finally { for (const gate of gates.values()) gate.release(); await page.close() }
  }
  console.log(JSON.stringify({ passed: true, scenarios: summary }, null, 2))
} finally { await browser?.close(); await new Promise(done => host.close(done)) }
