// TEST_ONLY: real user authorization forms with isolated external-provider fixtures.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = process.env.SINAN_WEB_DIST ?? fileURLToPath(new URL('../dist/', import.meta.url))
const root = '/api/plugins/sing-box', accessPath = `${root}/users/1/external-accesses`
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
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
const ref = entry => Object.fromEntries(['external_node_id', 'source_id', 'identity_epoch', 'node_version_id', 'update_mode', 'metadata_revision'].map(key => [key, entry[key]]))
const entry = (id, name) => ({ external_node_id: id, source_id: 8, identity_epoch: 2, node_version_id: id + 10, update_mode: 'follow_node', metadata_revision: 0, name, source_name: 'TEST_ONLY 外部来源', protocol: 'shadowsocks', server: 'provider.example.com', port: 443, available: true, reason: null, current_version_id: id + 10, resolved_version_id: id + 10, source_last_error: null })
let browser
try {
  await new Promise(done => server.listen(0, '127.0.0.1', done))
  const origin = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  for (const width of [1440, 390, 340]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }), errors = [], writes = []
    const first = entry(1, 'TEST_ONLY 原分配'), second = entry(2, 'TEST_ONLY 新节点')
    let data = { revision: 1, accesses: [{ ...first, node_version_id: 10 }], available_nodes: [first, second] }
    const userRows = [{ id: 1, name: 'TEST_ONLY 用户', subscription_token: 'TEST_ONLY', subscription_url: `${origin}/sub/TEST_ONLY` }, { id: 2, name: 'TEST_ONLY 第二用户', subscription_token: 'TEST_ONLY_TWO', subscription_url: `${origin}/sub/TEST_ONLY_TWO` }]
    let users = structuredClone(userRows), parentGate, gate, putFailure = true, subscriptionReads = 0
    const hold = () => { let release; const promise = new Promise(done => { release = done }); return gate = { promise, release, reached: 0, fail: false } }
    const finish = fail => { const pending = gate; gate = undefined; pending.fail = fail; pending.release() }
    page.on('pageerror', error => errors.push(error.message))
    await page.clock.install({ time: new Date('2026-10-03T00:00:00Z') })
    await page.clock.pauseAt(new Date('2026-10-03T00:00:00Z'))
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname
      assert.equal(url.origin, origin, 'Provider/external requests must never leave the browser fixture')
      if (!path.startsWith('/api/')) return route.continue()
      if (path === accessPath && request.method() === 'PUT') {
        const body = request.postDataJSON(); writes.push(body)
        if (putFailure) { data = { ...data, revision: 2 }; return route.fulfill({ status: 409, json: { error: 'TEST_ONLY 授权已变化' } }) }
        assert.equal(body.revision, data.revision)
        data = { ...data, revision: data.revision + 1, accesses: body.accesses.map(value => ({ ...data.available_nodes.find(entry => entry.external_node_id === value.external_node_id), ...value })) }
        return route.fulfill({ json: data })
      }
      assert.equal(request.method(), 'GET', `Unexpected write ${path}`)
      if (parentGate && path === parentGate.path) { const pending = parentGate; pending.reached++; await pending.promise; if (pending.fail) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 当前用户依赖读取失败' } }).catch(() => {}) }
      if (path === accessPath && gate) {
        const pending = gate; pending.reached++; await pending.promise
        if (pending.fail) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 外部分配读取失败' } }).catch(() => {})
      }
      let value
      if (path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (path === `${root}/users`) value = users
      else if (path === `${root}/nodes` || path === `${root}/proxy-resources` || path === `${root}/policy-groups` || path === `${root}/package-groups` || path === `${root}/users/1/accesses`) value = []
      else if (path === `${root}/usage`) value = { uplink: '0', downlink: '0', total: '0', by_user: [], by_node: [] }
      else if (path === `${root}/users/1/policy-groups`) value = { group_ids: [] }
      else if (path === `${root}/users/1/entitlement`) value = { user_id: 1, status: 'unlimited', allowed: true, monthly_bytes: null, used_bytes: '0', expires_at: null }
      else if (path === `${root}/users/1/portal`) value = { configuration: { enabled: false, reason: 'TEST_ONLY', origin }, keys: 0, url: null, activation_expires_at: null }
      else if (path === accessPath) value = data
      else if (path === `${root}/users/2/external-accesses`) value = { revision: 0, accesses: [], available_nodes: [] }
      else if (path === `${root}/users/2/accesses`) value = []
      else if (path === `${root}/users/2/policy-groups`) value = { group_ids: [] }
      else if (path === `${root}/users/2/entitlement`) value = { user_id: 2, status: 'unlimited', allowed: true, monthly_bytes: null, used_bytes: '0', expires_at: null }
      else if (path === `${root}/users/2/portal`) value = { configuration: { enabled: false, reason: 'TEST_ONLY', origin }, keys: 0, url: null, activation_expires_at: null }
      else if (path === `${root}/users/1/subscription`) {
        subscriptionReads++
        const format = url.searchParams.get('format') ?? 'singbox'
        value = { format, status: format === 'singbox' ? 'ready' : 'format_unavailable', message: 'TEST_ONLY 订阅', subscription_url: `${origin}/sub/TEST_ONLY`, available_formats: ['singbox'], granted_nodes: 2, eligible_nodes: 2, managed_nodes: 1, external_nodes: 1, external_granted_nodes: 1, ready_nodes: [{ kind: 'managed', id: 1, name: 'TEST_ONLY 受管入口', protocol: 'vless-reality' }, { kind: 'external', id: 1, name: 'TEST_ONLY 外部入口', protocol: 'shadowsocks' }], content: format === 'singbox' ? '{"outbounds":[]}' : null, filename: 'TEST_ONLY.json', content_type: 'application/json', entitlement: { allowed: true, status: 'unlimited', monthly_bytes: null, used_bytes: '0', expires_at: null } }
      } else assert.fail(`Unexpected read ${path}`)
      await route.fulfill({ json: value }).catch(() => {})
    })
    try {
      await page.goto(`${origin}/#/plugins/sing-box/users`)
      const section = page.getByRole('region', { name: '外部节点授权' })
      await wait(() => section.getByRole('button', { name: '管理分配' }).isEnabled(), 'External assignment read completes')
      await section.getByRole('button', { name: '管理分配' }).click()
      const dialog = page.getByRole('dialog'), save = dialog.getByRole('button', { name: '保存分配', exact: true })
      await dialog.getByRole('combobox', { name: 'TEST_ONLY 原分配 更新方式' }).selectOption('pinned')
      await dialog.getByRole('checkbox', { name: /TEST_ONLY 新节点/ }).check()
      assert.equal(await dialog.locator('fieldset.group-choices').first().getByRole('checkbox').count(), 2)
      assert.equal(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth), true, 'Assignment editor fits viewport')
      const pending = hold()
      await page.clock.runFor(5000); await wait(() => pending.reached > 0, 'Background assignment request starts')
      await forceSubmit(dialog); assert.equal(writes.length, 0, 'Pending read cannot submit old authorization')
      finish(true)
      await section.getByText('TEST_ONLY 外部分配读取失败', { exact: true }).waitFor()
      await forceSubmit(dialog); assert.equal(writes.length, 0, 'Failed read cannot submit old authorization')
      assert.equal(await dialog.getByRole('combobox', { name: 'TEST_ONLY 原分配 更新方式' }).inputValue(), 'pinned')
      await page.clock.runFor(5000)
      await wait(() => save.isEnabled(), 'Recovered read allows the retained draft')
      await dialog.getByLabel('搜索外部节点').fill('TEST_ONLY 保留草稿')
      const parentRefresh = () => page.getByRole('button', { name: '刷新', exact: true }).first().evaluate(button => button.click())
      // Each held parent GET is observed before invoking the real submit callback.
      for (const dependency of [`${root}/users`, `${root}/nodes`, `${root}/proxy-resources`, `${root}/users/1/accesses`, `${root}/users/1/entitlement`]) {
        let release; const promise = new Promise(done => { release = done })
        parentGate = { path: dependency, promise, release, reached: 0, fail: false }
        const pendingParent = parentGate
        await parentRefresh(); await wait(() => pendingParent.reached > 0, `Current parent read reached ${dependency}`)
        await forceSubmit(dialog); assert.equal(writes.length, 0, `${dependency} pending must issue zero PUTs`)
        const failedParent = page.waitForResponse(response => new URL(response.url()).pathname === dependency && response.status() === 503)
        pendingParent.fail = true; parentGate = undefined; pendingParent.release(); await failedParent
        await wait(() => save.isDisabled(), `${dependency} failure retains disabled submit`)
        await forceSubmit(dialog); assert.equal(writes.length, 0, `${dependency} failed must issue zero PUTs`)
        assert.equal(await dialog.getByLabel('搜索外部节点').inputValue(), 'TEST_ONLY 保留草稿')
        assert.equal(await dialog.getByRole('combobox', { name: 'TEST_ONLY 原分配 更新方式' }).inputValue(), 'pinned')
        await parentRefresh(); await wait(() => save.isEnabled(), `${dependency} current recovery preserves the same draft`)
      }
      const original = structuredClone(data)
      for (const [label, mutate] of [
        ['node disappeared', value => { value.available_nodes = value.available_nodes.filter(node => node.external_node_id !== second.external_node_id) }],
        ['source replaced', value => { value.available_nodes[1].source_id = 9; value.available_nodes[1].identity_epoch++ }],
        ['node disabled', value => { value.available_nodes[1].available = false; value.available_nodes[1].reason = 'node_disabled' }],
        ['version changed', value => { value.available_nodes[1].node_version_id++; value.available_nodes[1].current_version_id++; value.available_nodes[1].resolved_version_id++ }],
        ['metadata changed', value => { value.available_nodes[1].metadata_revision++ }],
        ['unknown revision', value => { delete value.revision }],
        ['unsafe revision', value => { value.revision = Number.MAX_SAFE_INTEGER + 1 }],
      ]) {
        data = structuredClone(original); mutate(data)
        const changed = page.waitForResponse(response => new URL(response.url()).pathname === accessPath && response.request().method() === 'GET' && response.status() === 200)
        await parentRefresh(); await changed; await wait(() => save.isDisabled(), label)
        await forceSubmit(dialog); assert.equal(writes.length, 0, `${label} must issue zero PUTs`)
        assert.equal(await dialog.getByLabel('搜索外部节点').inputValue(), 'TEST_ONLY 保留草稿')
        assert.equal(await dialog.locator('fieldset.group-choices').first().getByRole('checkbox').count(), 2)
        data = structuredClone(original); await parentRefresh(); await wait(() => save.isEnabled(), `${label} original identity recovered`)
      }
      users = []
      const removed = page.waitForResponse(response => new URL(response.url()).pathname === `${root}/users` && response.status() === 200)
      await parentRefresh(); await removed; await wait(() => save.isDisabled(), 'Current target disappearance blocks the retained editor')
      await forceSubmit(dialog); assert.equal(writes.length, 0, 'A disappeared user cannot receive the old external authorization')
      assert.equal(await dialog.getByLabel('搜索外部节点').inputValue(), 'TEST_ONLY 保留草稿')
      users = structuredClone(userRows); await parentRefresh(); await wait(() => save.isEnabled(), 'Only the original restored user can resume')
      await page.evaluate(() => { const form = document.querySelector('.external-user-access form'); const choice = [...document.querySelectorAll('.user-roster button')].find(button => button.textContent.includes('TEST_ONLY 第二用户')); choice.click(); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) })
      assert.equal(writes.length, 0, 'Same-event user switch never redirects the original draft to the new user')
      await dialog.waitFor({ state: 'hidden' })
      await page.getByRole('button', { name: /TEST_ONLY 用户/ }).click()
      await wait(() => save.isEnabled(), 'Original user selection restores its preserved draft')
      assert.equal(await dialog.getByLabel('搜索外部节点').inputValue(), 'TEST_ONLY 保留草稿')
      await save.click()
      await dialog.getByText('TEST_ONLY 授权已变化', { exact: true }).waitFor()
      assert.equal(writes.length, 1)
      assert.deepEqual(writes[0].accesses, [{ ...ref(first), update_mode: 'pinned' }, ref(second)])
      assert.equal(await dialog.locator('fieldset.group-choices').first().getByRole('checkbox').count(), 2, 'Conflict retains the draft')
      const reloading = hold()
      await dialog.getByRole('button', { name: '重新读取授权', exact: true }).click()
      await wait(() => reloading.reached > 0, 'Reload draft must actually fetch, not reuse its rejected cache')
      await forceSubmit(dialog); assert.equal(writes.length, 1)
      finish(false)
      await wait(async () => await dialog.locator('fieldset.group-choices').first().getByRole('checkbox').count() === 1, 'Explicit reload adopts the current assignment snapshot')
      await dialog.getByLabel('搜索外部节点').fill('')
      await dialog.getByRole('checkbox', { name: /TEST_ONLY 新节点/ }).check()
      putFailure = false
      await wait(() => save.isEnabled(), 'Fresh snapshot is writable')
      await save.click(); await dialog.waitFor({ state: 'hidden' })
      assert.equal(writes.length, 2); assert.equal(writes[1].revision, 2)
      await section.getByText('外部节点分配已保存，后续订阅按新分配生成。', { exact: true }).waitFor()
      const overflow = await page.evaluate(() => [...document.querySelectorAll('body *')].filter(element => element.getBoundingClientRect().right > innerWidth + 1).map(element => ({ tag: element.tagName, class: element.className, text: element.textContent?.slice(0, 70), width: element.getBoundingClientRect().width })))
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Page fits viewport: ${JSON.stringify(overflow.slice(0, 12))}`)
      await page.getByRole('button', { name: '订阅链接', exact: true }).click()
      const subscription = page.getByRole('dialog')
      await subscription.getByText('TEST_ONLY 外部入口', { exact: true }).waitFor()
      await subscription.getByText('TEST_ONLY 受管入口', { exact: true }).waitFor()
      assert.equal(await subscription.locator('.subscription-nodes li').count(), 2, 'Managed and external IDs do not collide')
      assert.equal(await subscription.getByRole('combobox').inputValue(), 'singbox')
      assert.equal(await subscription.locator('option[value=links]').evaluate(option => option.disabled), true)
      assert(subscriptionReads > 0)
      assert.deepEqual(errors, [])
      console.log(`external access ${width}: current parent/identity zero-write matrix, retained target draft, conflict recovery, fixed version and mixed subscription passed`)
    } finally { gate?.release(); parentGate?.release(); await page.close() }
  }
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
