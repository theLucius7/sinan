import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { extname, resolve, sep } from 'node:path'

// TEST_ONLY: the actual dist is served on loopback; every API and external request is intercepted.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url)), prefix = '/api/plugins/sing-box'
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const file = resolve(dist, new URL(request.url, 'http://127.0.0.1').pathname === '/' ? 'index.html' : `.${new URL(request.url, 'http://127.0.0.1').pathname}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
const wait = async (condition, description) => {
  const deadline = Date.now() + 10000
  while (!await condition()) { assert(Date.now() < deadline, description); await new Promise(resolve => setTimeout(resolve, 20)) }
}
const forceSubmit = (dialog, reload = false) => dialog.locator('form').evaluate((form, reload) => { if (reload) Array.from(document.querySelectorAll('.page-header button')).find(button => button.textContent.trim() === '刷新').click(); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) }, reload)
const forceClick = (button, reload = false) => button.evaluate((element, reload) => { if (reload) Array.from(document.querySelectorAll('.page-header button')).find(button => button.textContent.trim() === '刷新').click(); const disabled = element.disabled; try { element.disabled = false; element.click() } finally { element.disabled = disabled } }, reload)
const refresh = page => page.locator('.page-header button').filter({ hasText: /^刷新$/ }).evaluate(button => button.click())

let browser
const totals = { scenarios: 0, requests: 0, writes: 0, blocked_submissions: 0, unexpected: [], external: [], page_errors: [], screenshots: [] }
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  for (const width of [1440, 390]) {
    const fixture = async (routeName, callback) => {
      const page = await browser.newPage({ viewport: { width, height: 1000 } })
      const users = [1, 2].map(id => ({ id, name: `TEST_ONLY 用户 ${id}`, subscription_token: `TEST_ONLY_${id}`, subscription_url: `http://127.0.0.1/s/TEST_ONLY_${id}` }))
      const nodes = [1, 2].map(id => ({ id, name: `TEST_ONLY 节点 ${id}`, server_id: id, protocol: 'vless-reality', public_host: '127.0.0.1', port: 20000 + id, sni: 'localhost', public_key: 'TEST_ONLY', short_id: '0123abcd' }))
      const resources = nodes.map(node => ({ ...node, kind: 'direct', server_name: `TEST_ONLY 服务器 ${node.server_id}`, role: 'direct', entry_node_id: null, tcp: true, udp: true, available: true, enabled: true, stage: 'direct', reference_count: 0, entry_eligible: true }))
      resources.push({ ...resources[0], id: 10, kind: 'chain', name: 'TEST_ONLY 原链路', role: 'chain_entry', entry_node_id: 1, stage: 'ready' })
      const policies = [{ id: 1, name: 'TEST_ONLY 原策略', node_ids: [1], chain_ids: [10], member_count: 1 }, { id: 2, name: 'TEST_ONLY 新策略', node_ids: [2], chain_ids: [], member_count: 0 }]
      const packages = [1, 2].map(id => ({ id, name: `TEST_ONLY 套餐 ${id}`, monthly_bytes: String(id * 1073741824), reset_day: 1, reset_hour: 0, reset_minute: 0, timezone: 'UTC', duration_days: 30 }))
      let groupIds = [1], packageId = 1, direct = false
      const usage = { uplink: '10', downlink: '20', total: '30', by_user: [], by_node: [] }
      const entitlement = (userId = 1) => ({ user_id: userId, package_group_id: packageId, package_name: `TEST_ONLY 套餐 ${packageId}`, ...packages.find(value => value.id === packageId), starts_at: 1790812800, expires_at: 1795996800, cycle_start: 1790812800, next_reset: 1793491200, used_bytes: '30', status: 'active', allowed: true })
      const writes = [], gates = new Map(), pending = [], failures = new Set()
      const control = { page, users, nodes, resources, policies, packages, writes,
        hold(path) { let release; const promise = new Promise(resolve => { release = resolve }); gates.set(path, { promise, release, reached: 0 }); return gates.get(path) },
        fail(path) { failures.add(path) }, recover(path) { failures.delete(path); const gate = gates.get(path); gates.delete(path); gate?.release() },
        releaseAsFailure(path) { failures.add(path); const gate = gates.get(path); gates.delete(path); gate?.release() },
        setDirect(value) { direct = value },
      }
      page.on('pageerror', error => totals.page_errors.push(error.message))
      await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
        if (url.origin !== origin) { totals.external.push(request.url()); await route.abort(); return }
        if (!path.startsWith('/api/')) { await route.continue(); return }
        ++totals.requests
        if (method === 'GET') {
          const gate = gates.get(path)
          if (gate) { ++gate.reached; const blocked = gate.promise.then(() => undefined); pending.push(blocked); await blocked }
          if (failures.has(path)) { await route.fulfill({ status: 503, json: { error: 'TEST_ONLY 刷新失败，保留旧快照' } }); return }
        }
        if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\//.test(path) && !users.some(user => user.id === Number(path.split('/')[5]))) { await route.fulfill({ status: 404, json: { error: 'TEST_ONLY 代理用户已不存在' } }); return }
        let value
        if (method === 'GET' && (path === '/api/dashboard/access' || path === '/api/me')) value = { authenticated: true, public_dashboard: false }
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/portal$/.test(path)) value = { configuration: { enabled: false, reason: 'TEST_ONLY 未启用', origin }, keys: 0, url: null, activation_expires_at: null }
        else if (method === 'GET' && path === `${prefix}/users`) value = users
        else if (method === 'GET' && path === `${prefix}/nodes`) value = nodes
        else if (method === 'GET' && [`${prefix}/ordered-proxy-resources`, `${prefix}/ordered-subscription-sources`].includes(path)) value = []
        else if (method === 'GET' && path === `${prefix}/proxy-resources`) value = resources
        else if (method === 'GET' && path === `${prefix}/policy-groups`) value = policies
        else if (method === 'GET' && path === `${prefix}/package-groups`) value = packages
        else if (method === 'GET' && path === `${prefix}/usage`) value = usage
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/external-accesses$/.test(path)) value = { revision: 0, accesses: [], available_nodes: [] }
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/accesses$/.test(path)) value = [{ user_id: Number(path.split('/')[5]), node_id: 1, uuid: 'TEST_ONLY', stat_name: 'TEST_ONLY_fixture', direct_grant: direct }]
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/policy-groups$/.test(path)) value = { group_ids: [...groupIds] }
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/entitlement$/.test(path)) value = entitlement(Number(path.split('/')[5]))
        else if (method === 'GET' && /^\/api\/plugins\/sing-box\/users\/\d+\/subscription$/.test(path)) value = { format: url.searchParams.get('format'), status: 'ready', message: 'TEST_ONLY 订阅就绪', subscription_url: users.find(user => user.id === Number(path.split('/')[5])).subscription_url, available_formats: ['singbox', 'links'], granted_nodes: 1, eligible_nodes: 1, ready_nodes: nodes, content: '{}', filename: 'TEST_ONLY.json', content_type: 'application/json', entitlement: entitlement(Number(path.split('/')[5])) }
        else if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
          const payload = request.postData() ? request.postDataJSON() : undefined
          const allowed = method === 'PUT' && /^\/api\/plugins\/sing-box\/(policy-groups|package-groups)\/\d+$/.test(path)
            || method === 'POST' && [`${prefix}/policy-groups`, `${prefix}/package-groups`, `${prefix}/users`].includes(path)
            || method === 'DELETE' && /^\/api\/plugins\/sing-box\/(policy-groups|package-groups|users)\/\d+$/.test(path)
            || method === 'PATCH' && /^\/api\/plugins\/sing-box\/users\/\d+$/.test(path)
            || method === 'PUT' && path === `${prefix}/users/1/policy-groups`
            || method === 'POST' && [`${prefix}/users/1/package`, `${prefix}/users/1/accesses`, `${prefix}/users/1/subscription/reset`].includes(path)
            || method === 'DELETE' && path === `${prefix}/users/1/accesses/1`
          assert(allowed, `unexpected write ${method} ${path}`)
          writes.push({ method, path, payload }); ++totals.writes
          if (path === `${prefix}/users/1/policy-groups`) { groupIds = [...payload.group_ids]; value = { group_ids: groupIds } }
          else if (path === `${prefix}/users/1/package`) { packageId = payload.package_group_id; value = entitlement() }
          else if (path === `${prefix}/users/1/accesses` || path === `${prefix}/users/1/accesses/1`) { direct = method === 'POST'; value = {} }
          else if (path === `${prefix}/users/1/subscription/reset`) value = { ...users[0], subscription_token: 'TEST_ONLY_RESET' }
          else if (method === 'PATCH') { Object.assign(users.find(user => user.id === Number(path.split('/').at(-1))), payload); value = users[0] }
          else if (method === 'POST' && path === `${prefix}/users`) { value = { id: 3, name: payload.name, subscription_token: 'TEST_ONLY_3', subscription_url: 'http://127.0.0.1/s/TEST_ONLY_3' }; users.push(value) }
          else if (method === 'PUT') { const list = path.includes('/policy-groups/') ? policies : packages; Object.assign(list.find(item => item.id === Number(path.split('/').at(-1))), payload); value = {} }
          else if (method === 'DELETE') { const list = path.includes('/policy-groups/') ? policies : path.includes('/package-groups/') ? packages : users; const index = list.findIndex(item => item.id === Number(path.split('/').at(-1))); if (index >= 0) list.splice(index, 1); value = {} }
          else value = {}
        } else { totals.unexpected.push(`${method} ${path}`); await route.fulfill({ status: 404, json: { error: 'TEST_ONLY 未知接口' } }); return }
        await route.fulfill({ json: value })
      })
      try {
        await page.goto(`${origin}/#/plugins/sing-box/${routeName}`)
        await page.getByRole('button', { name: routeName === 'groups' ? '创建策略组' : '创建代理用户', exact: true }).first().waitFor()
        await wait(async () => await page.getByRole('button', { name: routeName === 'groups' ? '创建策略组' : '创建代理用户', exact: true }).first().isEnabled(), 'initial snapshot must be ready')
        await callback(control)
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
        ++totals.scenarios
      } finally { for (const gate of gates.values()) gate.release(); await Promise.all(pending); await page.close() }
    }
    const blockAndRecover = async (control, readPath, attempt, saved, checkDraft = async () => {}) => {
      const { page, writes } = control, baseline = writes.length
      const gate = control.hold(readPath)
      // Same-event reload + old form callback proves that handler refs, not only disabled DOM, gate writes.
      await attempt(true)
      await wait(() => gate.reached > 0, 'held GET must actually be requested')
      await attempt()
      assert.equal(writes.length, baseline, 'pending refresh must send zero writes'); totals.blocked_submissions += 2
      await checkDraft()
      control.releaseAsFailure(readPath)
      await page.getByText('TEST_ONLY 刷新失败，保留旧快照', { exact: true }).first().waitFor()
      await attempt()
      assert.equal(writes.length, baseline, 'failed refresh must send zero writes'); ++totals.blocked_submissions
      await checkDraft()
      control.recover(readPath); await refresh(page)
      await saved()
      await wait(() => writes.length === baseline + 1, 'one recovered write must reach the fixture')
    }

    for (const dependency of ['policy-groups', 'package-groups', 'proxy-resources']) await fixture('groups', async control => {
      const { page, writes } = control
      await page.getByRole('row').filter({ hasText: 'TEST_ONLY 原策略' }).getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'), name = dialog.locator('input[name="name"]')
      await name.fill('TEST_ONLY 保留策略草稿'); await dialog.locator('input[name="node_ids"][value="2"]').check()
      const draft = async () => { assert.equal(await name.inputValue(), 'TEST_ONLY 保留策略草稿'); assert(await dialog.locator('input[name="chain_ids"][value="10"]').isChecked()); assert(await dialog.locator('input[name="node_ids"][value="2"]').isChecked()) }
      await blockAndRecover(control, `${prefix}/${dependency}`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '保存', exact: true }).click(), draft)
      assert.deepEqual(writes[0], { method: 'PUT', path: `${prefix}/policy-groups/1`, payload: { name: 'TEST_ONLY 保留策略草稿', node_ids: [1, 2], chain_ids: [10] } })
    })
    await fixture('groups', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '套餐组', exact: true }).click()
      await page.getByRole('row').filter({ hasText: 'TEST_ONLY 套餐 1' }).getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="amount"]').fill('7')
      await blockAndRecover(control, `${prefix}/package-groups`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '保存', exact: true }).click(), async () => assert.equal(await dialog.locator('input[name="amount"]').inputValue(), '7'))
      assert.equal(writes[0].payload.monthly_bytes, String(7 * 1073741824))
    })
    for (const kind of ['policy-groups', 'package-groups']) await fixture('groups', async control => {
      const { page, writes } = control
      if (kind === 'package-groups') await page.getByRole('button', { name: '套餐组', exact: true }).click()
      await page.getByRole('row').filter({ hasText: kind === 'policy-groups' ? 'TEST_ONLY 新策略' : 'TEST_ONLY 套餐 2' }).getByRole('button', { name: '删除', exact: true }).click()
      const button = page.getByRole('dialog').getByRole('button', { name: '确认删除', exact: true })
      await blockAndRecover(control, `${prefix}/${kind}`, sameEvent => forceClick(button, sameEvent), () => button.click())
      assert.equal(writes[0].method, 'DELETE'); assert.equal(writes[0].path, `${prefix}/${kind}/2`)
    })
    for (const kind of ['policy-groups', 'package-groups']) await fixture('groups', async control => {
      const { page, writes } = control
      if (kind === 'package-groups') await page.getByRole('button', { name: '套餐组', exact: true }).click()
      await page.getByRole('button', { name: kind === 'policy-groups' ? '创建策略组' : '创建套餐组', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 创建草稿')
      await blockAndRecover(control, `${prefix}/${kind}`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '保存', exact: true }).click())
      assert.equal(writes[0].method, 'POST'); assert.equal(writes[0].path, `${prefix}/${kind}`)
    })
    for (const dependency of ['users', 'nodes', 'proxy-resources', 'users/1/accesses', 'users/1/entitlement']) await fixture('users', async control => {
      const { page, writes } = control
      await page.locator('.user-heading').getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 用户草稿')
      await blockAndRecover(control, `${prefix}/${dependency}`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '保存修改', exact: true }).click(), async () => assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'TEST_ONLY 用户草稿'))
      assert.deepEqual(writes[0], { method: 'PATCH', path: `${prefix}/users/1`, payload: { name: 'TEST_ONLY 用户草稿' } })
    })
    await fixture('users', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '创建代理用户', exact: true }).first().click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 新用户草稿')
      await blockAndRecover(control, `${prefix}/users`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '创建代理用户', exact: true }).click())
      assert.deepEqual(writes[0], { method: 'POST', path: `${prefix}/users`, payload: { name: 'TEST_ONLY 新用户草稿' } })
    })
    for (const dependency of ['policy-groups', 'package-groups', 'users/1/policy-groups', 'users/1/entitlement']) await fixture('users', async control => {
      const { page, writes } = control
      await page.getByRole('checkbox', { name: /TEST_ONLY 原策略/ }).uncheck(); await page.getByRole('checkbox', { name: /TEST_ONLY 新策略/ }).check()
      const save = page.getByRole('button', { name: '保存策略组分配', exact: true })
      const draft = async () => { assert.equal(await page.getByRole('checkbox', { name: /TEST_ONLY 原策略/ }).isChecked(), false); assert(await page.getByRole('checkbox', { name: /TEST_ONLY 新策略/ }).isChecked()) }
      await blockAndRecover(control, `${prefix}/${dependency}`, sameEvent => forceClick(save, sameEvent), () => save.click(), draft)
      assert.deepEqual(writes[0], { method: 'PUT', path: `${prefix}/users/1/policy-groups`, payload: { group_ids: [2] } })
    })
    for (const dependency of ['package-groups', 'users/1/entitlement']) await fixture('users', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '分配或更换套餐', exact: true }).click()
      const dialog = page.getByRole('dialog'), select = dialog.locator('select[name="package_group_id"]'); await select.selectOption('2')
      await blockAndRecover(control, `${prefix}/${dependency}`, sameEvent => forceSubmit(dialog, sameEvent), () => dialog.getByRole('button', { name: '确认分配', exact: true }).click(), async () => assert.equal(await select.inputValue(), '2'))
      assert.equal(writes[0].path, `${prefix}/users/1/package`); assert.equal(writes[0].payload.package_group_id, 2); assert.match(writes[0].payload.request_id, /^[a-f0-9-]{36}$/)
    })
    for (const granted of [false, true]) await fixture('users', async control => {
      const { page, writes } = control; control.setDirect(granted); await refresh(page)
      const input = page.getByRole('checkbox', { name: '授权 TEST_ONLY 节点 1', exact: true })
      await wait(async () => await input.isEnabled() && await input.isChecked() === granted, 'direct grant readback')
      const attempt = (reload = false) => input.evaluate((element, reload) => { if (reload) Array.from(document.querySelectorAll('.page-header button')).find(button => button.textContent.trim() === '刷新').click(); const disabled = element.disabled; try { element.disabled = false; element.click() } finally { element.disabled = disabled } }, reload)
      await blockAndRecover(control, `${prefix}/users/1/entitlement`, attempt, async () => { await wait(() => input.isEnabled(), 'grant snapshot restored'); await input.click() })
      assert.equal(writes[0].method, granted ? 'DELETE' : 'POST'); assert.equal(writes[0].path, `${prefix}/users/1/accesses${granted ? '/1' : ''}`)
    })
    await fixture('users', async control => {
      const { page, writes } = control
      await page.locator('.user-heading').getByRole('button', { name: '删除', exact: true }).click()
      const button = page.getByRole('dialog').getByRole('button', { name: '确认删除', exact: true })
      await blockAndRecover(control, `${prefix}/users`, sameEvent => forceClick(button, sameEvent), () => button.click())
      assert.equal(writes[0].method, 'DELETE'); assert.equal(writes[0].path, `${prefix}/users/1`)
    })
    await fixture('users', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '订阅链接', exact: true }).click(); await page.getByRole('button', { name: '重置订阅链接', exact: true }).click()
      const button = page.getByRole('dialog').getByRole('button', { name: '确认重置', exact: true })
      await blockAndRecover(control, `${prefix}/users/1/entitlement`, sameEvent => forceClick(button, sameEvent), () => button.click())
      assert.equal(writes[0].method, 'POST'); assert.equal(writes[0].path, `${prefix}/users/1/subscription/reset`)
    })
    await fixture('groups', async control => {
      const { page, writes, resources } = control
      await page.getByRole('row').filter({ hasText: 'TEST_ONLY 原策略' }).getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 消失资源草稿')
      resources.splice(resources.findIndex(value => value.kind === 'chain'), 1); resources.splice(resources.findIndex(value => value.id === 1), 1)
      await refresh(page); await dialog.getByText('已选资源已不可用或身份已变更，请取消这些选择后再保存。其余草稿已保留。', { exact: true }).waitFor()
      assert(await dialog.locator('input[name="chain_ids"][value="10"]').isChecked()); assert(await dialog.locator('input[name="node_ids"][value="1"]').isChecked())
      await forceSubmit(dialog); assert.equal(writes.length, 0)
      if (process.env.SINAN_UI_SCREENSHOT_DIR) { await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true }); const screenshot = resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `singbox-snapshot-missing-resource-${width}.png`); await page.screenshot({ path: screenshot, fullPage: true }); totals.screenshots.push(screenshot) }
      await dialog.locator('input[name="chain_ids"][value="10"]').click(); assert.equal(await dialog.locator('input[name="chain_ids"][value="10"]').count(), 0); await dialog.locator('input[name="node_ids"][value="1"]').click(); assert.equal(await dialog.locator('input[name="node_ids"][value="1"]').count(), 0); await dialog.getByRole('button', { name: '保存', exact: true }).click()
      assert.deepEqual(writes[0].payload, { name: 'TEST_ONLY 消失资源草稿', node_ids: [], chain_ids: [] })
    })
    await fixture('groups', async control => {
      const { page, policies, writes } = control
      await page.getByRole('row').filter({ hasText: 'TEST_ONLY 原策略' }).getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 已删除实体草稿'); policies.splice(0, 1); await refresh(page)
      await dialog.getByText('此资源已不可用，暂不能提交。草稿已保留，可关闭窗口后重新选择。', { exact: true }).waitFor(); await forceSubmit(dialog)
      assert.equal(writes.length, 0); assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'TEST_ONLY 已删除实体草稿')
    })
    await fixture('users', async control => {
      const { page, policies, writes } = control
      await page.getByRole('checkbox', { name: /TEST_ONLY 原策略/ }).uncheck(); await page.getByRole('checkbox', { name: /TEST_ONLY 新策略/ }).check(); policies.splice(1, 1); await refresh(page)
      const missing = page.getByRole('checkbox', { name: /策略组 #2（已不存在，原选择保留）/ }), save = page.getByRole('button', { name: '保存策略组分配', exact: true })
      await missing.waitFor(); assert(await missing.isChecked()); await forceClick(save); assert.equal(writes.length, 0)
      await missing.click(); assert.equal(await missing.count(), 0); await save.click(); assert.deepEqual(writes[0].payload, { group_ids: [] })
    })
    await fixture('users', async control => {
      const { page, packages, writes } = control
      await page.getByRole('button', { name: '分配或更换套餐', exact: true }).click()
      const dialog = page.getByRole('dialog'), select = dialog.locator('select[name="package_group_id"]'); await select.selectOption('2'); packages.splice(1, 1); await refresh(page)
      await dialog.getByText('已选套餐组已不存在，请重新选择；当前分配草稿已保留。', { exact: true }).waitFor(); assert.equal(await select.inputValue(), '2'); await forceSubmit(dialog); assert.equal(writes.length, 0)
      await select.selectOption('1'); await dialog.getByRole('button', { name: '确认分配', exact: true }).click(); assert.equal(writes[0].payload.package_group_id, 1)
    })
    await fixture('users', async control => {
      const { page, users, writes } = control
      await page.locator('.user-heading').getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 最后用户草稿'); users.splice(0); await refresh(page)
      await dialog.getByText('此代理用户已不存在，请重新选择；当前草稿已保留。', { exact: true }).waitFor(); await forceSubmit(dialog); assert.equal(writes.length, 0)
      assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'TEST_ONLY 最后用户草稿')
      await dialog.getByRole('button', { name: '取消', exact: true }).click(); await page.getByRole('button', { name: '清除已删除的用户选择', exact: true }).click()
      await page.getByRole('button', { name: '创建代理用户', exact: true }).first().click()
      const creation = page.getByRole('dialog'); await creation.locator('input[name="name"]').fill('TEST_ONLY 显式恢复新用户'); await creation.getByRole('button', { name: '创建代理用户', exact: true }).click()
      await wait(() => writes.length === 1, 'explicit deselection must restore creation without reassigning the old draft')
      assert.deepEqual(writes[0], { method: 'POST', path: `${prefix}/users`, payload: { name: 'TEST_ONLY 显式恢复新用户' } })
    })
    await fixture('users', async control => {
      const { page, users, writes } = control
      await page.locator('.user-heading').getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.locator('input[name="name"]').fill('TEST_ONLY 消失用户草稿'); users.splice(0, 1); await refresh(page)
      await dialog.getByText('此代理用户已不存在，请重新选择；当前草稿已保留。', { exact: true }).waitFor(); await forceSubmit(dialog); assert.equal(writes.length, 0)
      assert.equal(await dialog.locator('input[name="name"]').inputValue(), 'TEST_ONLY 消失用户草稿'); assert.equal(await page.locator('.user-row[aria-pressed="true"]').count(), 0, 'removed selected user must not silently switch to another user')
      await dialog.getByRole('button', { name: '取消', exact: true }).click(); await page.locator('.user-row').filter({ hasText: 'TEST_ONLY 用户 2' }).click(); await page.locator('.user-heading').getByRole('heading', { name: 'TEST_ONLY 用户 2', exact: true }).waitFor()
    })
  }
  assert.deepEqual(totals.unexpected, []); assert.deepEqual(totals.external, []); assert.deepEqual(totals.page_errors, [])
  console.log(JSON.stringify({ result: 'PASS', ...totals }))
} finally { try { await browser?.close() } finally { await new Promise(resolve => server.close(resolve)) } }
