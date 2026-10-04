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
  for (const width of [1440, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], unexpected = [], writes = [], reads = []
    page.on('pageerror', error => errors.push(error.message))
    await page.clock.install()
    const settle = () => new Promise(done => setTimeout(done, 100))
    const advance = async milliseconds => { await page.clock.runFor(milliseconds); await settle() }
    let rules = [], failSave = true, failSync = true, failRules = false, failServers = false, authenticated = true
    let held = null
    const now = Math.floor(Date.now() / 1000)
    const servers = [{ id: 1, name: '测试服务器', online: true, enabled: false }, { id: 2, name: '另一台服务器', online: true, enabled: true }]
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (method === 'GET') reads.push(path)
      if (method === 'GET' && held?.path === path) { ++held.reached; await held.promise }
      if (path === '/api/dashboard/access') return respond({ authenticated, public_dashboard: false })
      if (path === '/api/plugins/ddns/accounts' && method === 'GET') return respond([])
      if (path === '/api/plugins/ddns/servers') return failServers ? respond({ error: '测试：服务器状态不可用' }, 503) : respond(servers)
      if (path === '/api/plugins/ddns/servers/1/enable') { servers[0].enabled = true; return respond({ enabled: true }) }
      if (path === '/api/plugins/ddns/servers/1/disable') { servers[0].enabled = false; rules.forEach(rule => { rule.plugin_enabled = false }); return respond({ enabled: false }) }
      if (method !== 'GET') writes.push({ path, method, body: request.postData() ? request.postDataJSON() : null })
      if (path === '/api/plugins/ddns/rules') {
        if (method === 'GET') return failRules ? respond({ error: '测试：规则状态不可用' }, 503) : respond(rules)
        if (failSave) return respond({ error: '测试：域名已存在规则' }, 409)
        const body = request.postDataJSON()
        rules.push({ id: 'test-rule', config: body.config, revision: 1, token_configured: true, busy: false, plugin_enabled: true, server_name: '测试服务器', candidate_ip: '2001:db8::10', ip_status: 'ready', ip_received_at: now, last_ip: null, last_success_at: null, attempted_at: null, next_run_at: 0, status: 'pending', error_code: null, failures: 0 })
        return respond(rules[0], 201)
      }
      if (path === '/api/plugins/ddns/rules/dual-stack') {
        if (failSave) return respond({ error: '测试：双栈其中一种记录已存在' }, 409)
        const body = request.postDataJSON()
        const pair = ['A', 'AAAA'].map(record_type => ({ id: `dual-${record_type}`, config: { ...body.config, record_type }, revision: 1, token_configured: true, busy: false, plugin_enabled: true, server_name: '测试服务器', candidate_ip: null, ip_status: 'no_public_ip', ip_received_at: now, last_ip: null, last_success_at: null, next_run_at: 0, status: 'pending', error_code: null, failures: 0 }))
        rules.push(...pair)
        return respond({ rules: pair }, 201)
      }
      if (path === '/api/plugins/ddns/rules/test-rule') {
        if (method === 'DELETE') { rules = []; return route.fulfill({ status: 204 }) }
        const body = request.postDataJSON()
        assert.equal(body.revision, rules[0].revision)
        rules[0] = { ...rules[0], config: body.config, revision: body.revision + 1 }
        return respond(rules[0])
      }
      if (path === '/api/plugins/ddns/rules/test-rule/sync') {
        if (failSync) return respond({ error: '测试：规则正在同步，请稍后重试' }, 409)
        Object.assign(rules[0], { status: 'updated', last_ip: '2001:db8::10', last_success_at: now, next_run_at: now + 300 })
        return respond(rules[0])
      }
      unexpected.push(`${method} ${path}`)
      return respond({ error: 'Unexpected request' }, 500)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/ddns`)
    await page.getByRole('heading', { name: '动态域名解析', exact: true }).waitFor()
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/1/ddns`)
    await page.getByRole('heading', { name: '动态域名解析', exact: true }).waitFor()
    assert.equal(await page.getByText('另一台服务器', { exact: false }).count(), 0)
    await page.getByRole('button', { name: '启用 DDNS 插件', exact: true }).click()
    await page.getByRole('button', { name: '添加规则' }).click()
    const providerForm = page.getByRole('dialog')
    for (const provider of ['tencent', 'aliyun', 'huawei']) {
      await providerForm.getByLabel('DNS 提供方').selectOption(provider)
      assert.equal(await providerForm.getByLabel('访问密钥 Secret').count(), 1)
      await providerForm.getByLabel('访问密钥 ID').fill('TEST_ONLY_CLOUD_ID')
      await providerForm.getByLabel('访问密钥 Secret').fill('TEST_ONLY_CLOUD_SECRET')
      assert.equal(await providerForm.getByLabel('启用 Cloudflare 代理').count(), 0)
    }
    await providerForm.getByLabel('DNS 提供方').selectOption('cloudflare')
    assert.equal(await providerForm.getByLabel('访问密钥 Secret').count(), 0)
    const dialog = page.getByRole('dialog')
    await dialog.getByLabel('规则名称', { exact: true }).fill('家庭 IPv6')
    await dialog.getByLabel('完整域名', { exact: false }).fill('node.example.com')
    await dialog.getByLabel('Zone ID', { exact: false }).fill('00000000000000000000000000000001')
    await dialog.getByLabel('API Token', { exact: false }).fill('TEST_ONLY_CLOUDFLARE_TOKEN')
    await dialog.getByLabel('IP 类型', { exact: false }).selectOption('AAAA')
    await settle()
    const draftReads = reads.length, draftWrites = writes.length
    await advance(15_000)
    for (const path of ['/api/plugins/ddns/rules', '/api/plugins/ddns/servers']) assert(reads.slice(draftReads).includes(path), 'Editing keeps both current polling feeds live')
    assert.equal(writes.length, draftWrites, 'Fresh reads do not submit the preserved draft')
    assert.equal(await dialog.getByLabel('规则名称', { exact: true }).inputValue(), '家庭 IPv6')
    assert.equal(await dialog.getByLabel('API Token', { exact: false }).inputValue(), 'TEST_ONLY_CLOUDFLARE_TOKEN')
    await dialog.getByLabel('启用 Cloudflare 代理', { exact: false }).check()
    assert.equal(await dialog.getByLabel('TTL（秒）', { exact: false }).inputValue(), '1')
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.getByRole('alert').filter({ hasText: '测试：域名已存在规则' }).waitFor()
    assert.equal(await dialog.getByLabel('规则名称', { exact: true }).inputValue(), '家庭 IPv6')
    failSave = false
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.waitFor({ state: 'hidden' })
    await page.getByRole('heading', { name: '家庭 IPv6' }).waitFor()
    assert.equal(writes.at(-1).body.config.ttl, 1)
    assert.equal(writes.at(-1).body.config.server_id, 1)
    assert.equal(writes.at(-1).body.config.record_type, 'AAAA')
    await page.getByRole('button', { name: '编辑', exact: true }).click()
    assert.equal(await dialog.getByLabel('API Token', { exact: false }).inputValue(), '')
    assert.equal(await dialog.getByLabel('完整域名', { exact: false }).isDisabled(), true)
    await dialog.getByLabel('检查间隔（秒）', { exact: false }).fill('600')
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.equal(Object.hasOwn(writes.at(-1).body, 'api_token'), false)
    await page.getByRole('button', { name: '立即同步', exact: true }).click()
    await page.getByRole('alert').filter({ hasText: '测试：规则正在同步' }).waitFor()
    failSync = false
    await page.getByRole('button', { name: '立即同步', exact: true }).click()
    await page.getByText('已更新解析', { exact: true }).waitFor()
    const details = page.locator('.ddns-rule').first()
    Object.assign(rules[0], { candidate_ip: null, ip_status: 'no_public_ip', last_success_at: 0, ip_received_at: 0 })
    await advance(5000)
    await details.getByText('等待有效地址', { exact: true }).waitFor()
    assert.match(await details.innerText(), /上次成功地址[\s\S]*2001:db8::10/)
    assert.equal(await details.getByText('已更新解析', { exact: true }).count(), 0, 'A historical provider success cannot claim a currently available IP')
    assert.equal(await details.getByText('尚未成功', { exact: true }).count(), 0, 'A real timestamp zero is not missing')
    assert.equal(await details.getByText('尚未上报', { exact: true }).count(), 0)
    Object.assign(rules[0], { candidate_ip: null, ip_status: 'server_offline' })
    await advance(5000)
    await details.getByText('服务器离线，保留现有解析', { exact: true }).first().waitFor()
    failRules = true
    await advance(5000)
    await page.getByRole('alert').getByText('测试：规则状态不可用', { exact: true }).waitFor()
    assert.match(await page.locator('.panel-heading').last().innerText(), /— \/ 32 条/)
    for (const label of ['立即同步', '编辑', '暂停', '删除']) assert.equal(await page.getByRole('button', { name: label, exact: true }).isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: '添加规则' }).isDisabled(), true)
    assert.equal(await details.getByText('状态未知', { exact: true }).count(), 1)
    const beforeFailedWrites = writes.length
    await advance(5000)
    assert.equal(writes.length, beforeFailedWrites)
    failRules = false; failServers = true
    await advance(5000)
    await page.getByRole('alert').getByText('测试：服务器状态不可用', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '添加规则' }).isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: '停用 DDNS 插件', exact: true }).isDisabled(), true)
    failServers = false
    Object.assign(rules[0], { candidate_ip: '2001:db8::10', ip_status: 'ready', last_success_at: now, ip_received_at: now })
    await advance(5000)
    await page.getByText('已更新解析', { exact: true }).waitFor()
    await page.getByRole('button', { name: '暂停', exact: true }).click()
    await page.getByText('已暂停', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '立即同步', exact: true }).isDisabled(), true)
    const overflow = await page.evaluate(() => ({ width: window.innerWidth, scroll: document.documentElement.scrollWidth, elements: [...document.querySelectorAll('body *')].filter(element => element.getBoundingClientRect().right > window.innerWidth + 1).slice(0, 12).map(element => ({ tag: element.tagName, class: element.className, right: element.getBoundingClientRect().right })) }))
    if (overflow.scroll > width) console.log('Overflow evidence', JSON.stringify(overflow))
    assert.ok(overflow.scroll <= width)
    assert.equal(await page.locator('body').innerText().then(text => text.includes('TEST_ONLY_CLOUDFLARE_TOKEN')), false)
    if (screenshots) await page.screenshot({ path: `${screenshots}/ddns-${width}.png`, fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '编辑', exact: true }).click()
    if (screenshots) await page.screenshot({ path: `${screenshots}/ddns-editor-${width}.png`, fullPage: false, animations: 'disabled' })
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    await page.getByRole('button', { name: '停用 DDNS 插件', exact: true }).click()
    await page.getByRole('button', { name: '启用 DDNS 插件', exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '立即同步', exact: true }).isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: '启用', exact: true }).isDisabled(), true, 'A disabled server plugin cannot re-enable its rule')
    await page.getByRole('button', { name: '删除', exact: true }).click()
    await dialog.getByText(/云服务中的 DNS 记录会保留/).waitFor()
    await dialog.getByRole('button', { name: '确认删除' }).click()
    await page.getByRole('heading', { name: '尚未配置动态解析' }).waitFor()
    await page.getByRole('button', { name: '启用 DDNS 插件', exact: true }).click()
    await page.getByRole('button', { name: '添加规则' }).click()
    assert.deepEqual(await dialog.getByLabel('IP 类型').locator('option').allTextContents(), ['仅 IPv4', '仅 IPv6', 'IPv4 和 IPv6'])
    await dialog.getByLabel('IP 类型').selectOption('dual')
    await dialog.getByLabel('规则名称', { exact: true }).fill('家庭双栈')
    await dialog.getByLabel('完整域名', { exact: false }).fill('dual.example.com')
    await dialog.getByLabel('Zone ID', { exact: false }).fill('00000000000000000000000000000001')
    await dialog.getByLabel('API Token', { exact: false }).fill('TEST_ONLY_CLOUDFLARE_TOKEN')
    for (const dependency of ['rules', 'servers']) {
      let release
      held = { path: `/api/plugins/ddns/${dependency}`, reached: 0, promise: new Promise(resolve => { release = resolve }) }
      const baseline = writes.length
      await dialog.locator('form').evaluate(form => {
        document.querySelector('header.page-header button').click()
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      })
      const deadline = Date.now() + 5000
      while (!held.reached) { assert(Date.now() < deadline, 'Dual-stack prerequisite GET must be held'); await settle() }
      await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
      assert.equal(writes.length, baseline, 'Pending dual-stack reads must send zero POSTs')
      if (dependency === 'rules') failRules = true; else failServers = true
      release(); held = null
      await dialog.getByRole('alert').filter({ hasText: '刷新' }).first().waitFor()
      await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
      assert.equal(writes.length, baseline, 'Failed dual-stack reads must send zero POSTs')
      assert.equal(await dialog.getByLabel('IP 类型').inputValue(), 'dual')
      assert.equal(await dialog.getByLabel('API Token', { exact: false }).inputValue(), 'TEST_ONLY_CLOUDFLARE_TOKEN')
      if (dependency === 'rules') failRules = false; else failServers = false
      await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
      await page.waitForFunction(() => !document.querySelector('[role="dialog"] footer .button-primary')?.disabled)
    }
    const capacityRules = Array.from({ length: 31 }, (_, index) => ({ id: `capacity-${index}`, config: { name: `TEST_ONLY capacity ${index}`, server_id: 1, record_name: `capacity${index}.example.com`, record_type: 'A', enabled: false, ttl: 1, interval_secs: 300 }, revision: 1, token_configured: true, busy: false, plugin_enabled: true, server_name: '测试服务器', candidate_ip: null, ip_status: 'no_public_ip', ip_received_at: null, last_ip: null, last_success_at: null, next_run_at: null, status: 'pending', error_code: null, failures: 0 }))
    rules = capacityRules
    const beforeCapacity = writes.length
    await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
    await page.locator('.panel-heading').last().getByText('31 / 32 条', { exact: true }).waitFor()
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await dialog.getByRole('alert').filter({ hasText: '两条规则名额' }).waitFor()
    assert.equal(writes.length, beforeCapacity, 'One available slot cannot create a dual-stack pair')
    assert.equal(await dialog.getByLabel('规则名称', { exact: true }).inputValue(), '家庭双栈')
    rules = []
    await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
    await page.waitForFunction(() => !document.querySelector('[role="dialog"] footer .button-primary')?.disabled)
    failSave = true
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.getByRole('alert').filter({ hasText: '测试：双栈其中一种记录已存在' }).waitFor()
    assert.equal(await dialog.getByLabel('IP 类型').inputValue(), 'dual')
    assert.equal(await dialog.getByLabel('规则名称', { exact: true }).inputValue(), '家庭双栈')
    failSave = false
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.waitFor({ state: 'hidden' })
    assert.equal(writes.at(-1).path, '/api/plugins/ddns/rules/dual-stack')
    assert.equal(writes.at(-1).body.api_token, 'TEST_ONLY_CLOUDFLARE_TOKEN')
    assert.deepEqual(Object.keys(writes.at(-1).body).sort(), ['api_token', 'config'])
    await page.getByRole('heading', { name: '家庭双栈', exact: true }).first().waitFor()
    assert.equal(await page.getByRole('heading', { name: '家庭双栈', exact: true }).count(), 2)
    const hiddenReads = reads.length
    await page.evaluate(() => { Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' }); document.dispatchEvent(new Event('visibilitychange')) })
    await advance(15_000)
    assert.equal(reads.length, hiddenReads, 'Hidden tabs do not poll DDNS state')
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/999/ddns`)
    await page.getByText('指定服务器不存在或不可用。', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '添加规则' }).isDisabled(), true, 'An unknown scoped server cannot fall back to an enabled server')
    assert.equal(await page.getByText('另一台服务器', { exact: false }).count(), 0)
    failRules = true
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/ddns`)
    await page.getByRole('heading', { name: '规则状态暂不可用', exact: true }).waitFor()
    assert.match(await page.locator('.panel-heading').last().innerText(), /— \/ 32 条/)
    assert.equal(await page.getByRole('heading', { name: '尚未配置动态解析' }).count(), 0)
    const publicReads = reads.length, publicWrites = writes.length
    authenticated = false
    await page.reload()
    await page.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
    assert.deepEqual(reads.slice(publicReads), ['/api/dashboard/access'], 'Unauthenticated routes do not read DDNS configs or secrets')
    assert.equal(writes.length, publicWrites)
    assert.deepEqual(errors, [])
    assert.deepEqual(unexpected, [])
    results.push({ width, create: 'passed', editWithoutToken: 'passed', manualSync: 'passed', pause: 'passed', removePreservesDns: 'passed', draftPolling: 'live', unknownWrites: 'blocked', zeroTimestamps: 'preserved', noIpAndOffline: 'history preserved', hiddenPolling: 'paused', scopedServer: 'finite', unauthenticated: 'no DDNS reads' })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
