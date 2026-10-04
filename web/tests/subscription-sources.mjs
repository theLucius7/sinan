import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'
import { sourceJobFixture, sourceNodeFixture, sourceNodePageFixture, sourceRevisionFixture, sourceUuid, subscriptionSourceFixture } from './subscription-source-fixtures.mjs'

// Exercise the built UI, with strict owned fixtures. No upstream requests or parser execution.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(dist, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
let browser
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  const origin = `http://127.0.0.1:${server.address().port}`, prefix = '/api/plugins/sing-box', sourceRoot = `${prefix}/ordered-subscription-sources`, jobRoot = `${prefix}/ordered-subscription-source-jobs`
  for (const width of [1440, 390, 320]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    page.setDefaultTimeout(8000)
    await page.clock.install()
    const errors = [], writes = [], receipts = new Map(), jobs = new Map()
    const servers = [1, 2].map(id => ({ id, name: `受管服务器 ${id}`, enabled: true, online: false, agent_supported: true, read_only: false }))
    const nodes = [1, 2].map(id => ({ id, name: `受管监听 ${id}`, server_id: id, protocol: 'vless-reality', enabled: true, public_host: `managed${id}.example.com`, sni: 'www.example.com', port: 20000 + id }))
    const revision = sourceRevisionFixture(1, { counts: { supported: 2, unsupported: 1, ambiguous: 1, missing: 1 } }), olderRevision = sourceRevisionFixture(1, { id: sourceUuid(100), parsed_at: 1790860700 })
    const preview = [sourceNodeFixture(), sourceNodeFixture({ id: sourceUuid(302), version_id: sourceUuid(402), ordinal: 1, name: '不支持的示例', supported: false, selectable: false, identity_state: 'unresolved', parse_status: 'unsupported', protocol: null, server: null, server_port: null, sni: null, transport: null, capabilities: { tcp: false, udp: false }, unsupported_reasons: [{ code: 'unsupported_transport', message: '传输参数尚不支持' }] }), sourceNodeFixture({ id: sourceUuid(303), version_id: sourceUuid(403), ordinal: 2, name: '缺失的示例', present_in_latest: false, selectable: false, source_revision_id: olderRevision.id, reasons: ['当前成功批次缺失，保留历史版本'] }), sourceNodeFixture({ id: sourceUuid(304), version_id: sourceUuid(404), ordinal: 3, name: '不唯一的示例', identity_state: 'ambiguous', selectable: false, reasons: ['节点身份不唯一'] })]
    let sources = [subscriptionSourceFixture({ latest_success: revision, counts: revision.counts })], listMode = 'ok', oldNodesFailure = false, createMode = 'lose', patchMode = 'normal', deleteConflict = true, allocations = 0, nextSource = 2
    let heldEntered, heldRelease
    const heldStarted = new Promise(resolve => { heldEntered = resolve }), heldDone = new Promise(resolve => { heldRelease = resolve })
    let timeoutEntered, timeoutRelease
    const timeoutStarted = new Promise(resolve => { timeoutEntered = resolve }), timeoutDone = new Promise(resolve => { timeoutRelease = resolve })
    page.on('pageerror', error => errors.push(error.message))
    page.on('request', request => { if (!request.url().startsWith(origin)) errors.push(`Unexpected outbound URL: ${request.url()}`) })
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      if (method !== 'GET') writes.push({ path, method, serialized: request.postData(), body: request.postData() ? request.postDataJSON() : null })
      let value
      if (method === 'GET' && path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (method === 'GET' && path === '/api/me') value = { authenticated: true }
      else if (method === 'GET' && path === `${prefix}/servers`) value = servers
      else if (method === 'GET' && path === `${prefix}/nodes`) {
        if (oldNodesFailure) { await route.fulfill({ status: 500, json: { error: '旧节点元数据损坏' } }); return }
        value = nodes
      } else if (method === 'GET' && path === `${prefix}/proxy-resources`) value = flatResourceFixtures(nodes, servers)
      else if (method === 'GET' && path === `${prefix}/node-catalog`) value = catalogResourceFixtures(flatResourceFixtures(nodes, servers))
      else if (method === 'GET' && path === `${prefix}/ordered-proxy-resources`) value = proxyResourceFixtures(nodes, servers)
      else if (method === 'GET' && path === `${prefix}/subscription-sources`) value = []
      else if (method === 'GET' && path === `${prefix}/usage`) value = { total: '0', uplink: '0', downlink: '0', by_node: [], by_user: [] }
      else if (method === 'GET' && path === sourceRoot) {
        if (listMode === 'failed') { await route.fulfill({ status: 403, json: { error: '来源夹具读取被拒绝' } }); return }
        if (listMode === 'held') { heldEntered(); await heldDone }
        value = listMode === 'malformed' ? [{ id: 1, name: '旧版残缺元数据' }] : sources
      } else if (method === 'GET' && /^\/api\/plugins\/sing-box\/ordered-subscription-sources\/[1-9]\d*$/.test(path)) {
        value = sources.find(source => source.id === Number(path.split('/').at(-1)))
        if (!value) { await route.fulfill({ status: 404, json: { error: '来源已删除' } }); return }
      } else if (method === 'GET' && /^\/api\/plugins\/sing-box\/ordered-subscription-sources\/[1-9]\d*\/revisions$/.test(path)) {
        const sourceId = Number(path.split('/').at(-2)), item = sources.find(source => source.id === sourceId)
        assert(item); value = { source_id: sourceId, revisions: item.latest_success ? sourceId === 1 ? [revision, olderRevision] : [item.latest_success] : [] }
      } else if (method === 'GET' && /^\/api\/plugins\/sing-box\/ordered-subscription-sources\/[1-9]\d*(\/revisions\/[0-9a-f-]+)?\/nodes$/.test(path)) {
        const segments = path.split('/'), sourceId = Number(segments[5]), item = sources.find(source => source.id === sourceId), historical = segments.includes('revisions')
        assert(item)
        const success = historical ? [revision, olderRevision].find(value => value.id === segments[7]) : item.latest_success
        assert(!historical || success)
        const rows = historical ? success.id === olderRevision.id ? [preview[2]] : preview.filter(node => node.present_in_latest) : preview
        value = sourceNodePageFixture({ source_id: sourceId, current_settings_revision: item.settings_revision, current_identity_epoch: item.identity_epoch, success_revision: success, nodes: sourceId === 1 && (historical || item.identity_epoch === 1) ? rows.map(node => ({ ...node, selectable: !historical && !item.archived && node.selectable, ...(historical ? { present_in_latest: true, reasons: [...node.reasons, '历史批次仅供查看'] } : {}) })) : [] })
      } else if (method === 'GET' && path.startsWith(`${jobRoot}/`)) {
        value = jobs.get(path.split('/').at(-1)); assert(value)
      } else if ((method === 'POST' && path === sourceRoot) || (method === 'PATCH' && /^\/api\/plugins\/sing-box\/ordered-subscription-sources\/[1-9]\d*$/.test(path))) {
        const body = request.postDataJSON()
        assert.match(body.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
        if (receipts.has(body.request_id)) { const previous = receipts.get(body.request_id); assert.equal(request.postData(), previous.serialized); await route.fulfill({ json: previous.receipt }); return }
        let item, job_id = null
        if (method === 'POST') {
          assert(body.input.kind === 'inline' || body.input.kind === 'url')
          if (body.input.kind === 'url') { assert.equal(body.input.url, 'https://subscription.example.com/private?token=TEST_ONLY'); assert.deepEqual(body.input.auth_headers, { authorization: 'Bearer TEST_ONLY', cookie: 'session=TEST_ONLY', 'x-api-key': 'TEST_ONLY' }) }
          else assert.match(body.input.content, /TEST_ONLY_FILE/)
          const sourceId = nextSource++, job = sourceJobFixture(sourceId)
          jobs.set(job.id, job); job_id = job.id
          item = subscriptionSourceFixture({ id: sourceId, name: body.name, kind: body.input.kind, host: body.input.kind === 'url' ? 'subscription.example.com' : null, auth_configured: body.input.kind === 'url', refresh_interval_secs: body.input.kind === 'url' ? body.refresh_interval_secs : 0, latest_success: null, active_job: job, counts: { supported: 0, unsupported: 0, ambiguous: 0, missing: 0 }, last_success_at: null })
          sources.push(item); allocations++
        } else {
          item = sources.find(source => source.id === Number(path.split('/').at(-1))); assert(item)
          assert.equal(body.settings_revision, item.settings_revision)
          item.settings_revision++
          if (body.name !== undefined) item.name = body.name
          if (body.refresh_interval_secs !== undefined) item.refresh_interval_secs = body.refresh_interval_secs
          if (body.archived !== undefined) item.archived = body.archived
          if (body.input) {
            if (body.input.kind === 'inline') { assert(['update', 'replace'].includes(body.input.identity_action)); if (body.input.identity_action === 'replace') item.identity_epoch++ }
            else { assert.equal(body.input.kind, 'url'); assert.equal(body.input.url, 'https://replacement.example.com/new?token=TEST_ONLY_REPLACE'); assert.deepEqual(body.input.auth_headers, { action: 'clear' }); item.identity_epoch++; item.host = 'replacement.example.com'; item.auth_configured = false }
            const job = sourceJobFixture(item.id, { id: sourceUuid(1000 + item.id * 100 + item.settings_revision), settings_revision: item.settings_revision, identity_epoch: item.identity_epoch })
            jobs.set(job.id, job); item.active_job = job; job_id = job.id
          }
        }
        const result = { source_id: item.id, settings_revision: item.settings_revision, identity_epoch: item.identity_epoch, job_id }
        receipts.set(body.request_id, { serialized: request.postData(), receipt: result })
        if (method === 'POST' && createMode === 'lose') { createMode = 'normal'; await route.abort('connectionreset'); return }
        if (method === 'POST' && createMode === 'timeout') { createMode = 'normal'; timeoutEntered(); await timeoutDone; await route.abort('timedout').catch(error => { if (!/handled|closed|cancel|abort/i.test(error.message)) throw error }); return }
        if (method === 'PATCH' && patchMode === 'lose') { patchMode = 'normal'; await route.abort('connectionreset'); return }
        await route.fulfill({ status: method === 'POST' ? 202 : 200, json: result }); return
      } else if (method === 'POST' && /^\/api\/plugins\/sing-box\/ordered-subscription-sources\/[1-9]\d*\/refresh$/.test(path)) {
        const item = sources.find(source => source.id === Number(path.split('/').at(-2))); assert(item)
        assert.deepEqual(request.postDataJSON(), { settings_revision: item.settings_revision })
        const job = item.active_job ?? sourceJobFixture(item.id, { id: sourceUuid(800 + item.id), settings_revision: item.settings_revision, identity_epoch: item.identity_epoch, status: 'running', stage: 'fetch', started_at: 1790860801 })
        item.active_job = job; jobs.set(job.id, job); await route.fulfill({ status: 202, json: job }); return
      } else if (method === 'POST' && /^\/api\/plugins\/sing-box\/ordered-subscription-source-jobs\/[0-9a-f-]+\/cancel$/.test(path)) {
        const job = jobs.get(path.split('/').at(-2)); assert(job); assert.equal(request.postData(), null)
        job.status = 'cancelling'; value = job
      } else if (method === 'DELETE' && path === `${sourceRoot}/1`) {
        assert.deepEqual(request.postDataJSON(), { settings_revision: sources.find(source => source.id === 1).settings_revision })
        if (deleteConflict) { await route.fulfill({ status: 409, json: { error: '来源仍被当前路径「引用示例」#7 引用；请先解除引用。' } }); return }
        sources = sources.filter(source => source.id !== 1); await route.fulfill({ status: 204, body: '' }); return
      } else { errors.push(`Unexpected API: ${method} ${path}`); await route.fulfill({ status: 404, json: { error: '夹具拒绝未知接口' } }); return }
      // Public read fixtures deliberately contain no raw input or authentication values.
      if (method === 'GET' && path.startsWith(sourceRoot)) assert(!JSON.stringify(value).includes('TEST_ONLY'))
      await route.fulfill({ json: value })
    })
    const manager = page.getByRole('region', { name: '订阅来源管理', exact: true }), dialog = page.getByRole('dialog')
    const enable = async locator => { await locator.waitFor(); const deadline = Date.now() + 8000; while (await locator.isDisabled() && Date.now() < deadline) await page.waitForTimeout(20); assert.equal(await locator.isDisabled(), false) }
    const reloadList = async () => { const response = page.waitForResponse(response => new URL(response.url()).pathname === sourceRoot && response.request().method() === 'GET'); await manager.getByRole('button', { name: '刷新来源列表', exact: true }).click(); await response }
    const force = async label => page.evaluate(label => { const region = document.querySelector('[aria-label="订阅来源管理"]'); const button = [...region.querySelectorAll('button')].find(button => button.textContent.trim() === label); assertButton(button); function assertButton(button) { if (!button) throw new Error('Missing force target'); const key = Object.keys(button).find(key => key.startsWith('__reactProps')); if (!key || typeof button[key].onClick !== 'function') throw new Error('Missing actual click handler'); button[key].onClick() } }, label)
    const shot = async name => {
      if (!process.env.SINAN_UI_SCREENSHOT_DIR) return
      if (await dialog.count()) {
        // Finish this finite entrance animation without advancing the mocked job/request clocks.
        const appearance = await dialog.evaluate(element => {
          const shade = element.closest('.modal-shade')
          for (const animation of shade?.getAnimations() ?? []) {
            if (Number.isFinite(animation.effect?.getComputedTiming().endTime) && animation.playbackRate > 0) animation.finish()
          }
          const modalStyle = getComputedStyle(element)
          return { opacity: Number(modalStyle.opacity), background: modalStyle.backgroundColor, shadeOpacity: shade ? Number(getComputedStyle(shade).opacity) : null }
        })
        assert.equal(appearance.opacity, 1, 'the actual dialog must be opaque before capture')
        assert.equal(appearance.shadeOpacity, 1, 'the modal entrance animation must finish before capture')
        assert.equal(appearance.background, 'rgb(255, 255, 255)', 'capture must retain the shipped opaque dialog background')
        console.log(`SCREENSHOT: ${name} ${width} dialog=${appearance.opacity} shade=${appearance.shadeOpacity} background=${appearance.background}`)
      }
      await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true })
      await page.screenshot({ animations: 'disabled', path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `sources-${name}-${width}.png`) })
    }
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/sing-box/nodes`)
    await enable(manager.getByRole('button', { name: '添加订阅来源', exact: true }))
    assert.equal(await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '订阅来源', exact: true }).count(), 0)
    assert.equal(await page.locator('.stat').filter({ hasText: '代理资源' }).locator('strong').innerText(), '2')
    await page.getByRole('button', { name: '创建两跳链路', exact: true }).click(); await dialog.locator('[name=name]').fill('必须保留的两跳草稿'); await dialog.getByRole('button', { name: '取消', exact: true }).click()
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click()
    await dialog.getByText('外部示例节点', { exact: true }).waitFor()
    await dialog.getByText('端点未知', { exact: true }).waitFor()
    await dialog.getByText('身份不唯一', { exact: true }).waitFor()
    await dialog.getByText('身份尚未确认', { exact: true }).waitFor()
    await dialog.getByText('当前批次缺失', { exact: true }).waitFor()
    assert.equal(await dialog.getByText('可供后续路径引用', { exact: true }).count(), 1)
    assert.equal(await dialog.getByRole('button', { name: /创建链路|选择此节点|加入链路/ }).count(), 0)
    await shot('preview')
    await dialog.getByRole('combobox', { name: '选择订阅版本', exact: true }).selectOption(olderRevision.id)
    await dialog.getByText('此历史版本视图仅供查看，不提供新的引用操作。', { exact: true }).waitFor()
    assert.equal(await dialog.getByText('可供后续路径引用', { exact: true }).count(), 0)
    await dialog.getByRole('button', { name: '关闭来源详情', exact: true }).click()
    await shot('list')
    for (const mode of ['failed', 'malformed']) {
      listMode = mode; await reloadList(); await manager.getByText('来源修改暂不可用，已读取的历史信息仍可查看。', { exact: true }).waitFor()
      const before = writes.length; await force('添加订阅来源'); await force('抓取并解析'); await force('删除来源'); assert.equal(writes.length, before)
      assert.equal(await page.getByRole('button', { name: '创建节点', exact: true }).first().isDisabled(), false)
      assert.equal(await manager.getByText('示例订阅', { exact: true }).count(), 1)
      listMode = 'ok'; await reloadList(); await enable(manager.getByRole('button', { name: '添加订阅来源', exact: true }))
    }
    listMode = 'held'; await manager.getByRole('button', { name: '刷新来源列表', exact: true }).click(); await heldStarted
    const beforeHeld = writes.length; await force('添加订阅来源'); await force('删除来源'); assert.equal(writes.length, beforeHeld)
    listMode = 'ok'; heldRelease(); await enable(manager.getByRole('button', { name: '添加订阅来源', exact: true }))
    oldNodesFailure = true; await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByText('旧节点元数据损坏', { exact: true }).waitFor()
    await manager.getByRole('button', { name: '添加订阅来源', exact: true }).click()
    await dialog.locator('[name=source_name]').fill('URL 新来源')
    await dialog.locator('[name=source_url]').fill('https://subscription.example.com/private?token=TEST_ONLY')
    await dialog.locator('[name=source_authorization]').fill('Bearer TEST_ONLY'); await dialog.locator('[name=source_cookie]').fill('session=TEST_ONLY'); await dialog.locator('[name=source_apiKey]').fill('TEST_ONLY')
    await shot('url-editor')
    await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await dialog.getByRole('alert').filter({ hasText: '无法连接面板' }).waitFor()
    const firstCreate = writes.find(write => write.path === sourceRoot && write.method === 'POST')
    await dialog.getByRole('button', { name: '重试', exact: true }).click()
    await enable(dialog.getByRole('button', { name: '重试原请求', exact: true }))
    await dialog.getByRole('button', { name: '重试原请求', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    const createWrites = writes.filter(write => write.path === sourceRoot && write.method === 'POST')
    assert.equal(createWrites.length, 2); assert.equal(createWrites[1].serialized, firstCreate.serialized); assert.equal(allocations, 1)
    await manager.getByText('URL 新来源', { exact: true }).waitFor()
    await manager.getByRole('button', { name: '添加订阅来源', exact: true }).click()
    assert.equal(await dialog.locator('[name=source_url]').inputValue(), ''); assert.equal(await dialog.locator('[name=source_authorization]').inputValue(), '')
    await dialog.locator('[name=source_name]').fill('文件来源'); await dialog.getByRole('combobox', { name: '订阅输入方式', exact: true }).selectOption('inline')
    await dialog.locator('[name=source_file]').setInputFiles({ name: 'source.txt', mimeType: 'text/plain', buffer: Buffer.from('trojan://TEST_ONLY_FILE@exit.example.com:443#file') })
    await dialog.getByText('已读取：source.txt', { exact: true }).waitFor(); createMode = 'timeout'; await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await timeoutStarted
    await page.clock.fastForward(30000); await dialog.getByRole('alert').filter({ hasText: '请求超时' }).waitFor(); timeoutRelease()
    const fileFirst = writes.filter(write => write.path === sourceRoot && write.method === 'POST').at(-1)
    assert.equal(await dialog.locator('[name=source_content]').inputValue(), 'trojan://TEST_ONLY_FILE@exit.example.com:443#file')
    await enable(dialog.getByRole('button', { name: '重试原请求', exact: true })); await dialog.getByRole('button', { name: '重试原请求', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    assert.equal(writes.filter(write => write.path === sourceRoot && write.method === 'POST').at(-1).serialized, fileFirst.serialized); assert.equal(allocations, 2)
    await manager.getByText('文件来源', { exact: true }).waitFor()
    await manager.getByRole('button', { name: '添加订阅来源', exact: true }).click(); await dialog.getByRole('combobox', { name: '订阅输入方式', exact: true }).selectOption('inline')
    assert.equal(await dialog.locator('[name=source_content]').inputValue(), ''); assert.equal(await dialog.locator('[name=source_file]').evaluate(element => element.files.length), 0)
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    assert.equal(await page.evaluate(() => Object.keys(localStorage).some(key => /source|subscription/i.test(key))), false)
    await enable(manager.locator('[data-source-id="3"]').getByRole('button', { name: '更新内容', exact: true })); await manager.locator('[data-source-id="3"]').getByRole('button', { name: '更新内容', exact: true }).click()
    assert.equal(await dialog.locator('[name=source_content]').inputValue(), '')
    await dialog.locator('[name=source_content]').fill('trojan://TEST_ONLY_UPDATE@exit.example.com:443'); await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    assert.equal(writes.filter(write => write.path === `${sourceRoot}/3` && write.method === 'PATCH').at(-1).body.input.identity_action, 'update'); assert.equal(sources.find(source => source.id === 3).identity_epoch, 1)
    await manager.locator('[data-source-id="3"]').getByRole('button', { name: '查看来源', exact: true }).click(); await enable(dialog.getByRole('button', { name: '更换来源', exact: true })); await dialog.getByRole('button', { name: '更换来源', exact: true }).click()
    await dialog.locator('[name=source_content]').fill('trojan://TEST_ONLY_REPLACE_FILE@other.example.com:443'); await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    assert.equal(writes.filter(write => write.path === `${sourceRoot}/3` && write.method === 'PATCH').at(-1).body.input.identity_action, 'replace'); assert.equal(sources.find(source => source.id === 3).identity_epoch, 2)
    patchMode = 'lose'
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); await enable(dialog.getByRole('button', { name: '修改名称与周期', exact: true })); await dialog.getByRole('button', { name: '修改名称与周期', exact: true }).click()
    await dialog.locator('[name=source_name]').fill('新名称'); await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await dialog.getByRole('alert').filter({ hasText: '无法连接面板' }).waitFor()
    sources[0].identity_epoch = 2
    await dialog.getByRole('button', { name: '重试', exact: true }).click()
    await dialog.getByRole('alert').filter({ hasText: '来源身份代次已变化' }).waitFor()
    const retryPatch = dialog.getByRole('button', { name: '重试原请求', exact: true }), beforeRetry = writes.length
    assert.equal(await retryPatch.isDisabled(), true); assert.equal(await dialog.locator('[name=source_name]').inputValue(), '新名称')
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await retryPatch.evaluate(button => { const disabled = button.disabled; try { button.disabled = false; button.click() } finally { button.disabled = disabled } })
    await page.waitForTimeout(50); assert.equal(writes.length, beforeRetry)
    sources[0].identity_epoch = 1
    await dialog.getByRole('button', { name: '重试', exact: true }).click(); await enable(retryPatch); await retryPatch.click(); await dialog.waitFor({ state: 'hidden' })
    const patchWrites = writes.filter(write => write.path === `${sourceRoot}/1` && write.method === 'PATCH'); assert.equal(patchWrites.length, 2); assert.equal(patchWrites[0].serialized, patchWrites[1].serialized)
    await manager.getByText('新名称', { exact: true }).waitFor()
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '抓取并解析', exact: true }).click()
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); await enable(dialog.getByRole('button', { name: '取消来源任务', exact: true })); await dialog.getByRole('button', { name: '取消来源任务', exact: true }).click()
    await dialog.getByRole('button', { name: '等待取消确认', exact: true }).waitFor(); assert.equal(await dialog.getByRole('button', { name: '等待取消确认', exact: true }).isDisabled(), true)
    const running = sources[0].active_job; running.status = 'cancelled'; running.stage = 'done'; running.finished_at = 1790860810; sources[0].active_job = null
    await page.clock.fastForward(1500); await dialog.getByText('已取消', { exact: true }).waitFor()
    await dialog.getByRole('button', { name: '关闭来源详情', exact: true }).click()
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); await enable(dialog.getByRole('button', { name: '更换来源', exact: true })); await dialog.getByRole('button', { name: '更换来源', exact: true }).click()
    assert.equal(await dialog.locator('[name=source_url]').inputValue(), '')
    await dialog.locator('[name=source_url]').fill('https://replacement.example.com/new?token=TEST_ONLY_REPLACE'); await dialog.getByRole('combobox', { name: '认证信息处理', exact: true }).selectOption('clear'); await dialog.getByRole('button', { name: '保存来源', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    for (const failure of [{ stage: 'fetch', kind: 'http_429', message: '订阅服务请求受限', http_status: 429 }, { stage: 'fetch', kind: 'timeout', message: '订阅请求超时', http_status: null }]) {
      Object.assign(sources[0], { active_job: null, last_error: failure, stale_reason: '更新失败，显示上次成功解析的历史结果' }); await reloadList(); await manager.locator('[data-source-id="1"]').getByText(failure.message, { exact: false }).waitFor()
      assert.equal(sources[0].latest_success.id, revision.id)
    }
    Object.assign(sources[0], { last_error: { stage: 'fetch', kind: 'http_403', message: '订阅服务拒绝访问', http_status: 403 }, stale_reason: '来源已更换，显示原来源历史结果；需要重新选点' })
    await reloadList(); await manager.locator('[data-source-id="1"]').getByText('http_403', { exact: false }).waitFor()
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); await dialog.getByText('上次成功版本保留。', { exact: false }).waitFor()
    await dialog.getByRole('combobox', { name: '选择订阅版本', exact: true }).selectOption(revision.id); await dialog.getByText('外部示例节点', { exact: true }).waitFor(); assert.equal(await dialog.getByText('可供后续路径引用', { exact: true }).count(), 0)
    await shot('historical-failure')
    await enable(dialog.getByRole('button', { name: '归档来源', exact: true })); await dialog.getByRole('button', { name: '归档来源', exact: true }).click(); await dialog.getByRole('button', { name: '确认归档', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    await manager.locator('[data-source-id="1"]').waitFor({ state: 'hidden' }); await manager.getByRole('checkbox', { name: '显示已归档来源', exact: true }).check()
    assert.equal(await manager.locator('[data-source-id="1"]').getByRole('button', { name: '抓取并解析', exact: true }).isDisabled(), true)
    await manager.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); await enable(dialog.getByRole('button', { name: '恢复来源', exact: true })); await dialog.getByRole('button', { name: '恢复来源', exact: true }).click(); await dialog.getByRole('button', { name: '确认恢复', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    await enable(manager.locator('[data-source-id="1"]').getByRole('button', { name: '删除来源', exact: true })); await manager.locator('[data-source-id="1"]').getByRole('button', { name: '删除来源', exact: true }).click(); await dialog.getByRole('button', { name: '确认删除', exact: true }).click(); await dialog.getByRole('alert').filter({ hasText: '#7' }).waitFor()
    assert.equal(await manager.locator('[data-source-id="1"]').count(), 1)
    deleteConflict = false; await dialog.getByRole('button', { name: '确认删除', exact: true }).click(); await dialog.waitFor({ state: 'hidden' }); await manager.locator('[data-source-id="1"]').waitFor({ state: 'hidden' })
    oldNodesFailure = false; await page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click(); await enable(page.getByRole('button', { name: '创建两跳链路', exact: true })); await page.getByRole('button', { name: '创建两跳链路', exact: true }).click()
    assert.equal(await dialog.locator('[name=name]').inputValue(), '必须保留的两跳草稿')
    assert.equal(await dialog.locator('[name=exit_node_id] option').filter({ hasText: '外部示例节点' }).count(), 0)
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    assert.equal(await page.locator('.stat').filter({ hasText: '代理资源' }).locator('strong').innerText(), '2')
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true)
    assert.deepEqual(errors, [])
    await page.close()
  }
  console.log('PASS: Sources public preview, unsupported/missing/ambiguous/history, fresh write guards, original create/PATCH replays, cleared URL/auth/file, independent old-node failure, pending cancellation, replacement failure cache, archive/restore/refusal/delete, preserved two-hop draft, desktop/mobile')
} finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)) }
