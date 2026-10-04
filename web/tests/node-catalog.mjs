import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// The shipped bundle consumes explicit public DTOs, with every write confined here.
const hash = value => createHash('sha256').update(String(value)).digest('hex')
const wait = async (condition, description) => {
  const deadline = Date.now() + 8000
  while (!await condition()) { assert(Date.now() < deadline, description); await new Promise(done => setTimeout(done, 25)) }
}
const forceSubmit = dialog => dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = process.env.SINAN_WEB_DIST ?? fileURLToPath(new URL('../dist/', import.meta.url))
const apiRoot = '/api/plugins/sing-box', catalogPath = `${apiRoot}/node-catalog`, sourcePath = `${apiRoot}/subscription-sources`
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(dist, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1440, 390, 340]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }), errors = [], writes = []
    page.setDefaultTimeout(8000)
    await page.clock.install(); await page.clock.pauseAt(new Date())
    page.on('pageerror', error => errors.push(error.message))
    const pluginServers = [{ id: 1, name: '服务器', enabled: true, online: true, agent_supported: true, read_only: false }]
    const node = { id: 1, name: '受管节点', server_id: 1, port: 443, public_host: 'managed.example.com', sni: 'www.example.com', protocol: 'vless-reality', enabled: true, protocol_config: { type: 'vless-reality' }, settings: { public_port: 8443 } }
    const managed = { id: 1, kind: 'direct', name: node.name, original_name: node.name, server_id: 1, server_name: '服务器', public_host: node.public_host, port: 443, protocol: node.protocol, enabled: true, available: true, role: 'direct', entry_node_id: null, tcp: true, udp: true, stage: 'direct', reference_count: 0, tags: [], note: '', sort_order: 0, revision: hash('managed-1'), managed_server_ids: [1], metadata_revision: 0, entry_eligible: true }
    const managedNodes = [node]
    let catalog = [managed, ...Array.from({ length: 22 }, (_, i) => ({ id: i + 1, kind: 'external', name: `外部 ${String(i + 1).padStart(2, '0')}`, original_name: `来源名称 ${i + 1}`, server_id: null, server_name: null, public_host: 'provider.example.com', port: 443, protocol: i % 2 ? 'tuic' : 'shadowsocks', enabled: true, available: true, role: 'external', tcp: true, udp: true, stage: 'external', reference_count: 0, source_id: 1, source_name: '测试来源', version_id: i + 1, identity_epoch: 1, tags: i === 0 ? ['常用'] : [], note: '', sort_order: i + 1, metadata_revision: 0, revision: hash(`external-${i + 1}-1`) }))]
    let gate, catalogFail = false, rejectBatch = false, sources = [], previewCalls = 0, previewExpiry, sourceNode = { id: 23, source_id: 1, node_version_id: 23, source_revision_id: 1, identity_epoch: 1, metadata_revision: 0, name: '导入甲', protocol: 'shadowsocks', server: 'import.example.com', port: 443, transport: 'tcp', tcp: true, udp: true, selectable: true, present: true, identity_unique: true, adopted: true, reason: null }
    const source = { id: 1, name: '导入测试', kind: 'inline', source_host: null, url_configured: false, authorization_configured: false, content_configured: true, settings_revision: 1, identity_epoch: 1, refresh_interval_seconds: 1800, auto_refresh: false, archived: false, current_revision_id: 1, last_attempt_at: 1, last_success_at: 1, last_error: null, supported_count: 2, unsupported_count: 1, active_job_id: null, dependency_ids: [], traffic: {}, changes: { added: 2, updated: 0, missing: 0, unsupported: 1 } }
    const hold = path => { let release; const promise = new Promise(done => { release = done }); return gate = { path, promise, release, reached: 0, fail: false } }
    const release = fail => { const pending = gate; gate = undefined; pending.fail = fail; pending.release() }
    await page.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
      assert.equal(url.origin, origin, 'No source/provider/cloud request may escape this fixture')
      if (!path.startsWith('/api/')) return route.continue()
      const body = method === 'GET' ? undefined : request.postData() ? request.postDataJSON() : null
      if (method !== 'GET') writes.push({ path, method, body })
      if (gate && path === gate.path && method === 'GET') { const pending = gate; pending.reached++; await pending.promise; if (pending.fail) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 当前目录依赖读取失败' } }).catch(() => {}) }
      let value
      if (path === '/api/me') value = { authenticated: true }
      else if (path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (path === `${apiRoot}/nodes`) value = managedNodes
      else if (path === `${apiRoot}/proxy-resources`) value = catalog.filter(row => row.kind === 'direct')
      else if (path === `${apiRoot}/ordered-proxy-resources`) value = proxyResourceFixtures(managedNodes, [...pluginServers, ...(!pluginServers.length ? [{ id: 1, name: '服务器', enabled: false, online: false }] : [])])
      else if (path === `${apiRoot}/ordered-subscription-sources`) value = []
      else if (path === `${apiRoot}/servers`) value = pluginServers
      else if (path === `${apiRoot}/usage`) value = { total: '0', uplink: '0', downlink: '0', by_node: [], by_user: [] }
      else if (path === catalogPath && method === 'GET') { if (catalogFail) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 目录读取失败' } }); value = catalog }
      else if (path === `${catalogPath}/batch` && method === 'POST') {
        if (rejectBatch) return route.fulfill({ status: 409, json: { error: '节点已更新，请重新确认' } })
        for (const item of body.items) {
          const current = catalog.find(row => row.kind === item.kind && row.id === item.id)
          assert(current); assert.equal(item.revision, current.revision, 'Every batch item carries its observed public CAS token')
        }
        for (const item of body.items) {
          const current = catalog.find(row => row.kind === item.kind && row.id === item.id)
          if (item.delete) catalog = catalog.filter(row => row !== current)
          else Object.assign(current, item, { metadata_revision: current.metadata_revision + 1, revision: hash(`${current.revision}:next`) })
        }
        value = body.items.map(item => catalog.find(row => row.kind === item.kind && row.id === item.id)).filter(Boolean)
      }
      else if (path === `${apiRoot}/nodes/1/clone` && method === 'POST') {
        assert.equal(body.revision, catalog.find(row => row.kind === 'direct' && row.id === 1).revision); assert.equal(body.server_id, 1); assert.equal(body.name, 'TEST_ONLY 保留副本草稿'); assert.equal(body.public_host, 'clone.example.com')
        const created = { ...node, id: 2, name: body.name, public_host: body.public_host, port: body.port ?? 20002 }; managedNodes.push(created); catalog.push({ ...managed, id: 2, name: body.name, original_name: body.name, public_host: body.public_host, port: created.port, revision: hash('clone-2') }); value = created
      }
      else if (path === sourcePath) value = sources
      else if (path === `${apiRoot}/subscription-source-previews` && method === 'POST') {
        previewCalls++; assert.equal(sources.length, 0); assert.equal(body.kind, 'inline'); assert.ok(body.content.includes('TEST_ONLY'))
        value = { id: `00000000-0000-4000-8000-${String(previewCalls).padStart(12, '0')}`, expires_at: previewExpiry, format: 'uri', supported_count: 2, unsupported_count: 1, nodes: [
          { key: 'node-0', index: 0, name: '导入甲', protocol: 'shadowsocks', server: 'import.example.com', port: 443, transport: 'tcp', tcp: true, udp: true, supported: true, reason: null },
          { key: 'node-1', index: 1, name: '导入乙', protocol: 'tuic', server: 'import.example.com', port: 8443, transport: 'quic', tcp: true, udp: true, supported: true, reason: null },
          { key: 'rejected-0', index: 2, name: '不支持节点', protocol: null, server: null, port: null, transport: null, tcp: false, udp: false, supported: false, reason: 'unsupported_proxy_protocol' },
        ] }
      }
      else if (/\/subscription-source-previews\/[0-9a-f-]+\/commit$/.test(path) && method === 'POST') {
        assert.equal(previewCalls, 2); assert.deepEqual(body.selected, ['node-0']); assert.equal(body.name, '导入测试'); assert.equal(JSON.stringify(body).includes('TEST_ONLY'), false)
        assert.deepEqual(Object.keys(body).sort(), ['auto_refresh', 'name', 'refresh_interval_seconds', 'selected'])
        sources = [source]; value = source
      }
      else if (/\/subscription-source-previews\/[0-9a-f-]+$/.test(path) && method === 'DELETE') return route.fulfill({ status: 204, body: '' })
      else if (path === `${sourcePath}/1` && method === 'PATCH') { assert.equal('refresh_interval_seconds' in body, false); assert.equal('content' in body, false); assert.equal(body.settings_revision, source.settings_revision); Object.assign(source, body, { settings_revision: source.settings_revision + 1 }); sources = [source]; value = source }
      else if (path === `${sourcePath}/1/nodes` && method === 'GET') value = [sourceNode]
      else if (path === `${sourcePath}/1/nodes/23` && method === 'PATCH') {
        assert.deepEqual(body, { adopted: true, settings_revision: source.settings_revision, identity_epoch: sourceNode.identity_epoch, node_version_id: sourceNode.node_version_id, metadata_revision: sourceNode.metadata_revision })
        sourceNode = { ...sourceNode, adopted: true, metadata_revision: sourceNode.metadata_revision + 1 }; value = sourceNode
      }
      else { errors.push(`Unexpected ${method} ${path}`); return route.fulfill({ status: 404, json: {} }) }
      return route.fulfill({ json: structuredClone(value) })
    })
    const refresh = () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
    const library = page.getByRole('region', { name: '节点库' }), dialog = page.getByRole('dialog')
    const row = name => width < 768 ? library.locator('.catalog-card').filter({ has: page.getByText(name, { exact: true }) }) : library.getByRole('row').filter({ has: page.getByText(name, { exact: true }) })
    try {
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#/plugins/sing-box/nodes`)
      await row('外部 01').waitFor(); await row('受管节点').getByText('managed.example.com:8443', { exact: true }).waitFor()
      assert.equal(await row('受管节点').getByText('0 B', { exact: true }).count(), 1)
      assert.equal(await row('外部 01').getByText('提供方计量', { exact: true }).count(), 1)
      await library.getByRole('button', { name: '下一页', exact: true }).click(); await row('外部 22').waitFor()
      await library.getByRole('button', { name: '上一页', exact: true }).click()
      await library.getByLabel('按类型筛选').selectOption('external'); await library.getByLabel('按协议筛选').selectOption('shadowsocks')
      const moved = page.waitForResponse(response => new URL(response.url()).pathname === `${catalogPath}/batch` && response.status() === 200)
      await row('外部 03').getByRole('button', { name: '上移 外部 03', exact: true }).click(); await moved
      assert.equal(catalog.find(node => node.kind === 'external' && node.id === 3).sort_order, 1); assert.equal(catalog.find(node => node.kind === 'external' && node.id === 2).sort_order, 2); assert.equal(catalog.find(node => node.kind === 'external' && node.id === 1).sort_order, 3)
      await library.getByLabel('按协议筛选').selectOption(''); await library.getByLabel('按标签筛选').selectOption('常用')
      assert.equal(await library.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr').count(), 1)
      await row('外部 01').getByRole('checkbox').check(); await library.getByRole('button', { name: '批量改名', exact: true }).click(); await dialog.getByLabel('添加文本').fill('香港 ')
      assert.ok((await dialog.innerText()).includes('香港 外部 01')); rejectBatch = true
      await dialog.getByRole('button', { name: '确认保存', exact: true }).click(); await dialog.getByText('节点已更新，请重新确认').waitFor()
      assert.equal(await dialog.getByLabel('添加文本').inputValue(), '香港 ')
      rejectBatch = false; await dialog.getByRole('button', { name: '确认保存', exact: true }).click(); await dialog.waitFor({ state: 'hidden' }); await row('香港 外部 01').waitFor()
      assert.equal(writes.filter(write => write.body?.items?.[0]?.name).at(-1).body.items[0].kind, 'external'); assert.equal(managed.name, '受管节点')
      await row('香港 外部 01').getByRole('button', { name: '整理', exact: true }).click()
      await dialog.getByLabel('备注').fill('整理后的备注'); await dialog.getByLabel(/^标签/).fill('常用, 高速')
      const save = dialog.getByRole('button', { name: '确认保存', exact: true })
      await wait(() => save.isEnabled(), 'Current metadata draft is initially writable')
      for (const dependency of [catalogPath, `${apiRoot}/nodes`, `${apiRoot}/proxy-resources`, `${apiRoot}/ordered-proxy-resources`, `${apiRoot}/servers`]) {
        const pending = hold(dependency), before = writes.length
        await refresh(); await wait(() => pending.reached > 0, `Held current GET reached ${dependency}`)
        await forceSubmit(dialog); assert.equal(writes.length, before, `${dependency} pending: actual submit issues zero POST`)
        const failed = page.waitForResponse(response => new URL(response.url()).pathname === dependency && response.status() === 503)
        release(true); await failed; await wait(() => save.isDisabled(), 'Failed GET disables the current draft')
        await forceSubmit(dialog); assert.equal(writes.length, before, `${dependency} failed: actual submit issues zero POST`)
        assert.equal(await dialog.getByLabel('备注').inputValue(), '整理后的备注')
        await refresh(); await wait(() => save.isEnabled(), `${dependency} recovery restores the original draft`)
      }
      const frozen = structuredClone(catalog), beforeMatrix = writes.length
      for (const [label, mutate] of [
        ['disappeared target', rows => rows.filter(value => !(value.kind === 'external' && value.id === 1))],
        ['changed revision', rows => { rows.find(value => value.kind === 'external' && value.id === 1).revision = hash('updated'); return rows }],
        ['unknown revision', rows => { delete rows.find(value => value.kind === 'external' && value.id === 1).revision; return rows }],
        ['invalid revision', rows => { rows.find(value => value.kind === 'external' && value.id === 1).revision = ''; return rows }],
      ]) {
        catalog = mutate(structuredClone(frozen)); const read = page.waitForResponse(response => new URL(response.url()).pathname === catalogPath && response.status() === 200)
        await refresh(); await read; await wait(() => save.isDisabled(), label)
        await forceSubmit(dialog); assert.equal(writes.length, beforeMatrix, `${label}: zero POST`)
        assert.equal(await dialog.getByLabel('备注').inputValue(), '整理后的备注')
        catalog = structuredClone(frozen); await refresh(); await wait(() => save.isEnabled(), `${label}: original target recovery`)
      }
      // Change the filter and submit in one event, before the next React render.
      await page.evaluate(() => { const filter = document.querySelector('[aria-label="按服务器筛选"]'), form = document.querySelector('[role="dialog"] form'); filter.value = '1'; filter.dispatchEvent(new Event('change', { bubbles: true })); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })) })
      assert.equal(writes.length, beforeMatrix, 'Same-event filter change rejects an external target outside the current server scope')
      assert.equal(await dialog.getByLabel('备注').inputValue(), '整理后的备注')
      await library.getByLabel('按服务器筛选').selectOption(''); await wait(() => save.isEnabled(), 'Original filter restoration preserves the draft')
      await save.click(); await dialog.waitFor({ state: 'hidden' }); await row('香港 外部 01').getByText('整理后的备注').waitFor()
      assert.equal('name' in writes.at(-1).body.items[0], false)
      // An enabled confirmation captured before a stale read still calls its real guard.
      await row('香港 外部 01').getByRole('button', { name: '删除', exact: true }).click()
      const remove = dialog.getByRole('button', { name: '确认删除节点', exact: true }), beforeDelete = writes.length
      await remove.evaluate(button => { const props = button[Object.keys(button).find(key => key.startsWith('__reactProps'))]; window.TEST_ONLY_catalog_delete = props.onClick })
      const originalDelete = structuredClone(catalog); catalog = catalog.filter(value => !(value.kind === 'external' && value.id === 1)); await refresh(); await wait(() => remove.isDisabled(), 'Deleted target cannot be confirmed from its old token')
      await page.evaluate(() => window.TEST_ONLY_catalog_delete()); assert.equal(writes.length, beforeDelete, 'Captured actual stale deletion callback issues zero POST')
      catalog = originalDelete; await refresh(); await wait(() => remove.isEnabled(), 'The original current target restores delete confirmation'); await dialog.getByRole('button', { name: '取消', exact: true }).click()
      // A missing clone target retains its ID instead of selecting another server.
      await library.getByLabel('按标签筛选').selectOption(''); await library.getByLabel('按类型筛选').selectOption('')
      await row('受管节点').getByRole('button', { name: '复制', exact: true }).click()
      await dialog.getByLabel('副本名称').fill('TEST_ONLY 保留副本草稿'); await dialog.getByLabel('公开地址', { exact: true }).fill('clone.example.com')
      const cloneSave = dialog.getByRole('button', { name: '创建副本', exact: true }), cloneBefore = writes.length, restoredServers = structuredClone(pluginServers)
      const cloning = hold(`${apiRoot}/servers`); await refresh(); await wait(() => cloning.reached > 0, 'Clone target GET is held before real submit')
      await forceSubmit(dialog); assert.equal(writes.length, cloneBefore, 'A pending target GET blocks the actual clone callback')
      release(false); await wait(() => cloneSave.isEnabled(), 'The unchanged target GET recovers the clone draft')
      pluginServers.splice(0); await refresh(); await wait(() => cloneSave.isDisabled(), 'Disappeared target server blocks cloning')
      assert.equal(await dialog.getByLabel('目标服务器').inputValue(), '1')
      await forceSubmit(dialog); assert.equal(writes.length, cloneBefore, 'Unknown clone target issues zero POST'); assert.equal(await dialog.getByLabel('副本名称').inputValue(), 'TEST_ONLY 保留副本草稿'); assert.equal(await dialog.getByLabel('公开地址', { exact: true }).inputValue(), 'clone.example.com')
      pluginServers.push(...restoredServers); await refresh(); await wait(() => cloneSave.isEnabled(), 'Original server restores the exact clone draft')
      await cloneSave.click(); await dialog.waitFor({ state: 'hidden' }); await row('TEST_ONLY 保留副本草稿').waitFor()
      assert.equal(writes.length, cloneBefore + 1)
      // Preview credentials are removed from the DOM; expiry and parent failure block commit.
      await page.getByRole('region', { name: '订阅来源', exact: true }).getByRole('button', { name: '添加来源', exact: true }).first().click()
      await dialog.getByLabel('来源名称').fill('导入测试'); await dialog.getByLabel('来源类型').selectOption('inline'); await dialog.getByLabel('配置内容').fill('TEST_ONLY provider data')
      previewExpiry = Math.floor(await page.evaluate(() => Date.now()) / 1000) + 600
      await dialog.getByRole('button', { name: '解析并预览', exact: true }).click(); await dialog.getByRole('checkbox', { name: '导入 导入乙' }).uncheck()
      assert.equal(sources.length, 0); assert.equal(await dialog.getByRole('checkbox', { name: '导入 不支持节点' }).isDisabled(), true); assert.equal(await dialog.locator('textarea').count(), 0)
      const beforePreview = writes.length, importing = hold(sourcePath)
      await page.getByRole('region', { name: '订阅来源', exact: true }).getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click()); await wait(() => importing.reached > 0, 'The current source list GET is truly pending')
      await forceSubmit(dialog); assert.equal(writes.length, beforePreview, 'Pending source GET cannot commit the retained preview')
      release(false); await wait(() => dialog.getByRole('button', { name: '加入节点库（1）', exact: true }).isEnabled(), 'Source list recovery permits the retained selection')
      await page.clock.fastForward(601000)
      await wait(() => dialog.getByRole('button', { name: '加入节点库（1）', exact: true }).isDisabled(), 'Fresh preview expires on the real clock')
      await dialog.getByText('导入预览已过期，请重新解析；当前选择已保留。', { exact: true }).waitFor()
      await forceSubmit(dialog); assert.equal(writes.length, beforePreview, 'Expired preview cannot POST even through real submit')
      assert.equal(await dialog.getByRole('checkbox', { name: '导入 导入甲' }).isChecked(), true)
      await dialog.getByRole('button', { name: '重新填写', exact: true }).click(); await dialog.getByLabel('配置内容').fill('TEST_ONLY provider data')
      previewExpiry = Math.floor(await page.evaluate(() => Date.now()) / 1000) + 600
      await dialog.getByRole('button', { name: '解析并预览', exact: true }).click(); await dialog.getByRole('checkbox', { name: '导入 导入乙' }).uncheck()
      await dialog.getByRole('button', { name: '加入节点库（1）', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
      const sourceRegion = page.getByRole('region', { name: '订阅来源', exact: true })
      await sourceRegion.getByRole('button', { name: '查看节点', exact: true }).click(); await sourceRegion.getByRole('button', { name: '移出节点库', exact: true }).waitFor()
      const adoptBefore = writes.length
      await sourceRegion.getByRole('button', { name: '移出节点库', exact: true }).evaluate(button => { window.TEST_ONLY_old_adopt = button[Object.keys(button).find(key => key.startsWith('__reactProps'))].onClick })
      sourceNode = { ...sourceNode, adopted: false, metadata_revision: 1 }; await sourceRegion.getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
      await sourceRegion.getByRole('button', { name: '加入节点库', exact: true }).waitFor()
      await page.evaluate(() => window.TEST_ONLY_old_adopt()); assert.equal(writes.length, adoptBefore, 'Same-version catalog deletion advances metadata and blocks the captured adoption intent')
      await sourceRegion.getByRole('button', { name: '加入节点库', exact: true }).click(); await sourceRegion.getByRole('button', { name: '移出节点库', exact: true }).waitFor()
      assert.equal(writes.at(-1).body.metadata_revision, 1, 'Explicit new confirmation uses the current metadata revision')
      await sourceRegion.getByRole('button', { name: '设置与更新', exact: true }).click(); await dialog.getByLabel('来源名称').fill('导入测试改名'); await dialog.getByRole('button', { name: '保存并解析更新', exact: true }).click(); await dialog.waitFor({ state: 'hidden' }); assert.equal(source.refresh_interval_seconds, 1800)
      assert.equal(sources.length, 1); assert.equal(await page.evaluate(() => Object.values(localStorage).some(value => value.includes('TEST_ONLY'))), false)
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `overflow at ${width}`)
      assert.deepEqual(errors, [])
      if (process.env.SINAN_UI_SCREENSHOT_DIR) { await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true }); await page.screenshot({ path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `node-catalog-${width}.png`), fullPage: true }) }
      console.log(`node catalog ${width}: current-read/identity/filter/delete zero-write matrix, CAS recovery, preview expiry/privacy and adoption metadata confirmed`)
    } finally { gate?.release(); await page.close() }
  }
} finally { await browser.close(); await new Promise(done => server.close(done)) }
