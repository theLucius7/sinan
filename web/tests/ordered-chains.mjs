import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { orderedResourceFixture, pathFixtureUuid, flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'
import { sourceNodeFixture, sourceNodePageFixture, sourceRevisionFixture, sourceUuid, subscriptionSourceFixture } from './subscription-source-fixtures.mjs'

// Serve the real final dist. Owned public fixtures exercise UI contracts, not live proxy delivery.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const file = resolve(dist, new URL(request.url, 'http://127.0.0.1').pathname === '/' ? 'index.html' : `.${new URL(request.url, 'http://127.0.0.1').pathname}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
let browser
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  const origin = `http://127.0.0.1:${server.address().port}`, prefix = '/api/plugins/sing-box'
  for (const width of [1440, 390, 320]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(7000); await page.clock.install()
    const errors = [], writes = [], receipts = new Map(), mutations = new Map()
    page.on('pageerror', error => errors.push(error.message))
    const servers = [1, 2, 3].map(id => ({ id, name: `服务器 ${id}`, enabled: true, online: false, read_only: false, source: 'administrator', agent_supported: true }))
    let nodes = [1, 2, 3, 10, 11].map(id => ({ id, name: `节点 ${id}`, server_id: id >= 10 ? 1 : id, protocol: 'vless-reality', enabled: true, port: 20000 + id, public_host: `node${id}.example.com`, sni: 'www.example.com', public_key: 'TEST_ONLY', short_id: 'abcd' }))
    const legacy = [{ id: 1, name: '旧两跳', entry_node_id: 10, exit_node_id: 2, available: true }]
    let source = subscriptionSourceFixture(), sourceNodes = [sourceNodeFixture({ version_id: sourceUuid(405) })], sourceFailure = false, oldNodesFailure = false
    const endpoint = id => proxyResourceFixtures(nodes, servers).find(value => value.kind === 'direct' && value.id === id).entry
    const sourceHop = (position, version = sourceUuid(405), mode = 'pinned') => ({ kind: 'subscription', position, source_id: 1, source_name: source.name, identity_epoch: 1, external_node_id: sourceUuid(301), node_version_id: version, source_revision_id: sourceUuid(101), update_mode: mode, name: '外部示例节点', protocol: 'trojan', server: 'exit.example.com', server_port: 443, sni: 'exit.example.com', transport: 'tcp', capabilities: { tcp: true, udp: true }, source_archived: false, node_present: true, update_error: null })
    const managedHop = (position, id) => ({ kind: 'managed', position, node_id: id, endpoint_version_id: pathFixtureUuid(id), endpoint: endpoint(id) })
    const hops = [managedHop(1, 3), sourceHop(2), managedHop(3, 2)]
    const applied = structuredClone(hops); applied[1].node_version_id = sourceUuid(401)
    let ordered = [orderedResourceFixture({ id: 11, name: '已有四段路径', entry: endpoint(11), hops, path_state: { desired_generation: 2, candidate_generation: 2, applied_generation: 1, recovery_generation: 1, minimum_generation: 0, phase: 'preparing_dependencies', capabilities: { tcp: true, udp: true }, last_error: null, dependencies: [], probe: null, generations: [{ state: 'desired', generation: 2, hops }, { state: 'candidate', generation: 2, hops }, { state: 'applied', generation: 1, hops: applied }, { state: 'recovery', generation: 1, hops: applied }] } })]
    let nextNode = 20, nextChain = 30, mode = 'lose-batch', editMode = 'lose-edit'
    const resources = () => [...proxyResourceFixtures(nodes, servers, legacy).filter(resource => resource.kind === 'chain' || !ordered.some(value => value.entry.id === resource.id)), ...ordered]
    const getSource = () => ({ ...source, dependencies: ordered.flatMap(resource => resource.path_state.generations.filter(view => ['candidate', 'applied', 'recovery'].includes(view.state)).flatMap(view => view.hops.filter(hop => hop.kind === 'subscription').map(hop => ({ chain_id: resource.id, chain_name: resource.name, generation: view.generation, state: view.state, hop_position: hop.position, external_node_id: hop.external_node_id, node_version_id: hop.node_version_id, identity_epoch: hop.identity_epoch })))) })
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      if (method !== 'GET') writes.push({ path, method, serialized: request.postData(), body: request.postData() ? request.postDataJSON() : null })
      let value
      if (method === 'GET' && path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (method === 'GET' && path === '/api/me') value = { authenticated: true }
      else if (method === 'GET' && path === `${prefix}/servers`) value = servers
      else if (method === 'GET' && path === `${prefix}/subscription-sources`) value = []
      else if (method === 'GET' && path === `${prefix}/proxy-resources`) value = flatResourceFixtures(nodes.filter(node => !ordered.some(resource => resource.entry.id === node.id)), servers, legacy)
      else if (method === 'GET' && path === `${prefix}/node-catalog`) value = catalogResourceFixtures(flatResourceFixtures(nodes.filter(node => !ordered.some(resource => resource.entry.id === node.id)), servers, legacy))
      else if (method === 'GET' && path === `${prefix}/nodes`) { if (oldNodesFailure) { await route.fulfill({ status: 500, json: { error: '旧节点配置无法读取' } }); return } value = nodes }
      else if (method === 'GET' && path === `${prefix}/usage`) value = { total: '0', uplink: '0', downlink: '0', by_node: [], by_user: [] }
      else if (method === 'GET' && path === `${prefix}/ordered-proxy-resources`) value = resources()
      else if (method === 'GET' && /^\/api\/plugins\/sing-box\/ordered-proxy-resources\/(direct|chain)\/[1-9]\d*$/.test(path)) { const [, kind, id] = path.match(/\/(direct|chain)\/(\d+)$/); value = resources().find(resource => resource.kind === kind && resource.id === Number(id)); if (!value) { await route.fulfill({ status: 404, json: { error: '资源已删除' } }); return } }
      else if (method === 'GET' && path === `${prefix}/ordered-subscription-sources`) { if (sourceFailure) { await route.fulfill({ status: 503, json: { error: '来源读取失败' } }); return } value = [getSource()] }
      else if (method === 'GET' && path === `${prefix}/ordered-subscription-sources/1`) value = getSource()
      else if (method === 'GET' && path === `${prefix}/ordered-subscription-sources/1/nodes`) value = sourceNodePageFixture({ current_identity_epoch: source.identity_epoch, nodes: sourceNodes })
      else if (method === 'GET' && path === `${prefix}/ordered-subscription-sources/1/revisions`) value = { source_id: 1, revisions: [sourceRevisionFixture()] }
      else if (method === 'POST' && path === `${prefix}/chains/ordered-batch`) {
        const body = request.postDataJSON(); assert.deepEqual(Object.keys(body).sort(), ['items', 'request_id'])
        if (receipts.has(body.request_id)) { const saved = receipts.get(body.request_id); assert.equal(request.postData(), saved.serialized); await route.fulfill({ status: 200, json: saved.receipt }); return }
        assert.equal(body.items.length, 2)
        const receipt = { request_id: body.request_id, chain_ids: [], entry_node_ids: [] }
        for (const [index, item] of body.items.entries()) {
          assert.deepEqual(item.hops, [{ kind: 'managed', node_id: 3 }, { kind: 'subscription', source_id: 1, external_node_id: sourceUuid(301), node_version_id: sourceUuid(405), update_mode: index === 0 ? 'follow_node' : 'pinned' }, { kind: 'managed', node_id: 2 }])
          assert.deepEqual(item.entry, { mode: 'new', server_id: 1, public_host: 'entry.example.com', sni: 'www.example.com', port: index === 0 ? null : 24443 })
          const node = { ...nodes[0], id: nextNode++, name: item.name, public_host: item.entry.public_host, port: item.entry.port ?? 23000, server_id: 1 }; nodes.push(node)
          const resource = orderedResourceFixture({ id: nextChain++, name: item.name, entry: endpoint(node.id), hops: [managedHop(1, 3), sourceHop(2, sourceUuid(405), item.hops[1].update_mode), managedHop(3, 2)] }); ordered.push(resource)
          receipt.chain_ids.push(resource.id); receipt.entry_node_ids.push(node.id)
        }
        receipts.set(body.request_id, { serialized: request.postData(), receipt })
        if (mode === 'lose-batch') { mode = 'normal'; source = { ...source, identity_epoch: 2, archived: true }; sourceNodes = []; await route.abort('connectionreset'); return }
        await route.fulfill({ status: 201, json: receipt }); return
      } else if (method === 'POST' && path === `${prefix}/ordered-proxy-resources/chain/11/apply-node-versions`) {
        const body = request.postDataJSON(), resource = ordered.find(value => value.id === 11)
        assert.equal(body.settings_revision, resource.settings_revision); assert.equal(body.generation, 2); assert.deepEqual(body.versions, [{ hop_position: 2, node_version_id: sourceUuid(406) }])
        assert.equal(resource.path_state.candidate_generation, null)
        const appliedHops = structuredClone(resource.hops), nextHops = structuredClone(resource.hops); nextHops[1].node_version_id = sourceUuid(406)
        resource.hops = nextHops; resource.settings_revision++; resource.path_state = { ...resource.path_state, desired_generation: 3, candidate_generation: 3, applied_generation: 2, recovery_generation: 2, phase: 'preparing_dependencies', generations: [{ state: 'desired', generation: 3, hops: nextHops }, { state: 'candidate', generation: 3, hops: nextHops }, { state: 'applied', generation: 2, hops: appliedHops }, { state: 'recovery', generation: 2, hops: appliedHops }] }
        await route.fulfill({ json: { request_id: body.request_id, kind: 'chain', id: 11, settings_revision: resource.settings_revision, generation: 3 } }); return
      } else if (method === 'PATCH' && path === `${prefix}/ordered-proxy-resources/chain/11`) {
        const body = request.postDataJSON(), resource = ordered.find(value => value.id === 11)
        if (mutations.has(body.request_id)) { const saved = mutations.get(body.request_id); assert.equal(request.postData(), saved.serialized); await route.fulfill({ json: saved.receipt }); return }
        assert.deepEqual(Object.keys(body).sort(), ['name', 'request_id', 'settings_revision']); assert.equal(body.settings_revision, resource.settings_revision); assert.equal(body.name, '显示名可独立修改')
        resource.name = body.name; resource.settings_revision++
        const receipt = { request_id: body.request_id, kind: 'chain', id: 11, settings_revision: resource.settings_revision, generation: 3 }; mutations.set(body.request_id, { serialized: request.postData(), receipt })
        if (editMode === 'lose-edit') { editMode = 'normal'; await route.abort('connectionreset'); return }
        await route.fulfill({ json: receipt }); return
      } else if (method === 'DELETE' && path === `${prefix}/ordered-proxy-resources/chain/30`) {
        assert.equal(oldNodesFailure, true); assert.equal(sourceFailure, true); assert.equal(ordered.find(value => value.id === 30).available, false)
        const entryId = ordered.find(value => value.id === 30).entry.id; ordered = ordered.filter(resource => resource.id !== 30); nodes = nodes.filter(node => node.id !== entryId)
        assert(nodes.some(node => node.id === 2)); assert(nodes.some(node => node.id === 3)); assert(ordered.some(resource => resource.id === 31))
        await route.fulfill({ status: 204, body: '' }); return
      } else { errors.push(`Unexpected API: ${method} ${path}`); await route.fulfill({ status: 404, json: { error: '夹具拒绝未知接口' } }); return }
      await route.fulfill({ json: value })
    })
    const enabled = async locator => { await locator.waitFor(); const until = Date.now() + 6500; while (await locator.isDisabled() && Date.now() < until) await page.waitForTimeout(20); assert.equal(await locator.isDisabled(), false) }
    // Wrapping Field labels also contain option text; require the exact visible label span.
    const fieldSelect = (scope, label) => scope.locator('label.field').filter({ has: page.getByText(label, { exact: true }) }).locator('select')
    const poll = () => page.clock.fastForward(5000)
    const shot = async name => { if (!process.env.SINAN_UI_SCREENSHOT_DIR) return; await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR, { recursive: true }); await page.locator('[role=dialog]').evaluateAll(dialogs => { for (const dialog of dialogs) for (const animation of (dialog.closest('.modal-shade') ?? dialog).getAnimations({ subtree: true })) if (animation.effect?.getComputedTiming().iterations !== Infinity) animation.finish() }); await page.screenshot({ animations: 'disabled', path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `ordered-${name}-${width}.png`) }) }
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/sing-box/nodes`)
    const create = page.getByRole('button', { name: '创建有序链路', exact: true }); await enabled(create)
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('3')
    await page.locator('[data-resource-key="chain:11"]').waitFor(); await page.getByLabel('链路中的服务器角色', { exact: false }).selectOption('middle'); await page.locator('[data-resource-key="chain:11"]').waitFor()
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('')
    await page.locator('[data-resource-key="chain:11"]').getByRole('button', { name: '详情', exact: true }).click()
    let dialog = page.getByRole('dialog'); await dialog.getByText('已应用代 1', { exact: true }).waitFor(); await dialog.getByText('候选代 2', { exact: true }).waitFor()
    assert.match(await dialog.innerText(), new RegExp(sourceUuid(401))); assert.match(await dialog.innerText(), new RegExp(sourceUuid(405))); assert.equal(await dialog.getByText('指定目标验证成功', { exact: true }).count(), 0)
    await shot('versions'); await dialog.getByRole('button', { name: '关闭', exact: true }).click()
    await page.locator('[data-source-id="1"]').getByRole('button', { name: '查看来源', exact: true }).click(); dialog = page.getByRole('dialog')
    const refs = dialog.getByRole('region', { name: '来源路径引用', exact: true }); await refs.getByText(/候选代 2/).waitFor(); await refs.getByRole('link', { name: '「已有四段路径」#11', exact: true }).first().click()
    dialog = page.getByRole('dialog'); await dialog.getByRole('heading', { name: '资源详情：已有四段路径', exact: true }).waitFor(); assert.match(page.url(), /nodes\/chain\/11$/); await dialog.getByRole('button', { name: '关闭', exact: true }).click()
    await enabled(create); await create.click(); dialog = page.getByRole('dialog')
    await dialog.locator('[name=server_id]').selectOption('1'); await dialog.locator('[name=public_host]').fill('entry.example.com'); await dialog.locator('[name=sni]').fill('www.example.com'); await dialog.locator('[name=name]').fill('新四段甲')
    const shared = dialog.getByRole('group', { name: '共享有序路径', exact: true })
    await fieldSelect(shared, '第 1 跳受管节点').selectOption('3'); await shared.getByRole('button', { name: '添加下一跳', exact: true }).click()
    await fieldSelect(shared, '第 2 跳类型').selectOption('subscription'); await fieldSelect(shared, '第 2 跳订阅来源').selectOption('1')
    await enabled(shared.getByLabel('第 2 跳订阅节点', { exact: false })); await shared.getByLabel('第 2 跳订阅节点', { exact: false }).selectOption(sourceUuid(405))
    await shared.getByRole('button', { name: '添加下一跳', exact: true }).click(); await fieldSelect(shared, '第 3 跳受管节点').selectOption('2')
    await shared.getByRole('button', { name: '共享有序路径第 2 跳上移', exact: true }).click(); await shared.getByRole('button', { name: '共享有序路径第 1 跳下移', exact: true }).click()
    await dialog.getByRole('button', { name: '添加一条链路', exact: true }).click(); await dialog.locator('[name=name_1]').fill('新四段乙'); await dialog.locator('[name=entry_port_1]').fill('24443')
    await dialog.getByRole('button', { name: '单独编辑第 2 条路径', exact: true }).click(); await fieldSelect(dialog.getByRole('group', { name: '第 2 条独立路径', exact: true }), '第 2 跳更新方式').selectOption('pinned')
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true); await shot('batch')
    await enabled(dialog.getByRole('button', { name: '创建未授权链路', exact: true })); await dialog.getByRole('button', { name: '创建未授权链路', exact: true }).click(); await dialog.getByRole('alert').waitFor()
    await dialog.getByRole('button', { name: '取消', exact: true }).click(); await page.locator('[data-resource-key="chain:11"]').getByRole('button', { name: '创建替代链路', exact: true }).click(); dialog = page.getByRole('dialog')
    await dialog.getByText('先确认已发送批次的结果，原草稿和精确请求已保留。确认后再选择创建替代链路。', { exact: true }).waitFor(); assert.equal(await dialog.locator('[name=name]').inputValue(), '新四段甲')
    await poll()
    const retry = dialog.getByRole('button', { name: '重试原批次', exact: true }), priorWrites = writes.length
    await dialog.getByRole('alert').filter({ hasText: '来源或当前节点版本等待确认' }).waitFor()
    assert.equal(await retry.isDisabled(), true)
    assert.equal(await dialog.locator('[name=name]').inputValue(), '新四段甲')
    assert.equal(await dialog.locator('[name=name_1]').inputValue(), '新四段乙')
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await retry.evaluate(button => { const disabled = button.disabled; try { button.disabled = false; button.click() } finally { button.disabled = disabled } })
    await page.waitForTimeout(50); assert.equal(writes.length, priorWrites)
    source = subscriptionSourceFixture(); sourceNodes = [sourceNodeFixture({ version_id: sourceUuid(405) })]
    await poll(); await enabled(retry); await retry.click(); await dialog.waitFor({ state: 'hidden' })
    const batchWrites = writes.filter(write => write.path.endsWith('/chains/ordered-batch')); assert.equal(batchWrites.length, 2); assert.equal(batchWrites[0].serialized, batchWrites[1].serialized); assert.equal(receipts.size, 1); assert.equal(ordered.filter(resource => resource.id >= 30).length, 2)
    assert.equal(await page.locator('[data-resource-key="direct:20"]').count(), 0); assert.equal(await page.locator('[data-resource-key="chain:31"]').count(), 1)
    source = subscriptionSourceFixture(); sourceNodes = [sourceNodeFixture({ version_id: sourceUuid(406) })]
    const existing = ordered.find(resource => resource.id === 11); existing.path_state = { ...existing.path_state, candidate_generation: null, applied_generation: 2, recovery_generation: null, phase: 'applied', generations: [{ state: 'desired', generation: 2, hops: existing.hops }, { state: 'applied', generation: 2, hops: existing.hops }] }
    await poll(); await page.locator('[data-resource-key="chain:11"]').getByRole('button', { name: '应用节点新版本', exact: true }).click(); dialog = page.getByRole('dialog')
    const versions = dialog.getByLabel('第 2 跳：外部示例节点', { exact: false }); await enabled(versions); await versions.selectOption(sourceUuid(406)); await enabled(dialog.getByRole('button', { name: '创建版本候选', exact: true })); await dialog.getByRole('button', { name: '创建版本候选', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    await page.locator('[data-resource-key="chain:11"]').getByRole('button', { name: '编辑公开信息', exact: true }).click(); dialog = page.getByRole('dialog'); await dialog.getByLabel('链路显示名称', { exact: true }).fill('显示名可独立修改'); await dialog.getByRole('button', { name: '保存公开信息', exact: true }).click(); await dialog.getByRole('alert').waitFor()
    await dialog.getByRole('button', { name: '取消', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    await poll(); await page.getByRole('button', { name: '继续确认公开信息修改', exact: true }).click(); dialog = page.getByRole('dialog')
    assert.equal(await dialog.getByLabel('链路显示名称', { exact: true }).inputValue(), '显示名可独立修改'); await enabled(dialog.getByRole('button', { name: '重试原修改', exact: true })); await dialog.getByRole('button', { name: '重试原修改', exact: true }).click(); await dialog.waitFor({ state: 'hidden' })
    const editWrites = writes.filter(write => write.method === 'PATCH'); assert.equal(editWrites.length, 2); assert.equal(editWrites[0].serialized, editWrites[1].serialized)
    const broken = ordered.find(resource => resource.id === 30); broken.available = false; broken.unavailable_reasons = ['受管段缺失，等待清理']; oldNodesFailure = true; sourceFailure = true
    await poll(); const brokenRow = page.locator('[data-resource-key="chain:30"]'); await brokenRow.getByText('资源已不可用', { exact: true }).waitFor(); await enabled(brokenRow.getByRole('button', { name: '删除', exact: true })); await brokenRow.getByRole('button', { name: '删除', exact: true }).click(); await page.getByRole('dialog').getByRole('button', { name: '确认删除', exact: true }).click(); await page.locator('[data-resource-key="chain:30"]').waitFor({ state: 'hidden' })
    assert.equal(ordered.some(resource => resource.id === 31), true); assert.equal(await page.evaluate(() => Object.keys(localStorage).length), 0); assert.deepEqual(errors, [])
    await shot('broken-cleanup'); console.log(`ordered chains actual-dist contracts passed ${width}`); await page.close()
  }
} finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)) }
