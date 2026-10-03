import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// TEST_ONLY: exercise shipped UI against private loopback APIs. No real provider or credentials.
const catalogView = resources => resources.map(resource => ({ ...resource, original_name: resource.name, tags: [], note: '', sort_order: resource.id, revision: '1'.repeat(64), metadata_revision: 0 }))
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url)), prefix = '/api/plugins/sing-box'
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname, file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`, totals = { scenarios: 0, blocked: 0, recovered: 0, external: [], unexpected: [], errors: [] }
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const wait = async (condition, message) => { const end = Date.now() + 10000; while (!await condition()) { assert(Date.now() < end, message); await new Promise(resolve => setTimeout(resolve, 20)) } }
const forceForm = form => form.evaluate(element => element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
const forceClick = button => button.evaluate(element => { const disabled = element.disabled; try { element.disabled = false; element.click() } finally { element.disabled = disabled } })
try {
  for (const width of [1440, 390]) {
    const fixture = async (hash, callback) => {
      const page = await browser.newPage({ viewport: { width, height: 1000 } }); page.setDefaultTimeout(10000)
      page.on('pageerror', error => totals.errors.push(error.message))
      const hosts = [1, 2].map(id => ({ id, name: `TEST_ONLY 服务器 ${id}`, enabled: true, online: true, agent_supported: true, read_only: false }))
      const nodes = [1, 2].map(id => ({ id, name: `TEST_ONLY 节点 ${id}`, server_id: id, protocol: 'vless-reality', public_host: '127.0.0.1', port: 20000 + id, sni: 'localhost', enabled: true }))
      const direct = node => ({ ...node, kind: 'direct', server_name: `TEST_ONLY 服务器 ${node.server_id}`, role: 'direct', available: true, tcp: true, udp: true, entry_node_id: null, stage: 'direct', active_generation: null, pending_generation: null, minimum_generation: 0, reference_count: 0, entry_eligible: true, last_error: null, legacy: false })
      const resources = nodes.map(direct); resources.push({ ...direct(nodes[0]), id: 7, kind: 'chain', name: 'TEST_ONLY 链路', role: 'chain_entry', entry_node_id: 1, stage: 'active', active_generation: 1 })
      const source = { id: 10, name: 'TEST_ONLY 来源', kind: 'inline', source_host: null, url_configured: false, authorization_configured: false, content_configured: true, settings_revision: 1, identity_epoch: 1, archived: false, current_revision_id: 100, refresh_interval_seconds: 86400, last_success_at: 1, supported_count: 1, unsupported_count: 0, dependency_ids: [], active_job_id: null }
      const sources = [source], writes = [], gates = new Map(), failures = new Set()
      const tasks = [{ id: '00000000-0000-0000-0000-000000000001', spec: { id: '00000000-0000-0000-0000-000000000001', name: 'TEST_ONLY 周期任务', kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 30, carrier: '', enabled: false, monitor: null }, default_enabled: false, server_ids: [1], revision: 1 }]
      const status = { module: 'singbox', target_rev: 2, applied_rev: 2, last_result_rev: 2, healthy: true, last_error: null, updated_at: 1 }
      const operation = { supported: true, online: true, retiring: false, operations: [] }
      const detail = { resource: resources.at(-1), node: nodes[0], hops: [{ position: 0, kind: 'subscription', node_id: 101, server_id: null, source_id: 10, version_id: 201, update_mode: 'pinned', name: 'TEST_ONLY 外部段', protocol: 'trojan', server: '127.0.0.1', port: 443, present: true, latest_version_id: 202 }], versions: [{ generation: 1, stage: 'active', created_at: 1, last_error: null }] }
      const control = { page, writes, hosts, sources, status, tasks,
        hold(path) { let release; const promise = new Promise(resolve => { release = resolve }); const gate = { promise, release, reached: 0 }; gates.set(path, gate); return gate },
        fail(path) { failures.add(path); gates.get(path)?.release(); gates.delete(path) },
        recover(path) { failures.delete(path); gates.get(path)?.release(); gates.delete(path) },
      }
      await page.route('**/*', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method()
        if (url.origin !== origin) { totals.external.push(url.href); return route.abort() }
        if (!path.startsWith('/api/')) return route.continue()
        if (method === 'GET') {
          const gate = gates.get(path); if (gate) { ++gate.reached; await gate.promise }
          if (failures.has(path)) return route.fulfill({ status: 503, json: { error: 'TEST_ONLY 资源刷新失败' } })
        }
        let value
        if (method !== 'GET') {
          const allowed = method === 'POST' && [ `${prefix}/nodes`, `${prefix}/chains/batch`, `${prefix}/subscription-sources`, `${prefix}/subscription-source-previews`, `${prefix}/subscription-source-previews/00000000-0000-4000-8000-000000000044/commit`, `${prefix}/servers/1/enable`, `${prefix}/servers/1/deployments/check`, `${prefix}/servers/1/runtime-operations`, `${prefix}/proxy-resources/chain/7/apply-node-versions` ].includes(path)
            || method === 'PATCH' && [ `${prefix}/nodes/1`, `${prefix}/subscription-sources/10`, `${prefix}/proxy-resources/chain/7` ].includes(path)
            || method === 'PATCH' && path === '/api/latency-tasks/00000000-0000-0000-0000-000000000001'
            || method === 'DELETE' && [ `${prefix}/nodes/1`, `${prefix}/subscription-sources/10` ].includes(path)
          assert(allowed, `${method} ${path}`)
          const body = request.postData() ? request.postDataJSON() : undefined; writes.push({ method, path, body }); value = {}
          if (path === `${prefix}/chains/batch`) value = { request_id: body.request_id, chain_ids: [8], entry_node_ids: [20] }
          if (path.startsWith(`${prefix}/subscription-sources`) && method !== 'DELETE') value = { ...source, ...body }
          if (path === `${prefix}/subscription-source-previews`) value = { id: '00000000-0000-4000-8000-000000000044', expires_at: Math.floor(Date.now() / 1000) + 300, format: 'uris', supported_count: 1, unsupported_count: 0, nodes: [{ key: 'node-0', index: 0, name: 'TEST_ONLY 待导入节点', protocol: 'trojan', server: '127.0.0.1', port: 443, transport: 'tcp', tcp: true, udp: false, supported: true, reason: null }] }
          if (path === `${prefix}/subscription-source-previews/00000000-0000-4000-8000-000000000044/commit`) value = { ...source, name: body.name }
          if (path.endsWith('/deployments/check')) value = { ready: true, checks: [] }
          if (path.endsWith('/enable')) hosts[0].enabled = true
          if (path.endsWith('/runtime-operations')) value = { id: 'TEST_ONLY', operation: body.operation, requested_at: 1, expires_at: 600 }
        } else if (['/api/me', '/api/dashboard/access'].includes(path)) value = { authenticated: true, public_dashboard: false }
        else if (path === `${prefix}/servers` || path === '/api/servers') value = hosts
        else if (path === '/api/latency-tasks') value = tasks
        else if (path === '/api/probes/overview') value = []
        else if (path === `${prefix}/nodes`) value = nodes
        else if ([`${prefix}/ordered-proxy-resources`, `${prefix}/ordered-subscription-sources`].includes(path)) value = []
          else if (path === `${prefix}/proxy-resources`) value = resources
        else if (path === `${prefix}/node-catalog`) value = catalogView(resources)
        else if (path === `${prefix}/usage`) value = { total: '0', uplink: '0', downlink: '0', by_node: [], by_user: [] }
        else if (path === `${prefix}/subscription-sources`) value = sources
        else if (path === `${prefix}/subscription-sources/10/nodes`) value = [{ id: 101, source_id: 10, node_version_id: 201, source_revision_id: 100, identity_epoch: 1, name: 'TEST_ONLY 外部段', protocol: 'trojan', server: '127.0.0.1', port: 443, transport: 'tcp', tcp: true, udp: false, selectable: true, present: true, identity_unique: true, reason: null }]
        else if (path === `${prefix}/servers/1/deployments`) value = { status, history: [], pending: false, enabled_nodes: 1, authorized_nodes: 1 }
        else if (path === `${prefix}/servers/1/runtime-operations`) value = operation
        else if (path === `${prefix}/proxy-resources/chain/7`) value = detail
        else { totals.unexpected.push(`${method} ${path}`); return route.fulfill({ status: 404, json: {} }) }
        return route.fulfill({ json: value })
      })
      try { await page.goto(`${origin}/#${hash}`); await callback(control); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true); ++totals.scenarios }
      finally { for (const gate of gates.values()) gate.release(); await page.close() }
    }
    const block = async (control, path, refresh, attempt, restored, draft = async () => {}) => {
      const baseline = control.writes.length, gate = control.hold(path)
      await refresh(); await attempt(); await wait(() => gate.reached > 0, 'Held GET must be requested'); await draft()
      assert.equal(control.writes.length, baseline, 'Pending refresh sends zero writes'); ++totals.blocked
      control.fail(path); await control.page.getByText('TEST_ONLY 资源刷新失败', { exact: true }).first().waitFor(); await attempt(); await draft()
      assert.equal(control.writes.length, baseline, 'Failed refresh sends zero writes'); ++totals.blocked
      control.recover(path); await refresh(); await restored(); await wait(() => control.writes.length === baseline + 1, 'Exactly one recovered write'); ++totals.recovered
    }
    const nodesRefresh = page => page.locator('.page-header button').filter({ hasText: /^刷新$/ }).evaluate(button => button.click())
    const sourceRefresh = page => page.locator('.subscription-sources > .panel-heading button').filter({ hasText: /^刷新$/ }).evaluate(button => button.click())
    await fixture('/plugins/sing-box/nodes', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '创建节点', exact: true }).first().click()
      const dialog = page.getByRole('dialog'); await dialog.locator('[name=name]').fill('TEST_ONLY 节点草稿'); await dialog.locator('[name=public_host]').fill('127.0.0.1'); await dialog.locator('[name=sni]').fill('localhost')
      await block(control, `${prefix}/servers`, () => nodesRefresh(page), () => forceForm(dialog.locator('form')), () => dialog.getByRole('button', { name: '创建并自动发布', exact: true }).click(), async () => assert.equal(await dialog.locator('[name=name]').inputValue(), 'TEST_ONLY 节点草稿'))
      assert.equal(writes[0].body.server_id, 1)
    })
    await fixture('/plugins/sing-box/nodes', async ({ page, hosts, writes }) => {
      await page.getByRole('button', { name: '创建节点', exact: true }).first().click()
      const dialog = page.getByRole('dialog'); await dialog.locator('[name=name]').fill('TEST_ONLY 固定服务器草稿')
      hosts.splice(0, 1); await nodesRefresh(page)
      await dialog.getByText('已选节点所属服务器已不存在或未启用；当前草稿已保留。', { exact: true }).waitFor()
      assert.equal(await dialog.locator('[name=server_id]').inputValue(), '1'); await forceForm(dialog.locator('form')); assert.equal(writes.length, 0)
      await dialog.locator('[name=server_id]').selectOption('2'); await dialog.locator('[name=public_host]').fill('127.0.0.1'); await dialog.locator('[name=sni]').fill('localhost'); await dialog.getByRole('button', { name: '创建并自动发布', exact: true }).click()
      await wait(() => writes.length === 1, 'Explicit new server selection'); assert.equal(writes[0].body.server_id, 2)
    })
    await fixture('/plugins/sing-box/nodes', async control => {
      const { page } = control
      await page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr').filter({ hasText: 'TEST_ONLY 节点 1' }).getByRole('button', { name: '删除', exact: true }).click()
      const button = page.getByRole('dialog').getByRole('button', { name: '确认删除', exact: true })
      await block(control, `${prefix}/proxy-resources`, () => nodesRefresh(page), () => forceClick(button), () => button.click())
    })
    await fixture('/plugins/sing-box/nodes', async control => {
      const { page, writes } = control
      await page.getByRole('button', { name: '创建链路', exact: true }).click()
      const editor = page.getByRole('region', { name: '创建链路', exact: true }); await editor.getByLabel('链路名称', { exact: true }).fill('TEST_ONLY 链路草稿'); await editor.getByLabel('入口公开地址').fill('127.0.0.1'); await editor.getByLabel('入口握手域名').fill('localhost'); await editor.getByLabel('添加受管代理段').selectOption('2')
      await block(control, `${prefix}/nodes`, () => nodesRefresh(page), () => forceForm(editor.locator('form')), () => editor.getByRole('button', { name: '保存 1 条链路', exact: true }).click(), async () => assert.equal(await editor.getByLabel('链路名称', { exact: true }).inputValue(), 'TEST_ONLY 链路草稿'))
      assert.deepEqual(writes[0].body.items[0].hops, [{ kind: 'managed', node_id: 2 }])
    })
    for (const creating of [false, true]) await fixture('/plugins/sing-box/nodes', async control => {
      const { page, writes } = control, sourcePanel = page.locator('.subscription-sources')
      await sourcePanel.getByRole('button', { name: creating ? '添加来源' : '设置与更新', exact: true }).first().click()
      const dialog = page.getByRole('dialog'); await dialog.getByLabel('来源名称', { exact: true }).fill('TEST_ONLY 来源草稿')
      if (creating) { await dialog.getByLabel('来源类型').selectOption('inline'); await dialog.getByLabel('配置内容', { exact: false }).fill('TEST_ONLY content') }
      const draft = async () => assert.equal(await dialog.getByLabel('来源名称', { exact: true }).inputValue(), 'TEST_ONLY 来源草稿')
      await block(control, `${prefix}/subscription-sources`, () => sourceRefresh(page), () => forceForm(dialog.locator('form')), () => dialog.getByRole('button', { name: creating ? '解析并预览' : '保存并解析更新', exact: true }).click(), draft)
      assert.equal(writes[0].method, creating ? 'POST' : 'PATCH')
      if (creating) {
        assert.equal(writes[0].path, `${prefix}/subscription-source-previews`)
        await dialog.getByRole('heading', { name: '选择导入节点', exact: true }).waitFor()
        // A parsed preview must still respect the collection snapshot before committing.
        await block(control, `${prefix}/subscription-sources`, () => sourceRefresh(page), () => forceForm(dialog.locator('form')), () => dialog.getByRole('button', { name: '加入节点库（1）', exact: true }).click(), draft)
        assert.equal(writes[1].path, `${prefix}/subscription-source-previews/00000000-0000-4000-8000-000000000044/commit`)
        assert.deepEqual(writes[1].body.selected, ['node-0'])
      }
    })
    await fixture('/plugins/sing-box/nodes', async control => {
      const { page } = control
      await page.locator('.subscription-sources').getByRole('button', { name: '删除', exact: true }).click()
      const button = page.getByRole('dialog').getByRole('button', { name: '确认删除', exact: true })
      await block(control, `${prefix}/subscription-sources`, () => sourceRefresh(page), () => forceClick(button), () => button.click())
    })
    await fixture('/plugins/sing-box/nodes/chain/7', async control => {
      const { page } = control, dialog = page.getByRole('dialog')
      await dialog.getByRole('button', { name: '修改名称', exact: true }).click(); await dialog.getByLabel('链路名称', { exact: true }).fill('TEST_ONLY 链路名称草稿')
      // The detail has its own poll, so wait for that real request rather than reload the document.
      await block(control, `${prefix}/proxy-resources/chain/7`, async () => { if (await dialog.getByRole('button', { name: '重试', exact: true }).count()) await dialog.getByRole('button', { name: '重试', exact: true }).click(); else await wait(() => control.page.getByRole('button', { name: '保存名称', exact: true }).isDisabled(), 'Detail poll starts') }, () => forceForm(dialog.locator('form')), () => dialog.getByRole('button', { name: '保存名称', exact: true }).click(), async () => assert.equal(await dialog.getByLabel('链路名称', { exact: true }).inputValue(), 'TEST_ONLY 链路名称草稿'))
    })
    await fixture('/plugins/sing-box/nodes', async control => {
      const { page, writes, status } = control
      await page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr').filter({ hasText: 'TEST_ONLY 节点 1' }).getByRole('button', { name: '部署', exact: true }).click()
      const dialog = page.getByRole('dialog'), runtime = dialog.locator('.runtime-operations')
      const refresh = () => dialog.locator('.node-deployment-heading button').filter({ hasText: /^刷新$/ }).evaluate(button => button.click())
      const inspect = runtime.getByRole('button', { name: '读取状态与日志', exact: true })
      await wait(() => inspect.isEnabled(), 'Runtime/deployment initial snapshots')
      await block(control, `${prefix}/servers/1/deployments`, refresh, () => forceClick(inspect), () => inspect.click())
      await runtime.getByRole('button', { name: '重启运行时', exact: true }).click(); status.target_rev = 3; await refresh()
      await runtime.getByRole('alert').getByText('期望版本已改变，请取消后重新确认。', { exact: true }).waitFor()
      await forceClick(runtime.getByRole('button', { name: '确认重启', exact: true })); assert.equal(writes.length, 1, 'A confirmation must never retarget to a newer revision')
    })
    await fixture('/latency', async control => {
      const { page, writes } = control
      await page.getByRole('row').filter({ hasText: 'TEST_ONLY 周期任务' }).getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.getByLabel('任务名称').fill('TEST_ONLY 周期草稿')
      await block(control, '/api/latency-tasks', () => nodesRefresh(page), () => forceForm(dialog.locator('form')), () => dialog.getByRole('button', { name: '保存任务', exact: true }).click(), async () => assert.equal(await dialog.getByLabel('任务名称').inputValue(), 'TEST_ONLY 周期草稿'))
      assert.equal(writes[0].body.revision, 1); assert.equal(writes[0].body.spec.enabled, false)
    })
    await fixture('/latency', async ({ page, writes, tasks }) => {
      const row = page.getByRole('row').filter({ hasText: 'TEST_ONLY 周期任务' })
      await wait(() => row.getByRole('button', { name: '编辑', exact: true }).isEnabled(), 'Initial task revision')
      delete tasks[0].revision
      const read = page.waitForResponse(response => new URL(response.url()).pathname === '/api/latency-tasks' && response.request().method() === 'GET')
      await nodesRefresh(page); await read
      for (const label of ['编辑', '启用', '删除']) {
        const button = row.getByRole('button', { name: label, exact: true })
        await wait(() => button.isDisabled(), 'Missing task revisions fail closed')
        await forceClick(button); ++totals.blocked
      }
      assert.equal(await page.getByRole('dialog').count(), 0); assert.equal(writes.length, 0)
      tasks[0].revision = 1
      const restored = page.waitForResponse(response => new URL(response.url()).pathname === '/api/latency-tasks' && response.request().method() === 'GET')
      await nodesRefresh(page); await restored
      await row.getByRole('button', { name: '编辑', exact: true }).click()
      const dialog = page.getByRole('dialog'); await dialog.getByLabel('任务名称').fill('TEST_ONLY 原修订草稿')
      tasks[0].revision = 2
      await nodesRefresh(page)
      await dialog.getByText('延迟任务目标或版本已变化；草稿已保留。', { exact: true }).waitFor()
      await forceForm(dialog.locator('form')); assert.equal(writes.length, 0); ++totals.blocked
      assert.equal(await dialog.getByLabel('任务名称').inputValue(), 'TEST_ONLY 原修订草稿')
      await dialog.getByRole('button', { name: '取消', exact: true }).click()
      await row.getByRole('button', { name: '编辑', exact: true }).click()
      await page.getByRole('dialog').getByRole('button', { name: '保存任务', exact: true }).click()
      await wait(() => writes.length === 1, 'Explicit current revision selection permits one write'); ++totals.recovered
      assert.equal(writes[0].body.revision, 2)
    })
    await fixture('/system/plugins', async control => {
      const { page, hosts } = control; hosts[0].enabled = false
      // The initial response can already be in flight; explicitly refresh the installation collection.
      const refresh = () => page.locator('section.panel').filter({ has: page.getByRole('heading', { name: 'sing-box 安装与运行状态', exact: true }) }).getByRole('button', { name: '刷新', exact: true }).evaluate(button => button.click())
      await refresh(); const enable = page.getByRole('button', { name: '启用并安装 sing-box', exact: true }); await wait(() => enable.isEnabled(), 'Enable snapshot')
      await block(control, `${prefix}/servers`, refresh, () => forceClick(enable), () => enable.click())
    })
  }
  assert.deepEqual(totals.external, []); assert.deepEqual(totals.unexpected, []); assert.deepEqual(totals.errors, [])
  console.log(JSON.stringify({ result: 'PASS', ...totals }))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
