import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// Shipped dist with controlled API responses; PostgreSQL verifies migration/data.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const [width, height] of [[1280, 900], [1280, 600], [390, 900]]) {
    const page = await browser.newPage({ viewport: { width, height } })
    const errors = [], requests = [], mutations = [], now = Math.floor(Date.now() / 1000)
    const refreshPage = () => page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true }).click()
    const showResourceDetail = async id => {
      await page.locator(`[data-resource-key="chain:${id}"]`).getByRole('button', { name: '路径与引用', exact: true }).click()
      const dialog = page.getByRole('dialog')
      await dialog.getByText('资源存在', { exact: true }).waitFor()
      return dialog
    }
    const closeResourceDetail = () => page.getByRole('dialog').getByRole('button', { name: '关闭', exact: true }).click()
    page.on('pageerror', error => errors.push(error.message))
    const metadata = { id: 1, name: '纯监控验收服务器', enabled: false, source: null, read_only: false, online: true, agent_supported: false, installation: { state: 'not_enabled', reason: '尚未启用插件；设备支持此插件不代表已安装', target_rev: 0, applied_rev: 0 } }
    const entry = { id: 1, name: metadata.name, online: true, device_public_key: 'test-only-key', static_info: { runtime_version: 'test-only-runtime' }, latest_metrics: { network_interfaces: { eth0: { received_bytes: 1024, transmitted_bytes: 2048 } } }, last_seen: now, manifest_rev: 0, capabilities: [] }
    const node = { id: 2, name: '插件代理节点', server_id: 1, protocol: 'vless-reality', port: 443, public_host: 'proxy.example.com', sni: 'www.example.com', public_key: 'public-test', short_id: '0123abcd' }
    const exitNode = { ...node, id: 3, name: '另一台服务器的出口', server_id: 2, public_host: 'exit.example.com' }
    const chains = []
    const additionalNodes = [
      { ...node, id: 4, server_id: 3, name: '其他服务器入口' },
      { ...node, id: 5, server_id: 4, name: '其他服务器出口' },
      { ...node, id: 6, server_id: 5, name: '反向筛选入口' },
      { ...node, id: 7, server_id: 1, name: '本服务器的链路出口' },
    ]
    const additionalChains = [
      { id: 10, name: '无关服务器链路', entry_node_id: 4, exit_node_id: 5, available: true },
      { id: 11, name: '本服务器作为出口', entry_node_id: 6, exit_node_id: 7, available: true },
    ]
    const exitMetadata = { id: 2, name: '出口验收服务器', enabled: true, source: 'administrator', read_only: false, online: true, agent_supported: true, installation: { state: 'pending', reason: '出口夹具正在等待目标配置应用。', target_rev: 3, applied_rev: 2 } }
    const otherMetadata = [
      { ...exitMetadata, id: 3, name: '缺少应用状态的服务器', installation: undefined },
      { ...exitMetadata, id: 4, name: '版本不一致的服务器', installation: { state: 'ready', reason: '不一致夹具不能认证应用成功。', target_rev: 4, applied_rev: 3 } },
      { ...exitMetadata, id: 5, name: '离线入口服务器', online: false, installation: { state: 'offline', reason: '入口夹具当前离线。', target_rev: 2, applied_rev: 1 } },
    ]
    let chainsFailure = false, chainFixtures = false, pluginServersFailure = false, nodesEmpty = false, deploymentFailure = false
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname
      requests.push(path)
      if (route.request().method() !== 'GET') mutations.push({ path, method: route.request().method() })
      let value
      if (path === '/api/dashboard/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (path === '/api/me') value = { authenticated: true }
      else if (path === '/api/servers/1') value = entry
      else if (path === '/api/plugins/sing-box/servers/1') value = metadata
      else if (path === '/api/plugins/sing-box/servers') {
        if (pluginServersFailure) { await route.fulfill({ status: 500, json: { error: '服务器夹具读取失败' } }); return }
        value = chainFixtures ? [metadata, exitMetadata, ...otherMetadata] : [metadata]
      }
      else if (path === '/api/plugins/sing-box/servers/1/enable') {
        assert.equal(route.request().method(), 'POST')
        assert.deepEqual(route.request().postDataJSON(), {})
        Object.assign(metadata, { enabled: true, source: 'administrator', installation: { state: 'queued', reason: '启用请求已保存，正在生成初始运行配置', target_rev: 0, applied_rev: 0 } }); value = metadata
      } else if (path === '/api/plugins/sing-box/servers/1/deployments') {
        assert.equal(metadata.enabled, true)
        if (deploymentFailure) { await route.fulfill({ status: 500, json: { error: '部署夹具读取失败' } }); return }
        const installation = metadata.installation
        value = { status: installation?.target_rev > 0 ? { module: 'singbox', target_rev: installation.target_rev, applied_rev: installation.applied_rev, last_result_rev: installation.applied_rev, healthy: installation.state === 'ready', last_error: null, updated_at: now } : null,
          pending: ['queued', 'pending'].includes(installation?.state), enabled_nodes: node.enabled === false ? 0 : 1, authorized_nodes: 0, history: [] }
      } else if (path === '/api/plugins/sing-box/nodes/2') {
        assert.equal(route.request().method(), 'PATCH')
        const payload = route.request().postDataJSON()
        assert.deepEqual(payload, { name: node.name, public_host: node.public_host, sni: node.sni, protocol_config: { type: 'vless-reality' }, port: 443, enabled: false,
          settings: { listen: '0.0.0.0', public_port: 8443, tcp_fast_open: false, disable_tcp_keep_alive: false, tcp_keep_alive_seconds: null, tcp_keep_alive_interval_seconds: null, tls_alpn: [], tls_min_version: null, tls_max_version: null, tls_handshake_timeout_seconds: null, transport: { type: 'tcp' }, reality: { handshake_server: 'handshake.example.com', handshake_port: 443, fingerprint: 'firefox', max_time_difference_seconds: null, flow: 'vision' } } })
        Object.assign(node, payload)
        metadata.installation = { state: 'pending', reason: '节点设置已保存，等待设备应用。', target_rev: 2, applied_rev: 1 }
        value = node
      } else if (path === '/api/plugins/sing-box/nodes') {
        assert.equal(metadata.enabled, true); value = nodesEmpty ? [] : chainFixtures ? [node, exitNode, ...additionalNodes] : [node, exitNode]
      } else if (['/api/plugins/sing-box/subscription-sources','/api/plugins/sing-box/ordered-subscription-sources'].includes(path)) value = []
      else if (path === '/api/plugins/sing-box/proxy-resources') {
        assert.equal(route.request().method(), 'GET')
        if (chainsFailure) { await route.fulfill({ status:500,json:{error:'链路夹具读取失败'} }); return }
        value = nodesEmpty ? [] : flatResourceFixtures([node,exitNode,...additionalNodes],[metadata,exitMetadata,...otherMetadata],chainFixtures ? [...chains,...additionalChains] : chains).filter(resource => chainFixtures || resource.kind === 'chain' || [2,3].includes(resource.id))
      } else if (path === '/api/plugins/sing-box/node-catalog') {
        value = catalogResourceFixtures(nodesEmpty ? [] : flatResourceFixtures([node,exitNode,...additionalNodes],[metadata,exitMetadata,...otherMetadata],chainFixtures ? [...chains,...additionalChains] : chains).filter(resource => chainFixtures || resource.kind === 'chain' || [2,3].includes(resource.id)))
      } else if (path === '/api/plugins/sing-box/ordered-proxy-resources') {
        if (chainsFailure) { await route.fulfill({ status:500,json:{error:'链路夹具读取失败'} }); return }
        value = nodesEmpty ? [] : proxyResourceFixtures([node,exitNode,...additionalNodes],[metadata,exitMetadata,...otherMetadata],chainFixtures ? [...chains,...additionalChains] : chains).filter(resource => chainFixtures || resource.kind === 'chain' || [2,3].includes(resource.id))
      } else if (/^\/api\/plugins\/sing-box\/ordered-proxy-resources\/chain\/\d+$/.test(path)) {
        assert.equal(route.request().method(), 'GET')
        value = proxyResourceFixtures([node,exitNode,...additionalNodes],[metadata,exitMetadata,...otherMetadata],chainFixtures ? [...chains,...additionalChains] : chains).find(resource => resource.kind === 'chain' && resource.id === Number(path.split('/').at(-1)))
        assert(value, 'details must identify a current chain from the rich projection')
      } else if (path === '/api/plugins/sing-box/chains/ordered-batch') {
        assert.equal(route.request().method(), 'POST')
        const body = route.request().postDataJSON()
        assert.match(body.request_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
        assert.deepEqual(body.items,[{name:'未授权验收链路',entry:{mode:'existing',node_id:2},hops:[{kind:'managed',node_id:3}]}])
        const chain = { id:9,name:'未授权验收链路',entry_node_id:2,exit_node_id:3,available:true,path_kind:'ordered' }
        metadata.installation = { state:'pending',reason:'新链路已保存，两端配置仍待设备应用。',target_rev:2,applied_rev:2 }
        chains.push(chain); value = {request_id:body.request_id,chain_ids:[9],entry_node_ids:[2]}
      } else if (path === '/api/plugins/sing-box/users') value = []
      else if (/^\/api\/plugins\/sing-box\/users\/\d+\/portal$/.test(path)) value = { configuration: { enabled: false, reason: 'TEST_ONLY 未启用', origin: `http://127.0.0.1:${server.address().port}` }, keys: 0, url: null, activation_expires_at: null }
      else if (path === '/api/plugins/sing-box/chains') {
        if (route.request().method() === 'POST') {
          assert.deepEqual(route.request().postDataJSON(), { name: '未授权验收链路', entry_node_id: 2, exit_node_id: 3 })
          const chain = { id: 9, name: '未授权验收链路', entry_node_id: 2, exit_node_id: 3, available: true }
          metadata.installation = { state: 'pending', reason: '新链路已保存，两端配置仍待设备应用。', target_rev: 2, applied_rev: 2 }
          chains.push(chain); value = chain
        } else if (chainsFailure) { await route.fulfill({ status: 500, json: { error: '链路夹具读取失败' } }); return }
        else value = chainFixtures ? [...chains, ...additionalChains] : chains
      }
      else if (['/api/plugins/sing-box/policy-groups', '/api/plugins/sing-box/package-groups'].includes(path)) value = []
      else if (path === '/api/plugins/sing-box/usage') value = { uplink: '0', downlink: '0', total: '0', by_user: [], by_node: [] }
      else if (path === '/api/servers/1/agent-settings') value = { sample_interval_secs: 1, upload_interval_secs: 3, discover_public_ips: false, auto_update: false }
      else if (path === '/api/servers/1/telemetry-settings') value = { persist_interval_secs: 60 }
      else if (path === '/api/servers/1/node-quality') value = { ip_addresses: [], quality: [], plugin_ready: false, plugin_reason: '夹具未启用诊断', reports: [] }
      else if (path === '/api/servers/1/enrollment') value = { token: 'TEST_ONLY_ENROLLMENT', expires_at: now + 3600, install_command: null, warning: '夹具未导入 Agent 制品。' }
      else if (path === '/api/artifacts/agent-versions' && route.request().method() === 'GET') value = { versions: [] }
      else if (['/api/servers/1/probes', '/api/servers/1/probe-results', '/api/servers/1/commands'].includes(path)) value = []
      else if (path === '/api/security/totp') value = { enabled: false }
      else if (path === '/api/security/passkeys') value = { configuration: { enabled: false, reason: 'TEST_ONLY 未启用', origin: `http://127.0.0.1:${server.address().port}` }, keys: [] }
      else if (path.endsWith('/runtime-operations')) value = { supported:false,online:false,retiring:false,operations:[] }
      else { errors.push(`Unexpected API: ${path}`); await route.fulfill({ status: 404, json: {} }); return }
      await route.fulfill({ json: value })
    })
    const origin = `http://127.0.0.1:${server.address().port}`
    await page.goto(`${origin}/#/servers/1`)
    await page.getByRole('heading', { name: metadata.name, exact: true }).waitFor()
    await page.waitForFunction(() => document.querySelector('table')?.textContent.includes('eth0'))
    await page.waitForTimeout(150)
    assert.equal(await page.locator('[data-plugin="sing-box"]').count(), 0)
    assert.equal(await page.getByText('test-only-runtime', { exact: true }).count(), 0)
    assert.equal(requests.some(path => path.endsWith('/deployments') || path.endsWith('/nodes')), false)

    // Adapter support alone must not opt this server into proxy business.
    Object.assign(metadata, { agent_supported: true, installation: { state: 'not_enabled', reason: '尚未启用。', target_rev: 0, applied_rev: 0 } })
    entry.capabilities = ['singbox']
    const supportedStart = requests.length
    await page.reload()
    await page.getByRole('heading', { name: metadata.name, exact: true }).waitFor()
    await page.waitForTimeout(150)
    assert.equal(await page.locator('[data-plugin="sing-box"]').count(), 0)
    assert.equal(requests.slice(supportedStart).some(path => path.endsWith('/deployments') || path.endsWith('/nodes')), false)
    await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '服务器插件', exact: true }).click()
    await page.getByText('设备支持 sing-box', { exact: true }).waitFor()
    await page.getByRole('button', { name: '启用并安装 sing-box', exact: true }).click()
    await page.getByText('管理员明确启用', { exact: true }).waitFor()
    await page.getByText('安装已安排', { exact: true }).waitFor()
    assert.equal(metadata.enabled, true)
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)

    metadata.installation = { state: 'failed', reason: '缺少此平台的签名 sing-box 制品。', target_rev: 1, applied_rev: 0 }
    await page.reload()
    await page.getByText('安装或部署失败', { exact: true }).waitFor()
    await page.getByText(metadata.installation.reason, { exact: true }).waitFor()
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)

    metadata.installation = { state: 'ready', reason: '设备已确认 sing-box 安装并运行。', target_rev: 1, applied_rev: 1 }
    await page.reload()
    await page.getByText('已安装并运行', { exact: true }).waitFor()
    await page.goto(`${origin}/#/servers/1`)
    await page.getByRole('heading', { name: '配置部署', exact: true }).waitFor()
    await page.getByText('插件代理节点', { exact: true }).waitFor()
    await page.getByText('已安装并运行', { exact: true }).waitFor()
    assert.equal(await page.locator('[data-plugin="sing-box"]').count(), 1)

    // A legacy response and a runtime-version string cannot certify installation.
    delete metadata.installation
    await page.reload()
    await page.getByText('安装状态待确认', { exact: true }).waitFor()
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)
    Object.assign(metadata, { source: 'legacy_nodes', read_only: true, agent_supported: true })
    await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '服务器插件', exact: true }).click()
    await page.getByText('保留已有启用记录', { exact: true }).waitFor()
    await page.getByText('兼容已有代理节点', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '启用并安装 sing-box', exact: true }).count(), 0)

    // The server plugin route reads only this server and keeps conservative ACK semantics.
    const scopedStart = requests.length
    await page.goto(`${origin}/#/servers/1/plugins`)
    await page.getByRole('heading', { name: '服务器插件', exact: true }).waitFor()
    await page.getByText('安装状态待确认', { exact: true }).waitFor()
    assert.equal(await page.getByRole('navigation', { name: '服务器导航' }).getByRole('link', { name: '服务器插件', exact: true }).getAttribute('aria-current'), 'page')
    assert.equal(await page.getByRole('link', { name: '浏览插件目录', exact: true }).getAttribute('href'), '#/plugins/catalog')
    assert.equal(requests.slice(scopedStart).includes('/api/plugins/sing-box/servers/1'), true)
    assert.equal(requests.slice(scopedStart).includes('/api/plugins/sing-box/servers'), false)
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)

    await page.getByRole('link', { name: '代理服务', exact: true }).click()
    await page.getByRole('heading', { name: '代理服务', exact: true }).waitFor()
    await page.getByText('安装状态待确认', { exact: true }).waitFor()
    await page.getByRole('link', { name: '管理此服务器节点', exact: true }).click()
    await page.getByRole('heading', { name: '代理节点', exact: true }).waitFor()
    assert.equal(new URL(page.url()).hash, '#/plugins/sing-box/nodes?server=1')
    assert.equal(await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).inputValue(), '1')
    await page.getByRole('button', { name: '创建节点', exact: true }).click()
    assert.equal(await page.locator('select[name="server_id"]').inputValue(), '1')
    await page.getByRole('dialog').getByRole('button', { name: '取消', exact: true }).click()
    // Main's node settings survive the unified listener/chain category merge.
    const nodeMutationStart = mutations.length
    const editedCatalogNode = page.locator(`${width < 768 ? '.catalog-card' : '.catalog-table tbody tr'}[data-resource-key="direct:2"]`)
    await editedCatalogNode.getByRole('button', { name: '编辑', exact: true }).click()
    const nodeEditor = page.getByRole('dialog')
    await nodeEditor.locator('input[name="listen"]').fill('0.0.0.0')
    await nodeEditor.locator('input[name="public_port"]').fill('8443')
    await nodeEditor.locator('input[name="enabled"]').uncheck()
    await nodeEditor.getByText('协议高级设置', { exact: true }).click()
    await nodeEditor.locator('input[name="handshake_server"]').fill('handshake.example.com')
    await nodeEditor.locator('select[name="fingerprint"]').selectOption('firefox')
    await nodeEditor.getByRole('button', { name: '保存并自动发布', exact: true }).click()
    await page.getByText('资源已保存，正在等待自动发布与设备应用。', { exact: true }).waitFor()
    await editedCatalogNode.getByText('已停用', { exact: true }).waitFor()
    await editedCatalogNode.getByText('proxy.example.com:8443', { exact: true }).waitFor()
    // The catalog shows the public endpoint. Reopen the persisted node rather
    // than expecting the former direct-row listener summary.
    await editedCatalogNode.getByRole('button', { name: '编辑', exact: true }).click()
    const persistedNodeEditor = page.getByRole('dialog')
    assert.equal(await persistedNodeEditor.locator('input[name="listen"]').inputValue(), '0.0.0.0')
    assert.equal(await persistedNodeEditor.locator('input[name="port"]').inputValue(), '443')
    assert.equal(await persistedNodeEditor.locator('input[name="public_port"]').inputValue(), '8443')
    assert.equal(await persistedNodeEditor.locator('input[name="enabled"]').isChecked(), false)
    await persistedNodeEditor.getByRole('button', { name: '取消', exact: true }).click()
    assert.deepEqual(mutations.slice(nodeMutationStart), [{ path: '/api/plugins/sing-box/nodes/2', method: 'PATCH' }])
    await page.getByRole('button', { name: '查看部署进度', exact: true }).click()
    const deploymentDialog = page.getByRole('dialog')
    await deploymentDialog.getByText('等待合并发布', { exact: true }).waitFor()
    assert.equal(await deploymentDialog.getByText('目标配置已应用', { exact: true }).count(), 0)
    await deploymentDialog.getByText('链路出口可能凭内部连接凭据监听。', { exact: false }).waitFor()
    metadata.installation = { state: 'ready', reason: '设备已确认目标配置，健康检查通过。', target_rev: 2, applied_rev: 2 }
    await deploymentDialog.getByRole('button', { name: '刷新', exact: true }).click()
    await deploymentDialog.getByText('目标配置已应用', { exact: true }).waitFor()
    // A failed GET retains a historical snapshot in the resource hook, but the
    // deployment dialog must withhold the current application confirmation.
    deploymentFailure = true
    await deploymentDialog.getByRole('button', { name: '刷新', exact: true }).click()
    await deploymentDialog.getByText('部署夹具读取失败', { exact: true }).waitFor()
    await deploymentDialog.getByText('应用状态待确认', { exact: true }).waitFor()
    assert.equal(await deploymentDialog.getByText('目标配置已应用', { exact: true }).count(), 0)
    deploymentFailure = false
    await deploymentDialog.getByRole('button', { name: '重试', exact: true }).click()
    await deploymentDialog.getByText('目标配置已应用', { exact: true }).waitFor()
    await deploymentDialog.getByRole('button', { name: '关闭', exact: true }).click()
    // The following independent chain scenarios start with an enabled entry.
    node.enabled = true
    chainFixtures = true
    await refreshPage()
    await page.getByRole('navigation', { name: '节点资源类型', exact: true }).getByRole('link', { name: '链路', exact: true }).click()
    await page.getByRole('heading', { name: '代理节点', exact: true, level: 1 }).waitFor()
    await page.getByRole('heading', { name: /^有序链路与资源引用/, level: 2 }).waitFor()
    // The Nodes component and these headings remain mounted across category hash changes.
    await page.locator('nav[aria-label="节点资源类型"] a[aria-current="page"]').filter({ hasText: /^链路$/ }).waitFor()
    assert.equal(await page.getByRole('navigation', { name: '节点资源类型', exact: true }).getByRole('link', { name: '链路', exact: true }).getAttribute('aria-current'), 'page')
    assert.equal(await page.locator('nav[aria-label="主导航"]').getByRole('link', { name: '两跳链路', exact: true }).count(), 0)
    const chainMutationStart = mutations.length
    await page.getByRole('button', { name: '创建两跳链路', exact: true }).click()
    const chainDialog = page.getByRole('dialog')
    await chainDialog.locator('select[name="entry_mode"]').selectOption('existing')
    await chainDialog.locator('input[name="name"]').fill('未授权验收链路')
    await chainDialog.locator('select[name="entry_node_id"]').selectOption('2')
    await chainDialog.locator('select[name="exit_node_id"]').selectOption('3')
    await chainDialog.getByRole('button', { name: '创建未授权链路', exact: true }).click()
    await page.getByText('未授权验收链路', { exact: true }).waitFor()
    assert.deepEqual(mutations.slice(chainMutationStart), [{ path: '/api/plugins/sing-box/chains/ordered-batch', method: 'POST' }])
    // The server query includes any managed segment and never shows unrelated chains.
    assert.equal(new URL(page.url()).hash, '#/plugins/sing-box/nodes?kind=chains&server=1')
    await page.getByText(`筛选范围：任一受管段属于「${metadata.name}」的链路。`, { exact: false }).waitFor()
    const reverseRow = page.locator('[data-resource-key="chain:11"]')
    await reverseRow.locator('td').first().locator('strong').filter({ hasText: /^本服务器作为出口$/ }).waitFor()
    await reverseRow.locator('small').filter({ hasText: /^本服务器作为出口$/ }).waitFor()
    assert.equal(await page.getByText('无关服务器链路', { exact: true }).count(), 0)
    let createdRow = page.getByRole('row').filter({ has: page.getByText('未授权验收链路', { exact: true }) })
    assert.equal(await createdRow.getByRole('link', { name: metadata.name, exact: true }).getAttribute('href'), '#/servers/1')
    await createdRow.getByText('有序混合链路', { exact: true }).waitFor()
    await createdRow.getByText('状态与指定路径验证见详情', { exact: true }).waitFor()
    await createdRow.getByText(metadata.installation.reason, { exact: true }).waitFor()
    assert.equal(await createdRow.getByText('目标配置已应用', { exact: true }).count(), 0)
    let resourceDetail = await showResourceDetail(9)
    assert.equal(await resourceDetail.getByRole('link', { name: metadata.name, exact: true }).getAttribute('href'), '#/servers/1')
    assert.equal(await resourceDetail.getByRole('link', { name: exitMetadata.name, exact: true }).getAttribute('href'), '#/servers/2')
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 0)
    await closeResourceDetail()
    metadata.installation = { state: 'ready', reason: '入口设备已确认目标配置，健康检查通过。', target_rev: 2, applied_rev: 2 }
    await refreshPage()
    await createdRow.getByText('目标配置已应用', { exact: true }).waitFor()
    assert.equal(await createdRow.getByText('目标配置已应用', { exact: true }).count(), 1)
    assert.equal(await createdRow.getByText('资源存在', { exact: true }).count(), 1)
    resourceDetail = await showResourceDetail(9)
    await resourceDetail.getByText('等待应用配置', { exact: true }).waitFor()
    await resourceDetail.getByText('目标版本 3 · 已应用版本 2', { exact: true }).waitFor()
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 1)
    await closeResourceDetail()
    await page.getByText('两端状态仅表示设备应用与健康信息，尚未验证公网可达或链路连通。', { exact: false }).waitFor()
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)

    await page.getByRole('navigation', { name: '节点资源类型', exact: true }).getByRole('link', { name: '直连节点', exact: true }).click()
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('2')
    await page.getByRole('navigation', { name: '节点资源类型', exact: true }).getByRole('link', { name: '链路', exact: true }).click()
    await page.locator('nav[aria-label="节点资源类型"] a[aria-current="page"]').filter({ hasText: /^链路$/ }).waitFor()
    await page.waitForFunction(() => document.querySelector('select[aria-label="按服务器筛选"]')?.value === '2')
    await page.getByText('未授权验收链路', { exact: true }).waitFor()
    assert.equal(new URL(page.url()).hash, '#/plugins/sing-box/nodes?kind=chains&server=2')
    assert.equal(await page.locator('.proxy-resource-table').getByRole('row').count(), 2)
    assert.equal(await reverseRow.count(), 0, 'The unrelated reverse chain is absent in the server=2 scope')
    await createdRow.locator('small').filter({ hasText: /^本服务器作为出口$/ }).waitFor()
    assert.equal(await page.getByText('无关服务器链路', { exact: true }).count(), 0)
    // Equal revisions alone cannot certify a still-pending dirty configuration.
    exitMetadata.installation = { state: 'pending', reason: '新配置仍待发布确认，版本相等不足以确认应用。', target_rev: 3, applied_rev: 3 }
    await page.reload()
    resourceDetail = await showResourceDetail(9)
    await resourceDetail.getByText(exitMetadata.installation.reason, { exact: true }).waitFor()
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 1)
    await closeResourceDetail()
    exitMetadata.installation = { state: 'failed', reason: '出口夹具设备应用失败。', target_rev: 3, applied_rev: 2 }
    await page.reload()
    resourceDetail = await showResourceDetail(9)
    await resourceDetail.getByText(exitMetadata.installation.reason, { exact: true }).waitFor()
    await resourceDetail.getByText('安装或部署失败', { exact: true }).waitFor()
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 1)
    await closeResourceDetail()
    exitMetadata.installation = { state: 'ready', reason: '出口设备已确认目标配置，健康检查通过。', target_rev: 3, applied_rev: 3 }
    await page.reload()
    resourceDetail = await showResourceDetail(9)
    await resourceDetail.getByText(exitMetadata.installation.reason, { exact: true }).waitFor()
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 2)
    await closeResourceDetail()

    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains&server=3`)
    await page.getByText('无关服务器链路', { exact: true }).waitFor()
    await page.getByText('设备状态与目标版本尚未确认一致，请查看服务器详情。', { exact: true }).waitFor()
    assert.equal(await page.getByText('应用状态待确认', { exact: true }).count(), 2)
    assert.equal(await page.getByText('目标配置已应用', { exact: true }).count(), 0)
    assert.equal(await page.getByText('未授权验收链路', { exact: true }).count(), 0)
    await page.getByRole('link', { name: '查看全部链路', exact: true }).click()
    await page.getByText('筛选范围：全部服务器的链路。', { exact: true }).waitFor()
    await page.getByText('未授权验收链路', { exact: true }).waitFor()
    assert.equal(await page.locator('.proxy-resource-table').getByRole('row').count(), 4)
    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains&server=999`)
    await page.getByText('此服务器暂无已确认关联的链路', { exact: true }).waitFor()
    assert.equal(await page.getByText('未授权验收链路', { exact: true }).count(), 0)

    // A failed refresh must stop treating the previous successful snapshot as current.
    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains&server=1`)
    createdRow = page.getByRole('row').filter({ has: page.getByText('未授权验收链路', { exact: true }) })
    await createdRow.getByText('目标配置已应用', { exact: true }).first().waitFor()
    resourceDetail = await showResourceDetail(9)
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 2)
    await closeResourceDetail()
    pluginServersFailure = true
    await refreshPage()
    await page.getByText('服务器夹具读取失败', { exact: true }).waitFor()
    assert.equal(await createdRow.getByText('应用状态待确认', { exact: true }).count(), 1)
    assert.equal(await page.getByText('目标配置已应用', { exact: true }).count(), 0)
    resourceDetail = await showResourceDetail(9)
    assert.equal(await resourceDetail.getByText('应用状态待确认', { exact: true }).count(), 2)
    assert.equal(await resourceDetail.getByText('目标配置已应用', { exact: true }).count(), 0)
    assert.equal(await resourceDetail.getByRole('link', { name: '服务器 #2', exact: true }).getAttribute('href'), '#/servers/2')
    await closeResourceDetail()
    assert.deepEqual(mutations.slice(chainMutationStart), [{ path: '/api/plugins/sing-box/chains/ordered-batch', method: 'POST' }])
    pluginServersFailure = false
    chainFixtures = false
    await page.getByRole('navigation', { name: '节点资源类型', exact: true }).getByRole('link', { name: '直连节点', exact: true }).click()
    assert.equal(new URL(page.url()).hash, '#/plugins/sing-box/nodes?kind=direct&server=1')
    // Tabs preserve the server scope and the component keeps pending drafts. The
    // shared exit belongs to server 2, so explicitly clear scope and refresh the
    // changed fixtures rather than expecting a route change to remount loaders.
    await page.getByRole('link', { name: '查看全部资源', exact: true }).click()
    const recoveredResources = page.waitForResponse(response => new URL(response.url()).pathname === '/api/plugins/sing-box/proxy-resources' && response.request().method() === 'GET' && response.status() === 200)
    await refreshPage()
    await recoveredResources
    const currentCatalog = page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr')
    const direct3 = page.locator(`${width < 768 ? '.catalog-card' : '.catalog-table tbody tr'}[data-resource-key="direct:3"]`)
    await direct3.waitFor()
    assert.equal(await currentCatalog.count(), 1)
    assert.equal(await page.locator(`${width < 768 ? '.catalog-card' : '.catalog-table tbody tr'}[data-resource-key="direct:2"]`).count(),0)
    await page.getByText('普通节点需为代理用户授权并等待设备成功应用配置', { exact: false }).waitFor()
    await page.getByText('出口可使用内部连接凭据监听，无需为出口单独授权用户。', { exact: false }).waitFor()
    await page.goto(`${origin}/#/plugins/sing-box/nodes`)
    await page.getByRole('button', { name: /· 1 个引用$/ }).waitFor()
    chainsFailure = true
    await page.reload()
    // Flat and ordered projections report their own failed reads in separate panels.
    await page.locator('.nodes-page > [role="alert"]').getByText('链路夹具读取失败', { exact: true }).waitFor()
    await page.locator('section[aria-label="有序链路与资源引用"]').getByText('链路夹具读取失败', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button',{name:'创建节点',exact:true}).first().isDisabled(),true)
    assert.equal(await page.getByRole('button',{name:'创建两跳链路',exact:true}).isDisabled(),true)
    assert.equal(await page.getByText('目标配置已应用',{exact:true}).count(),0)
    chainsFailure = false
    nodesEmpty = true
    await page.reload()
    await page.getByText('填写端口或使用自动分配。为代理用户授权后，等待设备成功应用配置，再连接节点。', { exact: true }).waitFor()
    assert.equal(await page.getByText('为代理用户授权后，节点会自动启用。', { exact: false }).count(), 0)
    nodesEmpty = false

    await page.goto(`${origin}/#/servers/1`)
    await page.getByRole('button', { name: '接入 / 升级', exact: true }).click()
    const enrollment = page.getByRole('dialog')
    await enrollment.getByRole('link', { name: '安装服务器插件', exact: true }).waitFor()
    assert.equal(await enrollment.getByRole('link', { name: '安装服务器插件', exact: true }).getAttribute('href'), '#/plugins/sing-box')
    await enrollment.getByRole('link', { name: '安装服务器插件', exact: true }).click()
    await page.getByRole('heading', { name: '代理服务', exact: true }).waitFor()

    await page.getByRole('link', { name: '代理用户', exact: true }).click()
    await page.getByRole('heading', { name: '代理用户', exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '创建代理用户', exact: true }).count(), 2)
    await page.getByRole('link', { name: '系统管理员', exact: true }).click()
    await page.getByRole('heading', { name: '系统管理员', exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '创建代理用户', exact: true }).count(), 0)
    assert.equal(await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '统计仪表盘', exact: true }).getAttribute('href'), '#/statistics')
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    assert.deepEqual(errors, [])
    assert.equal(requests.some(path => ['/api/nodes', '/api/users', '/api/usage'].includes(path)), false)
    await page.close()
  }
  console.log('PASS: dist desktop/mobile, support does not enable business, queued/failed/ready installation and conservative legacy fallback, overview/server-node selection/settings preservation/deployment stale-failure guard/ungranted chain creation, either-endpoint server filtering/details/application states/unknown and stale-failure guards, listener/relay roles/enrollment navigation, statistics route and administrator/proxy-user separation, canonical APIs')
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
