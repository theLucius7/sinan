import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// Shipped dist with controlled API responses; PostgreSQL verifies migration/data.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
// TEST_ONLY independent read-only view; no actual preflight or device evidence.
const operationsViewFixture = {
  runtime: { supported_versions: [], selected_version: 'TEST_ONLY', reason: 'TEST_ONLY 未读取真实运行时版本。', compatibility_metadata: { upstream_release: 'https://example.com/TEST_ONLY', upstream_commit: 'TEST_ONLY', protocols: [], acceptance_scope: 'TEST_ONLY 只读夹具' } },
  preflight: { id: null, ready: false, confirmed: false, device_checks_pending: false, checks: [] },
  drift: { state: 'unknown', target_revision: null, applied_revision: null, last_observed_at: null, reason: 'TEST_ONLY 无真实配置检查点。', checkpoint_supported: false, checkpoint: { state: 'unknown', observed_at: null, reason: 'TEST_ONLY 未读取进程或文件。' } },
  changes: [], history: [], paths: [], hop_observations: [], path_diagnosis: 'TEST_ONLY 无真实路径证据。',
}
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1440, 390, 320]) {
    const page = await browser.newPage({ viewport:{ width, height:950 } })
    const errors = [], writes = [], nodes = []
    page.on('pageerror', error => errors.push(error.message))
    let rejected = false
    const progress = { pending:true, enabled_nodes:1, authorized_nodes:0, status:null, history:[] }
    const pluginServers = [{ id:1, name:'测试服务器', enabled:true, online:false, agent_supported:true, read_only:false }]
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname, method = route.request().method()
      let value
      if (path === '/api/me') value = { authenticated:true }
      else if (path === '/api/dashboard/access') value = { authenticated:true, public_dashboard:false }
      else if (path === '/api/plugins/sing-box/servers') value = pluginServers
      else if (path === '/api/plugins/sing-box/usage') value = { total:'0', by_node:[], by_user:[], uplink:'0',downlink:'0' }
      else if (path === '/api/plugins/sing-box/proxy-resources') value = nodes.map(node => ({ ...node, kind:'direct', server_name:'测试服务器', role:'direct', entry_node_id:null, tcp:true, udp:true, available:true, stage:'direct', reference_count:0 }))
      else if (path === '/api/plugins/sing-box/node-catalog') value = catalogResourceFixtures(nodes.map(node => ({ ...node, kind:'direct', server_name:'测试服务器', role:'direct', entry_node_id:null, tcp:true, udp:true, available:true, stage:'direct', reference_count:0 })))
      else if (path === '/api/plugins/sing-box/subscription-sources') value = []
      else if (path === '/api/plugins/sing-box/nodes' && method === 'GET') value = nodes
      else if (path === '/api/plugins/sing-box/ordered-proxy-resources' && method === 'GET') value = proxyResourceFixtures(nodes, pluginServers)
      else if (path === '/api/plugins/sing-box/ordered-subscription-sources' && method === 'GET') value = []
      else if (path === '/api/plugins/sing-box/subscription-sources' && method === 'GET') value = []
      else if (path === '/api/plugins/sing-box/nodes' && method === 'POST') {
        const body = route.request().postDataJSON(); writes.push(body)
        value = { ...body,id:1,protocol:body.protocol_config.type,port:body.port ?? 20000 }
        nodes.push(value)
      } else if (path === '/api/plugins/sing-box/nodes/1' && method === 'PATCH') {
        const body = route.request().postDataJSON(); writes.push(body)
        if (rejected) { await route.fulfill({status:400,json:{error:'夹具：参数无效'}}); return }
        Object.assign(nodes[0],body); value=nodes[0]
      } else if (method === 'GET' && !new URL(route.request().url()).search && path === '/api/plugins/sing-box/servers/1/operations-view') value = operationsViewFixture
      else if (path.endsWith('/deployments')) value = progress
      else if (path.endsWith('/deployments/check')) value = { ready:false,checks:[{name:'设备在线',passed:false,detail:'设备离线，配置将在重新连接后下发'},{name:'签名运行时',passed:true,detail:'已验证匹配的制品'}] }
      else if (path.endsWith('/runtime-operations')) value = { supported:false,online:false,retiring:false,operations:[] }
      else { errors.push(`Unexpected ${method}: ${path}`); return route.fulfill({status:404,json:{}}) }
      await route.fulfill({json:value})
    })
    await installControlCenterFixtures(page)
    await page.goto(`http://127.0.0.1:${server.address().port}/#/plugins/sing-box/nodes`)
    await page.getByRole('button',{name:'创建节点',exact:true}).first().click()
    const dialog = page.getByRole('dialog')
    await dialog.locator('[name=name]').fill('测试 HY2')
    await dialog.locator('[name=public_host]').fill('proxy.example.com')
    await dialog.locator('[name=public_port]').fill('443')
    await dialog.getByLabel('代理协议',{exact:true}).selectOption('hysteria2')
    await dialog.locator('[name=sni]').fill('proxy.example.com')
    await dialog.locator('[name=email]').fill('admin@example.com')
    await dialog.getByText('协议高级设置',{exact:true}).click()
    await dialog.locator('[name=obfs_enabled]').check()
    await dialog.locator('[name=up_mbps]').fill('80')
    await dialog.locator('[name=down_mbps]').fill('40')
    assert.equal(await dialog.locator('[name=tcp_fast_open]').count(),0)
    assert.equal(await dialog.locator('[name=obfs_password]').inputValue(),'')
    assert.equal(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth),true)
    if (process.env.SINAN_UI_SCREENSHOT_DIR) {
      await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR,{recursive:true})
      await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`node-settings-${width}.png`)})
    }
    await dialog.getByRole('button',{name:'创建目标节点',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.equal(writes[0].settings.public_port,443)
    assert.equal(writes[0].settings.hysteria2.obfs_enabled,true)
    assert.equal(writes[0].settings.hysteria2.up_mbps,80)
    assert.equal(Object.hasOwn(writes[0].settings.hysteria2,'obfs_password'),false)
    const currentRow = page.locator(width < 768 ? '.catalog-card[data-resource-key="direct:1"]' : '.catalog-table [data-resource-key="direct:1"]')
    await currentRow.getByText('proxy.example.com:443',{exact:true}).waitFor()
    await page.getByRole('button',{name:'查看差异、完整预检与发布状态',exact:true}).click()
    await dialog.getByText('目标配置待发布',{exact:true}).waitFor()
    await dialog.getByRole('button',{name:'检查基础安装条件',exact:true}).click()
    await dialog.getByText('设备离线，配置将在重新连接后下发',{exact:true}).waitFor()
    Object.assign(progress,{pending:false,status:{target_rev:2,applied_rev:1,last_result_rev:2,healthy:true,last_error:'测试校验失败',updated_at:1}})
    await dialog.locator('.node-deployment > .node-deployment-heading').getByRole('button',{name:'刷新',exact:true}).click()
    await dialog.getByText('最新配置应用失败',{exact:true}).waitFor()
    assert.equal(await dialog.getByText('目标配置已应用',{exact:true}).count(),0)
    await dialog.getByRole('button',{name:'关闭',exact:true}).click()
    await currentRow.getByRole('button',{name:'编辑',exact:true}).click()
    await dialog.locator('[name=enabled]').uncheck()
    await dialog.locator('[name=public_port]').fill('')
    rejected=true
    await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
    await dialog.getByRole('alert').getByText('夹具：参数无效').waitFor()
    assert.equal(await dialog.locator('[name=enabled]').isChecked(),false)
    rejected=false
    await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.equal(writes.at(-1).enabled,false)
    assert.equal(writes.at(-1).settings.public_port,null)
    await currentRow.getByText('已停用',{exact:true}).waitFor()
    if (process.env.SINAN_UI_SCREENSHOT_DIR) await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`node-list-${width}.png`)})
    const layout = await page.evaluate(() => ({width:innerWidth, scroll:document.documentElement.scrollWidth, overflow:[...document.querySelectorAll('main *')].filter(el => el.getBoundingClientRect().right > innerWidth + 1).slice(0,8).map(el => ({tag:el.tagName,class:el.className,right:el.getBoundingClientRect().right}))}))
    assert.equal(layout.scroll <= layout.width,true,JSON.stringify(layout))
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: node settings desktop/mobile, protocol fields, secret preservation, disabled state, failed-save retention and deployment readiness/status')
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
