import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

const catalogView = resources => resources.map(resource => ({ ...resource, original_name: resource.name, tags: [], note: '', sort_order: resource.id, revision: '1'.repeat(64), metadata_revision: 0 }))
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const file = resolve(root, new URL(request.url, 'http://127.0.0.1').pathname === '/' ? 'index.html' : `.${new URL(request.url, 'http://127.0.0.1').pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html':'text/html', '.js':'text/javascript', '.css':'text/css' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height:950 } }), errors = [], writes = []
    page.on('pageerror', error => errors.push(error.message))
    const nodes = [1,2].map(id => ({ id, server_id:id, name:`服务器${id}节点`, protocol:'vless-reality', port:443, public_host:`node${id}.example.com`, sni:'www.example.com' }))
    const servers = [1,2].map(id => ({ id, name:`服务器${id}`, enabled:true, online:true, agent_supported:true, read_only:false }))
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname
      if (route.request().method() !== 'GET') { writes.push(path); return route.fulfill({ status:405, json:{} }) }
      let data
      if (path === '/api/dashboard/access') data = { authenticated:true, public_dashboard:false }
      else if (path === '/api/plugins/sing-box/servers') data = servers
      else if (path === '/api/plugins/sing-box/nodes') data = nodes
      else if (path === '/api/plugins/sing-box/proxy-resources') data = nodes.map(node => ({ ...node, kind:'direct', server_name:`服务器${node.server_id}`, enabled:true, available:true, role:'direct', entry_node_id:null, tcp:true, udp:true, legacy:false, active_generation:null, pending_generation:null, minimum_generation:0, stage:'direct', last_error:null, reference_count:0, entry_eligible:true }))
      else if (path === '/api/plugins/sing-box/ordered-proxy-resources') data = proxyResourceFixtures(nodes, servers)
      else if (path === '/api/plugins/sing-box/ordered-subscription-sources') data = []
      else if (path === '/api/plugins/sing-box/node-catalog') data = catalogView(nodes.map(node => ({ ...node, kind:'direct', server_name:`服务器${node.server_id}`, enabled:true, available:true, role:'direct', entry_node_id:null, tcp:true, udp:true, legacy:false, active_generation:null, pending_generation:null, minimum_generation:0, stage:'direct', last_error:null, reference_count:0, entry_eligible:true })))
      else if (path === '/api/plugins/sing-box/subscription-sources') data = []
      else if (path === '/api/plugins/sing-box/usage') data = { total:'0', uplink:'0', downlink:'0', by_node:[], by_user:[] }
      else if (['policy-groups','package-groups','chains'].some(key => path === `/api/plugins/sing-box/${key}`)) data = []
      else { errors.push(`Unexpected API ${path}`); return route.fulfill({ status:404, json:{} }) }
      await route.fulfill({ json:data })
    })
    const catalogRows = page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr')
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/plugins/sing-box/nodes?server=2`)
    await page.getByRole('heading', { name:'代理节点', exact:true }).waitFor({ timeout:3000 })
    await page.waitForFunction(() => document.querySelector('[aria-label="按服务器筛选"]')?.value === '2')
    assert.equal(await catalogRows.count(), 1)
    assert.match(await catalogRows.innerText(), /服务器2节点/)
    assert.equal(await page.getByRole('navigation', { name:'主导航' }).getByRole('link', { name:'代理节点', exact:true }).getAttribute('aria-current'), 'page')
    await page.getByRole('button', { name:'创建节点', exact:true }).first().click()
    assert.equal(await page.getByRole('dialog').locator('[name=server_id]').inputValue(), '2')
    await page.getByRole('dialog').getByRole('button', { name:'取消', exact:true }).click()
    await page.evaluate(() => { location.hash = '/plugins/sing-box/nodes?server=1' })
    await page.waitForFunction(() => document.querySelector('[aria-label="按服务器筛选"]')?.value === '1')
    assert.match(await catalogRows.innerText(), /服务器1节点/)
    await page.evaluate(() => { location.hash = '/plugins/sing-box/nodes?server=3' })
    await page.waitForFunction(() => document.querySelector('[aria-label="按服务器筛选"]')?.value === '3')
    assert.equal(await page.getByRole('button', { name:'创建节点', exact:true }).first().isDisabled(), true)
    assert.equal(await catalogRows.count(), 0)
    await page.evaluate(() => { location.hash = '/plugins/sing-box/nodes?kind=chains' })
    await page.getByLabel('按类型筛选').waitFor()
    assert.equal(await page.getByLabel('按类型筛选').inputValue(), 'chain')
    assert.equal(await catalogRows.count(), 0)
    await page.getByRole('button', { name:'创建链路', exact:true }).click()
    const chain = page.getByRole('region', { name:'创建链路', exact:true })
    await chain.getByRole('heading', { name:'创建链路', exact:true }).waitFor()
    await chain.getByLabel('入口方式', { exact:true }).selectOption('existing')
    assert.equal(await chain.getByLabel('已有入口', { exact:true }).locator('option').count(), 3)
    await chain.getByRole('button', { name:'收起编辑器', exact:true }).click()
    for (const query of ['server=0','server=1&server=2','server=9007199254740992','server=1e2','kind=unknown','other=1']) {
      await page.evaluate(query => { location.hash = '/plugins/sing-box/nodes?' + query }, query)
      await page.getByRole('heading', { name:'这个页面不存在', exact:true }).waitFor()
      assert.equal(await page.locator('.node-editor').count(), 0)
    }
    assert.deepEqual(writes, [])
    assert.deepEqual(errors, [])
    await page.close()
  }
  console.log('PASS: selected-server node route and create default, live route change, legacy chain route opens unified resources and ordered editor, invalid/duplicate routes refuse without writes')
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
