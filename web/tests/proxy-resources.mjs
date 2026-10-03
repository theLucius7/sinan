import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { mkdir, readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// Exercise the shipped UI with owned API fixtures, including a committed request whose response is lost.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/',import.meta.url))
const server = createServer(async (request,response) => {
  const path = new URL(request.url,'http://127.0.0.1').pathname
  const file = resolve(dist,path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) {response.writeHead(400).end();return}
  try {const body = await readFile(file); response.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(file)] ?? 'application/octet-stream'}).end(body)}
  catch {response.writeHead(404).end()}
})
let browser
try {
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve))
  browser = await chromium.launch({headless:true,...(process.env.SINAN_CHROME_PATH ? {executablePath:process.env.SINAN_CHROME_PATH} : {})})
  const origin = `http://127.0.0.1:${server.address().port}`
  for (const width of [1440,390,320]) {
    const page = await browser.newPage({viewport:{width,height:1000}})
    page.setDefaultTimeout(7000)
    await page.clock.install()
    const prefix = '/api/plugins/sing-box', errors = [], writes = [], receipts = new Map()
    const servers = [1,2].map(id => ({id,name:`服务器 ${id}`,enabled:true,online:false,read_only:false,agent_supported:true,source:'administrator',installation:{state:'pending',reason:'等待设备应用，尚未确认连通。',target_rev:1,applied_rev:0}}))
    let nodes = [1,2,3,4].map(id => ({id,name:id === 2 ? '共享出口' : `监听 ${id}`,server_id:id === 2 ? 2 : 1,protocol:'vless-reality',enabled:true,port:20000+id,public_host:id === 2 ? 'exit.example.com' : 'entry.example.com',sni:'www.example.com',public_key:'TEST_ONLY',short_id:'abcd',...(id === 3 ? {settings:{public_port:8443}} : {})}))
    let chains = [{id:1,name:'既有链路',entry_node_id:3,exit_node_id:2,available:true}]
    let nextNode = 200,nextChain = 100,allocations = 0,mode = 'reject-once',resourceFailure = false,malformed = false,nodesFailure = false,broken = false
    let enterTimeout,releaseTimeout
    const timeoutEntered = new Promise(resolve => {enterTimeout=resolve})
    const timeoutReleased = new Promise(resolve => {releaseTimeout=resolve})
    page.on('pageerror',error => errors.push(error.message))
    const resources = () => {
      const values = proxyResourceFixtures(nodes,servers,chains)
      if (broken) {const value = values.find(value => value.kind === 'chain' && value.id === 1);if (value) {value.available=false;value.unavailable_reasons=['入口公开端口参数无法确认，暂显示监听端口'];value.entry.public_port=value.entry.port}}
      return values
    }
    await page.route('**/api/**',async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      if (method !== 'GET') writes.push({path,method,serialized:request.postData(),body:request.postData() ? request.postDataJSON() : null})
      let value
      if (method === 'GET' && path === '/api/dashboard/access') value={authenticated:true,public_dashboard:false}
      else if (method === 'GET' && path === '/api/me') value={authenticated:true}
      else if (method === 'GET' && path === `${prefix}/servers`) value=servers
      else if (method === 'GET' && [ `${prefix}/subscription-sources`, `${prefix}/ordered-subscription-sources` ].includes(path)) value=[]
      else if (method === 'GET' && path === `${prefix}/proxy-resources`) value=flatResourceFixtures(nodes,servers,chains)
      else if (method === 'GET' && path === `${prefix}/node-catalog`) value=catalogResourceFixtures(flatResourceFixtures(nodes,servers,chains))
      else if (method === 'GET' && path === `${prefix}/nodes`) {
        if (nodesFailure) {await route.fulfill({status:500,json:{error:'旧节点设置无法解析'}});return}
        value=nodes
      } else if (method === 'GET' && path === `${prefix}/usage`) value={total:'0',uplink:'0',downlink:'0',by_node:[],by_user:[]}
      else if (method === 'GET' && path === `${prefix}/ordered-proxy-resources`) {
        if (resourceFailure) {await route.fulfill({status:403,json:{error:'资源快照读取被拒绝'}});return}
        value=malformed ? [{id:1,name:'旧版不完整元数据'}] : resources()
      } else if (method === 'GET' && /^\/api\/plugins\/sing-box\/ordered-proxy-resources\/(direct|chain)\/[1-9]\d*$/.test(path)) {
        const [,kind,id] = path.match(/\/(direct|chain)\/(\d+)$/)
        value=resources().find(value => value.kind === kind && value.id === Number(id))
        if (!value) {await route.fulfill({status:404,json:{error:'所选资源已删除'}});return}
      } else if (method === 'POST' && path === `${prefix}/chains/ordered-batch`) {
        const body = request.postDataJSON()
        assert.match(body.request_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
        assert.deepEqual(Object.keys(body).sort(),['items','request_id'])
        assert(body.items.length >= 1 && body.items.length <= 32)
        if (receipts.has(body.request_id)) {
          const saved = receipts.get(body.request_id)
          assert.equal(request.postData(),saved.serialized,'an idempotent replay must retain the exact body')
          await route.fulfill({status:200,json:saved.result});return
        }
        if (mode === 'reject-once' || mode === 'reject-draft') {
          mode = 'normal'
          await route.fulfill({status:503,json:{error:'夹具：本批次未创建，请原样重试。'}});return
        }
        const result = {request_id:body.request_id,chain_ids:[],entry_node_ids:[]}
        for (const item of body.items) {
          assert.deepEqual(Object.keys(item).sort(),['entry','hops','name'])
          assert.deepEqual(item.hops,[{kind:'managed',node_id:2}])
          let entry
          if (item.entry.mode === 'new') {
            assert.equal(item.entry.server_id,1)
            assert.equal(item.entry.public_host,'entry.example.com')
            assert.equal(item.entry.sni,'www.example.com')
            entry={id:nextNode++,name:`${item.name} · 入口`,server_id:1,protocol:'vless-reality',enabled:true,port:item.entry.port ?? 21000+allocations,public_host:item.entry.public_host,sni:item.entry.sni,public_key:'TEST_ONLY',short_id:'abcd'}
            nodes.push(entry);allocations++
          } else {assert.equal(item.entry.mode,'existing');entry=nodes.find(node => node.id === item.entry.node_id);assert(entry);assert(!chains.some(chain => chain.entry_node_id === entry.id))}
          const chain={id:nextChain++,name:item.name,entry_node_id:entry.id,exit_node_id:2,available:true,path_kind:'ordered'}
          chains.push(chain);result.chain_ids.push(chain.id);result.entry_node_ids.push(entry.id)
        }
        receipts.set(body.request_id,{serialized:request.postData(),result})
        if (mode === 'lose-response') {mode='normal';await route.abort('connectionreset');return}
        if (mode === 'timeout-response') {
          mode='normal';enterTimeout();await timeoutReleased
          // The browser owns and has already aborted this request after its real deadline.
          await route.abort('timedout').catch(error => {if (!/handled|closed|cancel|abort/i.test(error.message)) throw error})
          return
        }
        await route.fulfill({status:201,json:result});return
      } else if (method === 'DELETE' && path === `${prefix}/nodes/2`) {
        await route.fulfill({status:409,json:{error:'出口被链路引用：既有链路 #1；请先解除引用。',references:{policies:[],chains:[{id:1,name:'既有链路',role:'exit'}]}}});return
      } else if (method === 'DELETE' && path === `${prefix}/ordered-proxy-resources/chain/1`) {
        assert(broken && nodesFailure,'broken resources must remain cleanable when the old nodes API fails')
        chains=chains.filter(chain => chain.id !== 1);nodes=nodes.filter(node => node.id !== 3)
        assert(nodes.some(node => node.id === 2),'shared exit must remain')
        await route.fulfill({status:204,body:''});return
      } else {errors.push(`Unexpected API: ${method} ${path}`);await route.fulfill({status:404,json:{error:'夹具拒绝未知接口'}});return}
      await route.fulfill({json:value})
    })
    const create = page.getByRole('button',{name:'创建两跳链路',exact:true})
    const poll = async () => {await page.clock.fastForward(5000)}
    const enabled = async locator => {await locator.waitFor();const end=Date.now()+7000;while(await locator.isDisabled() && Date.now()<end) await page.waitForTimeout(20);assert.equal(await locator.isDisabled(),false)}
    // Catalog and chains are separate sections; both stay mounted, so counts include either.
    const views = page.getByRole('navigation',{name:'节点视图',exact:true})
    const showView = name => views.getByRole('link',{name,exact:true}).click()
    const chainRows = page.locator('.proxy-resource-table tbody tr')
    const screenshot = async name => {if (process.env.SINAN_UI_SCREENSHOT_DIR) {await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`proxy-${name}-${width}.png`)})}}
    const catalogRows = page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr')
    const directKey = id => page.locator(`${width < 768 ? '.catalog-card' : '.catalog-table tbody tr'}[data-resource-key="direct:${id}"]`)
    const resourceCount = async () => await catalogRows.count() + await page.locator('.proxy-resource-table tbody tr').count()
    const waitCount = async count => { const deadline = Date.now() + 8000; while (await resourceCount() !== count) { assert(Date.now() < deadline, `Expected ${count} visible resources`); await page.waitForTimeout(20) } }
    await page.goto(`${origin}/#/plugins/sing-box/nodes`)
    await showView('链路')
    await enabled(create)
    assert.equal(await resourceCount(),4)
    assert.equal(await directKey(1).count(),1)
    assert.equal(await page.locator('[data-resource-key="chain:1"]').count(),1)
    assert.equal(await directKey(3).count(),0)
    assert.equal(await page.locator('.stat').filter({hasText:'代理资源'}).locator('strong').innerText(),'4')
    assert.equal(await page.locator('.stat').filter({hasText:'物理监听数'}).locator('strong').innerText(),'4')
    await screenshot('resources')
    await page.locator('[data-resource-key="chain:1"]').getByRole('button',{name:'路径与引用',exact:true}).click()
    let dialog = page.getByRole('dialog')
    await dialog.getByText('entry.example.com:8443',{exact:true}).waitFor()
    await dialog.getByText('受管两跳链路',{exact:true}).waitFor()
    await dialog.getByText('授权人数表示当前授权关系，不代表套餐仍然有效。',{exact:false}).waitFor()
    assert.equal(await dialog.getByText('目标配置已应用',{exact:true}).count(),0)
    await dialog.getByRole('button',{name:'关闭',exact:true}).click()
    // The catalog type filter narrows the catalog; the chain section always lists chains.
    await showView('节点库')
    await page.getByRole('combobox',{name:'按类型筛选',exact:true}).selectOption('direct')
    assert.equal(await catalogRows.count(),3)
    assert.equal(await chainRows.count(),1)
    await page.getByRole('combobox',{name:'按类型筛选',exact:true}).selectOption('chain')
    await waitCount(1)
    assert.equal(await catalogRows.count(),0)
    await page.getByRole('combobox',{name:'按类型筛选',exact:true}).selectOption('')
    await page.getByRole('combobox',{name:'按服务器筛选',exact:true}).selectOption('2')
    await waitCount(2)
    assert.equal(await catalogRows.count(),1)
    await showView('链路')
    await page.getByText('筛选范围：任一受管段属于「服务器 2」的链路。',{exact:false}).waitFor()
    assert.equal(await chainRows.count(),1)
    await showView('节点库')
    await page.getByRole('combobox',{name:'按服务器筛选',exact:true}).selectOption('')
    await showView('链路')
    await enabled(create);await create.click();dialog=page.getByRole('dialog')
    await dialog.locator('[name=server_id]').selectOption('1')
    await dialog.locator('[name=public_host]').fill('entry.example.com')
    await dialog.locator('[name=sni]').fill('www.example.com')
    await dialog.locator('[name=exit_node_id]').selectOption('2')
    await dialog.locator('[name=name]').fill('批量甲')
    await dialog.getByRole('button',{name:'添加一条链路',exact:true}).click()
    await dialog.locator('[name=name_1]').fill('批量乙')
    await dialog.locator('[name=entry_port_1]').fill('24443')
    await screenshot('batch')
    await dialog.locator('form').evaluate(form => {form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))})
    await dialog.getByRole('alert').filter({hasText:'本批次未创建'}).waitFor()
    assert.equal(chains.length,1);assert.equal(allocations,0);assert.equal(writes.length,1)
    assert.equal(await dialog.locator('[name=name]').inputValue(),'批量甲')
    assert.equal(await dialog.locator('[name=name_1]').inputValue(),'批量乙')
    await dialog.getByRole('button',{name:'重试原批次',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    await page.getByText('批量甲',{exact:true}).waitFor()
    assert.equal(writes.length,2);assert.equal(writes[0].serialized,writes[1].serialized)
    assert.equal(allocations,2);assert.equal(chains.length,3)
    assert.equal(writes[1].body.items[0].entry.port,null);assert.equal(writes[1].body.items[1].entry.port,24443)
    assert.equal(await page.locator('[data-resource-key="direct:200"]').count(),0)
    await page.locator('.stat').filter({hasText:'物理监听数'}).getByText('6',{exact:true}).waitFor()
    assert.equal(await page.locator('.stat').filter({hasText:'物理监听数'}).locator('strong').innerText(),'6')
    // Existing-entry creation commits, then loses the response before the browser receives the receipt.
    mode='lose-response';await enabled(create);await create.click();dialog=page.getByRole('dialog')
    await dialog.locator('[name=entry_mode]').selectOption('existing')
    await dialog.locator('[name=name]').fill('失响应链路')
    await dialog.locator('[name=entry_node_id]').selectOption('1')
    await dialog.locator('[name=exit_node_id]').selectOption('2')
    await dialog.getByRole('button',{name:'创建未授权链路',exact:true}).click()
    await dialog.getByRole('alert').filter({hasText:'无法连接面板'}).waitFor()
    const committed = chains.length, beforeAllocations = allocations, original=writes.at(-1)
    await poll()
    const blockedRetry = dialog.getByRole('button',{name:'重试原批次',exact:true}), replayWriteCount = writes.length
    await dialog.getByRole('alert').filter({hasText:'链路身份已变更'}).waitFor()
    assert.equal(await blockedRetry.isDisabled(),true)
    assert.equal(await directKey(1).count(),0)
    assert.equal(await dialog.locator('[name=entry_node_id]').inputValue(),'1')
    assert.equal(await dialog.locator('[name=name]').inputValue(),'失响应链路')
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})))
    await blockedRetry.evaluate(button => {const disabled=button.disabled;try {button.disabled=false;button.click()} finally {button.disabled=disabled}})
    await page.waitForTimeout(50)
    assert.equal(writes.length,replayWriteCount);assert.equal(writes.at(-1).serialized,original.serialized)
    assert.equal(chains.length,committed);assert.equal(allocations,beforeAllocations)
    // An explicit page departure discards the unresolved local editor after its committed resource is confirmed.
    await dialog.getByRole('button',{name:'取消',exact:true}).click()
    await page.locator('[data-resource-key="chain:102"]').getByText('失响应链路',{exact:true}).waitFor()
    await page.reload()
    // The reloaded route keeps the chain section and carries no server scope.
    assert.equal(new URL(page.url()).hash,'#/plugins/sing-box/nodes?view=chains')
    await page.waitForFunction(() => document.querySelector('select[aria-label="按服务器筛选"]')?.value === '')
    // Changing a rejected draft gets a new request key; it never mutates the old request body.
    mode='reject-draft';await enabled(create);await create.click();dialog=page.getByRole('dialog')
    await dialog.locator('[name=server_id]').selectOption('1')
    await dialog.locator('[name=public_host]').fill('entry.example.com')
    await dialog.locator('[name=sni]').fill('www.example.com')
    await dialog.locator('[name=exit_node_id]').selectOption('2')
    await dialog.locator('[name=name]').fill('修改前')
    await dialog.getByRole('button',{name:'创建未授权链路',exact:true}).click()
    await dialog.getByRole('alert').filter({hasText:'本批次未创建'}).waitFor()
    const rejected=writes.at(-1)
    await dialog.locator('[name=name]').fill('修改后')
    await dialog.getByRole('button',{name:'创建未授权链路',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.notEqual(writes.at(-1).body.request_id,rejected.body.request_id)
    assert.equal(rejected.body.items[0].name,'修改前')
    assert.equal(writes.at(-1).body.items[0].name,'修改后')
    // A real frontend deadline aborts an outstanding request without discarding its exact replay body.
    mode='timeout-response';await enabled(create);await create.click();dialog=page.getByRole('dialog')
    await dialog.locator('[name=server_id]').selectOption('1')
    await dialog.locator('[name=public_host]').fill('entry.example.com')
    await dialog.locator('[name=sni]').fill('www.example.com')
    await dialog.locator('[name=exit_node_id]').selectOption('2')
    await dialog.locator('[name=name]').fill('超时链路')
    await dialog.getByRole('button',{name:'创建未授权链路',exact:true}).click()
    let timeoutWait
    try {await Promise.race([timeoutEntered,new Promise((_,reject) => {timeoutWait=setTimeout(() => reject(new Error('owned timeout request did not arrive')),7000)})])}
    finally {clearTimeout(timeoutWait)}
    const timedOut = writes.at(-1), timeoutChains = chains.length, timeoutAllocations = allocations
    try {await page.clock.fastForward(30000);await dialog.getByRole('alert').filter({hasText:'提交超时，批次可能已完成'}).waitFor()}
    finally {releaseTimeout()}
    await enabled(dialog.getByRole('button',{name:'重试原批次',exact:true}))
    await dialog.getByRole('button',{name:'重试原批次',exact:true}).click();await dialog.waitFor({state:'hidden'})
    assert.equal(writes.at(-1).serialized,timedOut.serialized)
    assert.equal(chains.length,timeoutChains);assert.equal(allocations,timeoutAllocations)
    // The preview caps the UI at 32 rows without sending requests.
    await enabled(create);await create.click();dialog=page.getByRole('dialog')
    const writeCount=writes.length
    for (let i=1;i<32;i++) await dialog.getByRole('button',{name:'添加一条链路',exact:true}).click()
    assert.equal(await dialog.locator('.chain-draft-row').count(),32)
    assert.equal(await dialog.getByRole('button',{name:'添加一条链路',exact:true}).isDisabled(),true)
    assert.equal(writes.length,writeCount)
    await dialog.getByRole('button',{name:'取消',exact:true}).click()
    await showView('节点库')
    await directKey(2).getByRole('button',{name:'删除',exact:true}).click();dialog=page.getByRole('dialog')
    await dialog.getByRole('button',{name:'确认删除',exact:true}).click()
    await dialog.getByRole('alert').filter({hasText:'既有链路 #1'}).waitFor()
    assert(nodes.some(node => node.id === 2))
    await dialog.getByRole('button',{name:'取消',exact:true}).click()
    await showView('链路')
    // Old /nodes can fail while the public projection still identifies a broken resource for cleanup.
    broken=true;nodesFailure=true;await page.locator('header.page-header').getByRole('button',{name:'刷新',exact:true}).click()
    await page.getByRole('alert').filter({hasText:'旧节点设置无法解析'}).waitFor()
    const brokenRow=page.locator('[data-resource-key="chain:1"]')
    await brokenRow.getByText('资源已不可用',{exact:true}).waitFor()
    await brokenRow.getByText('入口公开端口参数无法确认，暂显示监听端口',{exact:true}).waitFor()
    await enabled(brokenRow.getByRole('button',{name:'删除',exact:true}))
    assert.equal(await create.isDisabled(),true)
    await brokenRow.getByRole('button',{name:'删除',exact:true}).click();dialog=page.getByRole('dialog')
    await dialog.getByRole('button',{name:'确认删除',exact:true}).click();await dialog.waitFor({state:'hidden'})
    const deletedDeadline=Date.now()+7000
    while (await brokenRow.count() !== 0) {
      assert(Date.now()<deletedDeadline,'deleted chain must disappear from every resource layout')
      await page.waitForTimeout(20)
    }
    assert(!nodes.some(node => node.id === 3));assert(nodes.some(node => node.id === 2))
    assert.equal(writes.at(-1).path,`${prefix}/ordered-proxy-resources/chain/1`)
    nodesFailure=false;broken=false;await poll();await enabled(create)
    // Bad metadata and a failed GET keep the last good public list readable but block writes.
    malformed=true;await page.locator('header.page-header').getByRole('button',{name:'刷新',exact:true}).click()
    await page.getByRole('alert').filter({hasText:'资源信息格式不完整'}).first().waitFor()
    assert.equal(await create.isDisabled(),true)
    await showView('节点库')
    assert.equal(await directKey(2).count(),1)
    assert.equal(await directKey(2).getByRole('button',{name:'删除',exact:true}).isDisabled(),true)
    await showView('链路')
    malformed=false;resourceFailure=true;await page.locator('header.page-header').getByRole('button',{name:'刷新',exact:true}).click()
    await page.getByRole('alert').filter({hasText:'资源快照读取被拒绝'}).first().waitFor()
    assert.equal(await create.isDisabled(),true)
    await showView('节点库')
    await directKey(2).getByText('资源状态待确认',{exact:true}).waitFor()
    await showView('链路')
    resourceFailure=false;await page.locator('header.page-header').getByRole('button',{name:'刷新',exact:true}).click();await enabled(create)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true)
    assert.equal(writes.some(write => write.path.includes('grant') || write.path.includes('polic') || write.path.includes('/access')),false)
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: unified typed resources, scoped topology, counts and NAT ports, atomic batch and exact replay including lost-response role changes, changed-draft key, 32-row cap, no implicit grants, conflict references, broken-resource cleanup, invalid/stale metadata and mobile layout')
} finally {await browser?.close();await new Promise(resolve => server.close(resolve))}
