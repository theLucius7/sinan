import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

const catalogView = resources => resources.map(resource => ({ ...resource, original_name: resource.name, tags: [], note: '', sort_order: resource.id, revision: '1'.repeat(64), metadata_revision: 0 }))
// TEST_ONLY read-only contract for the newly mounted UserDiagnostics resource.
// Device state and sensitive template content remain explicitly unavailable.
const diagnosisFixture = user => ({ user_id: user.id, account: { user_id: user.id, name: user.name, portal_created: false, keys: 0, active_sessions: 0, activation_expires_at: null },
  subscription: { status: 'empty', message: 'TEST_ONLY 真实设备状态未验证。', granted_nodes: 0, ready_managed_nodes: 0, ready_external_nodes: 0 },
  permissions: [], external_authorizations: [], ledger: [], quota_credits: [], package_history: [], rotations: [], events: [],
  limitations: { credentials_read: { available: false, reason: 'TEST_ONLY 敏感内容未读取；此处仅为独立只读诊断快照。' } } })
const templateFixture = { template: null, definition_redacted: false, credential_access_reason: 'TEST_ONLY 完整模板未读取。', supported_client: 'singbox', supported_version: '1.14.2', schema_validation: true, runtime_validation: false, limitations: 'TEST_ONLY 没有保存的模板，未执行真实客户端验证。' }

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless:true, ...(process.env.SINAN_CHROME_PATH ? {executablePath:process.env.SINAN_CHROME_PATH} : {}) })
try {
  for (const width of [1440,390,320]) {
    const page=await browser.newPage({viewport:{width,height:1000}})
    page.setDefaultTimeout(10000)
    const errors=[], requests=[], batches=[], policies=[]
    page.on('pageerror',error=>errors.push(error.message))
    const host=(id,name,server_id)=>({id,name,server_id,protocol:'vless-reality',port:20000+id,public_host:`node${id}.example.com`,sni:'www.example.com',enabled:true})
    const nodes=[host(1,'备用入口',1),host(2,'受管中段',2),host(3,'受管出口',3),host(4,'原链路专用入口',1)]
    const direct=node=>({...node,kind:'direct',server_name:`测试服务器 ${node.server_id}`,role:'direct',entry_node_id:null,tcp:true,udp:true,available:true,legacy:false,active_generation:null,pending_generation:null,minimum_generation:0,stage:'direct',last_error:null,reference_count:0, entry_eligible:true})
    const resources=nodes.slice(0,3).map(direct)
    resources.push({...direct(nodes[3]),id:7,kind:'chain',name:'原两跳链路',role:'chain_entry',entry_node_id:4,legacy:true,active_generation:1,stage:'active'})
    const source={id:10,name:'测试机场',kind:'inline',source_host:null,archived:false,settings_revision:1,identity_epoch:1,current_revision_id:100,last_success_at:1,supported_count:1,unsupported_count:0,dependency_ids:[],active_job_id:null,refresh_interval_seconds:86400}
    const external={id:101,source_id:10,node_version_id:201,source_revision_id:100,identity_epoch:1,name:'机场中间节点',protocol:'trojan',server:'transit.example.com',port:443,transport:'tcp',tcp:true,udp:false,selectable:true,present:true,identity_unique:true,reason:null}
    let created=false, generation=1, stage='active', renamed='机场混合链路', writes=[]
    await page.route('**/api/**',async route=>{
      const request=route.request(),path=new URL(request.url()).pathname,method=request.method()
      requests.push(`${method} ${path}`)
      const reply=value=>route.fulfill({json:value})
      if(path==='/api/plugins/sing-box/ordered-proxy-resources'||path==='/api/plugins/sing-box/ordered-subscription-sources')return reply([])
      if(path==='/api/dashboard/access')return reply({authenticated:true,public_dashboard:false})
      if(path==='/api/plugins/sing-box/servers')return reply([1,2,3].map(id=>({id,name:`测试服务器 ${id}`,enabled:true,online:true,agent_supported:true})))
      if(path==='/api/plugins/sing-box/nodes')return reply(nodes)
      if(path==='/api/plugins/sing-box/proxy-resources')return reply(resources)
      if(path==='/api/plugins/sing-box/node-catalog')return reply(catalogView(resources))
      if(path==='/api/plugins/sing-box/subscription-sources')return reply([source])
      if(path==='/api/plugins/sing-box/subscription-sources/10/nodes')return reply([external])
      if(path==='/api/plugins/sing-box/usage')return reply({total:'0',uplink:'0',downlink:'0',by_node:[],by_user:[]})
      if(path==='/api/plugins/sing-box/chains/batch'){
        const body=request.postDataJSON();batches.push(body)
        if(!created){
          assert.equal(body.items.length,2)
          assert.deepEqual(body.items[0].hops,[{kind:'subscription',source_id:10,external_node_id:101,node_version_id:201,update_mode:'pinned'},{kind:'managed',node_id:2}])
          assert.deepEqual(body.items[1].hops,[{kind:'managed',node_id:3}])
          assert.equal(body.items[0].entry.port,null);assert.equal(body.items[1].entry.port,24443)
          body.items.forEach((item,index)=>{const node=host(20+index,item.name,1);node.public_host=item.entry.public_host;node.port=item.entry.port??22000;nodes.push(node);resources.push({...direct(node),id:8+index,kind:'chain',name:item.name,role:'chain_entry',entry_node_id:node.id,active_generation:1,stage:'active',udp:false})})
          created=true
          return route.fulfill({status:503,json:{error:'测试：保存响应未确认，请重试'}})
        }
        assert.deepEqual(body,batches[0])
        return reply({request_id:body.request_id,chain_ids:[8,9],entry_node_ids:[20,21]})
      }
      if(path==='/api/plugins/sing-box/proxy-resources/chain/8/apply-node-versions'){
        writes.push(request.postDataJSON());assert.deepEqual(writes.at(-1),{expected_generation:1,versions:[{position:0,node_version_id:202}]})
        generation=2;stage='waiting_dependencies';Object.assign(resources.find(r=>r.kind==='chain'&&r.id===8),{pending_generation:2,stage});return reply({generation,stage})
      }
      if(path==='/api/plugins/sing-box/proxy-resources/chain/8'){
        if(method==='PATCH'){const body=request.postDataJSON();assert.equal(Object.hasOwn(body,'subscription_name'),body.name==='同步名称链路');renamed=body.name;if(body.subscription_name)nodes.find(n=>n.id===20).name=body.subscription_name;resources.find(r=>r.kind==='chain'&&r.id===8).name=renamed}
        return reply({resource:{...resources.find(r=>r.kind==='chain'&&r.id===8),name:renamed},node:nodes.find(n=>n.id===20),hops:[{position:0,kind:'subscription',node_id:101,server_id:null,source_id:10,version_id:201,update_mode:'pinned',name:external.name,protocol:'trojan',server:external.server,port:443,present:true,latest_version_id:202},{position:1,kind:'managed',node_id:2,server_id:2,source_id:null,version_id:null,update_mode:null,name:'受管中段',protocol:'vless-reality',server:'node2.example.com',port:20002,present:true,latest_version_id:null}],versions:[{generation,stage,last_error:null,created_at:1}]})
      }
      if(path==='/api/plugins/sing-box/policy-groups'){
        if(method==='POST'){const body=request.postDataJSON();policies.push({id:1,...body,member_count:0});return reply(policies[0])}return reply(policies)
      }
      if(path==='/api/plugins/sing-box/package-groups')return reply([])
      if(path==='/api/plugins/sing-box/users')return reply([{id:1,name:'测试代理用户',subscription_url:'https://panel.example.com/sub/TEST_ONLY',subscription_token:'TEST_ONLY'}])
      if(path==='/api/plugins/sing-box/users/1/portal')return reply({configuration:{enabled:false,reason:'TEST_ONLY 未启用',origin:`http://127.0.0.1:${server.address().port}`},keys:0,url:null,activation_expires_at:null})
      if(method==='GET'&&!new URL(request.url()).search&&path==='/api/plugins/sing-box/users/1/diagnosis')return reply(diagnosisFixture({id:1,name:'测试代理用户'}))
      if(method==='GET'&&!new URL(request.url()).search&&path==='/api/plugins/sing-box/users/1/client-template')return reply(templateFixture)
      if(path.endsWith('/users/1/policy-groups'))return reply({group_ids:[]})
      if(path.endsWith('/users/1/external-accesses'))return reply({revision:0,accesses:[],available_nodes:[]})
      if(path.endsWith('/users/1/portal'))return reply({configuration:{enabled:false,reason:'TEST_ONLY 未启用',origin:'https://panel.example.com'},keys:0,url:null,activation_expires_at:null})
      if(path.endsWith('/users/1/entitlement'))return reply({user_id:1,package_group_id:null,monthly_bytes:null,starts_at:null,expires_at:null,used_bytes:'0',status:'unmetered',allowed:true})
      if(path.endsWith('/accesses'))return reply([])
      errors.push(`Unexpected ${method} ${path}`);return route.fulfill({status:404,json:{error:'Unexpected API'}})
    })
    await installControlCenterFixtures(page)
    await page.goto(`http://127.0.0.1:${server.address().port}/#/plugins/sing-box/nodes`)
    await page.getByRole('button',{name:'创建链路',exact:true}).click()
    const editor=page.getByRole('region',{name:'创建链路'})
    const first=editor.locator('.chain-draft').first()
    await first.getByLabel('链路名称',{exact:true}).fill('机场混合链路')
    await first.getByLabel('入口公开地址',{exact:true}).fill('entry.example.com')
    await first.getByLabel('入口握手域名',{exact:true}).fill('www.example.com')
    await first.getByLabel('添加受管代理段',{exact:true}).selectOption('2')
    await first.getByRole('button',{name:'从订阅来源添加一段'}).click()
    await editor.getByRole('button',{name:'测试机场',exact:true}).click()
    await editor.getByLabel('选中节点后的更新方式').selectOption('pinned')
    await editor.getByRole('button',{name:'加入此段'}).click()
    await first.getByRole('button',{name:'第 2 段上移'}).click()
    await editor.getByRole('button',{name:'添加一条独立链路'}).click()
    const second=editor.locator('.chain-draft').nth(1)
    await second.getByLabel('链路名称',{exact:true}).fill('第二条独立链路')
    await second.getByLabel('入口公开地址',{exact:true}).fill('second.example.com')
    await second.getByLabel('入口握手域名',{exact:true}).fill('www.example.com')
    await second.getByLabel('入口端口',{exact:false}).fill('24443')
    await second.getByLabel('添加受管代理段',{exact:true}).selectOption('3')
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true)
    if(process.env.SINAN_UI_SCREENSHOT_DIR){await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`mixed-chain-editor-${width}.png`),fullPage:true})}
    await editor.getByRole('button',{name:'保存 2 条链路'}).click()
    await editor.getByRole('alert').getByText('测试：保存响应未确认，请重试').waitFor()
    assert.equal(await first.getByLabel('链路名称',{exact:true}).inputValue(),'机场混合链路')
    await editor.getByRole('button',{name:'保存 2 条链路'}).click()
    await editor.waitFor({state:'hidden'})
    assert.equal(batches.length,2);assert.equal(batches[0].request_id,batches[1].request_id)
    await page.getByRole('link',{name:'查看链路详情'}).click()
    const dialog=page.getByRole('dialog')
    await dialog.getByRole('heading',{name:'有序路径'}).waitFor()
    assert.match(page.url(),/\/nodes\/chain\/8$/)
    await dialog.getByLabel('更新第 1 段 机场中间节点').check()
    await dialog.getByRole('button',{name:'应用所选节点更新'}).click()
    await dialog.getByText('等待受管段配置',{exact:true}).first().waitFor()
    assert.equal(writes.length,1)
    await dialog.getByRole('button',{name:'修改名称'}).click()
    await dialog.getByLabel('链路名称',{exact:true}).fill('已改名链路')
    await dialog.getByRole('button',{name:'保存名称'}).click()
    await dialog.getByRole('heading',{name:'链路：已改名链路'}).waitFor()
    await dialog.getByRole('button',{name:'修改名称'}).click()
    await dialog.getByLabel('链路名称',{exact:true}).fill('同步名称链路')
    await dialog.getByLabel('同步修改订阅显示名称',{exact:false}).check()
    await dialog.getByRole('button',{name:'保存名称'}).click()
    await dialog.getByRole('heading',{name:'链路：同步名称链路'}).waitFor()
    assert.equal(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth),true)
    if(process.env.SINAN_UI_SCREENSHOT_DIR){await dialog.evaluate(element=>{element.scrollTop=0});await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`mixed-chain-detail-${width}.png`)})}
    await dialog.getByRole('button',{name:'关闭',exact:true}).click()
    await page.getByLabel('按类型筛选').selectOption('chain')
    const catalogRows = page.locator(width < 768 ? '.catalog-card' : '.catalog-table tbody tr')
    await catalogRows.filter({hasText:'原两跳链路'}).getByRole('link',{name:'详情',exact:true}).waitFor()
    assert.equal(await catalogRows.filter({hasText:'受管出口'}).count(),0)
    await page.getByRole('link',{name:'策略与套餐',exact:true}).click()
    assert.equal(await page.getByRole('button',{name:'两跳链路',exact:true}).count(),0)
    await page.getByRole('button',{name:'创建策略组'}).click()
    await dialog.getByLabel('名称',{exact:true}).fill('链路策略')
    await dialog.locator('input[name=chain_ids][value="8"]').check()
    assert.equal(await dialog.locator('input[name=node_ids][value="20"]').count(),0)
    await dialog.getByRole('button',{name:'保存',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.deepEqual(policies[0].chain_ids,[8])
    await page.getByRole('link',{name:'代理用户',exact:true}).click()
    await page.getByLabel('授权 备用入口').waitFor()
    assert.equal(await page.getByLabel('授权 原链路专用入口').count(),0)
    assert.equal(await page.getByLabel('授权 同步名称链路').count(),0)
    assert.equal(requests.some(path=>/\/chains$/.test(path)),false)
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: mixed resources, ordered subscription intermediate, independent batch entries, request retry, version apply, deep link, policy grants and responsive layouts')
}finally{await browser.close();await new Promise(resolve=>server.close(resolve))}
