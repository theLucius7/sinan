import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// Shipped dist with private loopback API responses; native compiler and persistence checks are separate.
const catalogView = resources => resources.map(resource => ({ ...resource, original_name: resource.name, tags: [], note: '', sort_order: resource.id, revision: '1'.repeat(64), metadata_revision: 0 }))
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = process.env.SINAN_WEB_DIST ?? fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const wait = async (condition, reason) => {
  const deadline = Date.now()+8000
  while(!await condition()) {assert(Date.now()<deadline,reason); await new Promise(done=>setTimeout(done,40))}
}
const tls = { mode:'manual', configured:true }
const common = {listen:'0.0.0.0',public_port:8443,tcp_fast_open:false,disable_tcp_keep_alive:false,tcp_keep_alive_seconds:60,tcp_keep_alive_interval_seconds:20,tls_alpn:[],tls_min_version:null,tls_max_version:null,tls_handshake_timeout_seconds:null}
const fixtures = [
  {protocol:'vless-reality',settings:{...common,reality:{handshake_server:'www.example.com',handshake_port:443,fingerprint:'firefox',max_time_difference_seconds:60,flow:'none'},transport:{type:'ws',path:'/proxy',host:'proxy.example.com',max_early_data:2048,early_data_header_name:'Sec-WebSocket-Protocol'}}},
  {protocol:'hysteria2',settings:{...common,tcp_keep_alive_seconds:null,tcp_keep_alive_interval_seconds:null,tls_min_version:'1.2',tls_max_version:'1.3',hysteria2:{up_mbps:null,down_mbps:null,ignore_client_bandwidth:true,obfs_enabled:true,bbr_profile:'conservative',masquerade:{status_code:200,content_type:'text/plain',content:'TEST_ONLY response'}}}},
  {protocol:'tuic',settings:{...common,tcp_keep_alive_seconds:null,tcp_keep_alive_interval_seconds:null,tuic:{congestion_control:'bbr',auth_timeout_seconds:10,heartbeat_seconds:20,zero_rtt_handshake:false,udp_relay_mode:'udp-over-stream'}}},
  {protocol:'anytls',settings:{...common,tls_min_version:'1.2',tls_max_version:'1.3',tls_handshake_timeout_seconds:15,anytls:{idle_session_check_seconds:30,idle_session_timeout_seconds:60,min_idle_session:2,padding_scheme:['stop=2','0=30-30','1=100-400']}}},
  {protocol:'naive',settings:{...common,tls_min_version:'1.2',tls_max_version:'1.3',tls_handshake_timeout_seconds:20}},
  {protocol:'snell-v6',settings:{...common,snell:{mode:'unshaped',reuse:true}}},
  {protocol:'shadowsocks2022',settings:{...common,shadowsocks:{udp_over_tcp:true,multiplex:{enabled:true,padding:true,protocol:'smux',max_connections:null,min_streams:null,max_streams:16}}}},
]
try {
  for (const width of [1440,390,320]) {
    const page = await browser.newPage({viewport:{width,height:1000}}), writes=[], errors=[]
    let nodeReadGate
    const origin = `http://127.0.0.1:${server.address().port}`
    page.on('pageerror', error => errors.push(error.message))
    const nodes = fixtures.map((node,index) => ({...structuredClone(node),id:index+1,server_id:1,name:`测试 ${node.protocol}`,enabled:true,port:20000+index,public_host:'proxy.example.com',sni:['snell-v6','shadowsocks2022'].includes(node.protocol)?'':'proxy.example.com',protocol_config:{type:node.protocol,...(['hysteria2','tuic','anytls','naive'].includes(node.protocol)?{tls}:{}),...(node.protocol==='shadowsocks2022'?{method:'2022-blake3-aes-128-gcm'}:{})}}))
    nodes.push({...structuredClone(nodes[0]),id:8,name:'链路使用中的节点',configuration_locked:true,referenced_chains:[{id:9,name:'测试链路'}]})
    const entry = {...structuredClone(nodes[0]), id:9, name:'测试有序链路入口', configuration_locked:true, referenced_chains:[{id:9,name:'测试链路'}]}
    nodes.push(entry)
    const servers = [{id:1,name:'测试服务器',enabled:true,online:true,agent_supported:true,read_only:false,source:'administrator'}]
    const chains = [{id:9,name:'测试链路',entry_node_id:9,exit_node_id:8,path_kind:'ordered'}]
    const richResources = () => proxyResourceFixtures(nodes, servers, chains).map(resource => resource.path_kind === 'ordered' ? {...resource, path_state:{...resource.path_state,candidate_generation:null,applied_generation:1,phase:'applied',generations:[{generation:1,state:'desired',hops:resource.hops},{generation:1,state:'applied',hops:resource.hops}]}} : resource)
    await page.route('**/*',async route => {
      const url=new URL(route.request().url()), path=url.pathname, method=route.request().method()
      assert.equal(url.origin,origin,'Node options never request external endpoints')
      if(!path.startsWith('/api/')) return route.continue()
      if(path==='/api/plugins/sing-box/nodes' && method==='GET' && nodeReadGate) {nodeReadGate.reached=true; await nodeReadGate.promise}
      let value
      if(path==='/api/me') value={authenticated:true}
      else if(path==='/api/dashboard/access') value={authenticated:true,public_dashboard:false}
      else if(path==='/api/plugins/sing-box/servers') value=servers
      else if(path==='/api/plugins/sing-box/usage') value={total:'0',by_node:[],by_user:[],uplink:'0',downlink:'0'}
      else if(path==='/api/plugins/sing-box/proxy-resources') value=flatResourceFixtures(nodes, servers, chains)
      else if(path==='/api/plugins/sing-box/node-catalog') value=catalogView(flatResourceFixtures(nodes, servers, chains))
      else if(path==='/api/plugins/sing-box/ordered-proxy-resources') value=richResources()
      else if(path==='/api/plugins/sing-box/subscription-sources' || path==='/api/plugins/sing-box/ordered-subscription-sources') value=[]
      else if(path==='/api/plugins/sing-box/nodes') value=nodes
      else if(path.match(/\/nodes\/\d+$/) && method==='PATCH') {const node=nodes.find(node=>node.id===Number(path.split('/').at(-1))); const body=route.request().postDataJSON(); writes.push({id:node.id,body}); Object.assign(node,body); value=node}
      else {errors.push(`Unexpected ${method}: ${path}`); return route.fulfill({status:404,json:{}})}
      await route.fulfill({json:value})
    })
    await installControlCenterFixtures(page)
    await page.goto(`http://127.0.0.1:${server.address().port}/#/plugins/sing-box/nodes`)
    const dialog=page.getByRole('dialog')
    for(let index=0;index<fixtures.length;index++) {
      await page.getByRole('button',{name:'编辑',exact:true}).nth(index).click()
      await dialog.evaluate(el => el.querySelectorAll('details').forEach(details => {details.open=true}))
      assert.equal(await dialog.locator('[name=public_port]').inputValue(),'8443')
      const fixture=fixtures[index], group = ({'vless-reality':'reality',hysteria2:'hysteria2',tuic:'tuic',anytls:'anytls','snell-v6':'snell',shadowsocks2022:'shadowsocks'})[fixture.protocol]
      if(fixture.protocol==='vless-reality') {
        assert.equal(await dialog.locator('[name=transport_type]').inputValue(),'ws')
        assert.equal(await dialog.locator('[name=transport_path]').inputValue(),'/proxy')
        assert.equal(await dialog.locator('[name=reality_flow]').isDisabled(),true)
        await dialog.locator('[name=max_early_data]').fill('0')
        assert.equal(await dialog.locator('[name=early_data_header_name]').isDisabled(),true)
        await dialog.locator('[name=max_early_data]').fill('2048')
        assert.equal(await dialog.locator('[name=early_data_header_name]').inputValue(),'Sec-WebSocket-Protocol')
        await dialog.locator('[name=transport_path]').fill('/draft')
        await dialog.locator('[name=transport_type]').selectOption('grpc')
        await dialog.locator('[name=service_name]').fill('draft-service')
        await dialog.locator('[name=transport_type]').selectOption('ws')
        assert.equal(await dialog.locator('[name=transport_path]').inputValue(),'/draft')
        let release
        nodeReadGate = {reached:false,promise:new Promise(done => {release=done})}
        const before = writes.length
        await dialog.locator('form').evaluate(form => {
          document.querySelector('.page-header button').click()
          form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))
        })
        await wait(() => nodeReadGate.reached,'A real current node read must be held')
        assert(await dialog.getByRole('button',{name:'保存目标配置',exact:true}).isDisabled())
        assert.equal(writes.length,before,'Same-event reload invalidates the captured node submit callback')
        assert(nodeReadGate.reached,'A real current node read is held')
        assert.equal(await dialog.locator('[name=transport_path]').inputValue(),'/draft')
        assert.equal(await dialog.locator('[name=service_name]').count(),0,'Only the chosen WS fields remain active')
        release(); nodeReadGate=undefined
        await dialog.getByRole('button',{name:'保存目标配置',exact:true}).waitFor()
        const save = dialog.getByRole('button',{name:'保存目标配置',exact:true})
        await wait(() => save.isEnabled(),'Equal current snapshots must restore the advanced draft')
        assert.equal(await dialog.locator('[name=transport_path]').inputValue(),'/draft')
        await dialog.locator('[name=transport_path]').fill('/proxy')
      }
      if(fixture.protocol==='hysteria2') assert.equal(await dialog.locator('[name=obfs_password]').inputValue(),'')
      if(['hysteria2','tuic','anytls','naive'].includes(fixture.protocol)) {
        assert.equal(await dialog.locator('[name=certificate]').inputValue(),'')
        assert.equal(await dialog.locator('[name=key]').inputValue(),'')
      }
      if(fixture.protocol==='anytls') {
        await dialog.locator('[name=certificate]').fill('TEST_ONLY draft certificate')
        await dialog.locator('[name=key]').fill('TEST_ONLY draft key')
        await dialog.locator('[name=tls_mode]').selectOption('acme')
        await dialog.locator('[name=email]').fill('admin@example.com')
        await dialog.locator('[name=tls_mode]').selectOption('manual')
        assert.equal(await dialog.locator('[name=certificate]').inputValue(),'TEST_ONLY draft certificate')
        assert.equal(await dialog.locator('[name=key]').inputValue(),'TEST_ONLY draft key')
        await dialog.locator('[name=certificate]').fill('')
        await dialog.locator('[name=key]').fill('')
      }
      assert.equal(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth),true)
      await dialog.locator('[name=name]').fill(`已编辑 ${fixture.protocol}`)
      await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
      await dialog.waitFor({state:'hidden'})
      const body=writes.at(-1).body
      if(group) assert.deepEqual(body.settings[group],fixture.settings[group])
      if(fixture.protocol==='vless-reality') assert.deepEqual(body.settings.transport,fixture.settings.transport)
      if(['hysteria2','tuic','anytls','naive'].includes(fixture.protocol)) assert.deepEqual(body.protocol_config.tls,{mode:'manual'})
      assert.equal(body.settings.tcp_keep_alive_seconds,fixture.settings.tcp_keep_alive_seconds)
      assert.equal(body.settings.tls_min_version,fixture.settings.tls_min_version)
    }
    await page.getByRole('button',{name:'编辑',exact:true}).nth(7).click()
    await dialog.getByText('此节点已被链路引用',{exact:false}).waitFor()
    assert.equal(await dialog.locator('[name=public_host]').isDisabled(),true)
    assert.equal(await dialog.locator('[name=name]').isEnabled(),true)
    await dialog.locator('[name=name]').fill('仅修改名称')
    await dialog.locator('[name=enabled]').uncheck()
    await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.deepEqual(writes.at(-1).body,{name:'仅修改名称',enabled:false})
    for(const transport of ['httpupgrade','grpc']) {
      await page.getByRole('button',{name:'编辑',exact:true}).first().click()
      await dialog.evaluate(el => el.querySelectorAll('details').forEach(details => {details.open=true}))
      await dialog.locator('[name=transport_type]').selectOption(transport)
      if(transport==='httpupgrade') await dialog.locator('[name=transport_path]').fill('/upgrade')
      else await dialog.locator('[name=service_name]').fill('node-service')
      assert.equal(await dialog.locator('[name=max_early_data]').count(),0,'Inactive WS options are excluded from the form')
      await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
      await dialog.waitFor({state:'hidden'})
      assert.deepEqual(writes.at(-1).body.settings.transport,transport==='httpupgrade'?{type:'httpupgrade',path:'/upgrade',host:'proxy.example.com'}:{type:'grpc',service_name:'node-service'})
      assert.equal(writes.at(-1).body.settings.reality.flow,'none')
    }
    await page.getByRole('button',{name:'编辑',exact:true}).first().click()
    await dialog.evaluate(el => el.querySelectorAll('details').forEach(details => {details.open=true}))
    await dialog.locator('[name=transport_type]').selectOption('tcp')
    await dialog.locator('[name=reality_flow]').selectOption('vision')
    await dialog.locator('[name=tcp_keep_alive_seconds]').fill('')
    await dialog.locator('[name=tcp_keep_alive_interval_seconds]').fill('')
    await dialog.locator('[name=public_port]').fill('')
    await dialog.getByRole('button',{name:'保存目标配置',exact:true}).click()
    await dialog.waitFor({state:'hidden'})
    assert.deepEqual(writes.at(-1).body.settings.transport,{type:'tcp'})
    assert.equal(writes.at(-1).body.settings.reality.flow,'vision')
    assert.equal(writes.at(-1).body.settings.tcp_keep_alive_seconds,null)
    assert.equal(writes.at(-1).body.settings.public_port,null)
    assert.deepEqual(errors,[])
    console.log(`node options ${width}: seven protocol round trips, secret preservation, ordered reference lock, pending callback zero writes, WS/HTTPUpgrade/gRPC and clearing passed`)
    await page.close()
  }
} finally { await browser.close(); await new Promise(resolve=>server.close(resolve)) }
