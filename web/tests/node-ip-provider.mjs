import { installControlCenterFixtures } from './control-center-fixtures.mjs'
// Real dist, normalized panel API fixtures, private loopback only; never a provider request.
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const now = Math.floor(Date.now() / 1000), at = now - 60, ip = '1.1.1.1'
const id = '00000000-0000-4000-8000-000000000024'
const descriptors = [
  ['ipregistry-node', 'Ipregistry 正式节点接口', 'ipregistry-v1', 'Ipregistry 正式节点查询', 'https://api.ipregistry.co'],
  ['dbip-node', 'DB-IP 正式节点接口', 'dbip-v2', 'DB-IP 正式节点查询', 'https://api.db-ip.com/v2'],
]
function view(problem = null, history = false, ready = true, configured = true) {
  return { ip_addresses:[ip], public_ip_addresses:[ip], private_ip_addresses:[],
    node_query_ready:ready, node_query_reason:ready ? null : 'TEST_ONLY 正式节点查询 r21 制品尚未上传',
    providers:descriptors.map(([provider,label,database]) => ({provider,label,kind:'node_self',execution:'node',enabled:configured,
      reason:configured ? null : '节点尚未配置正式私有凭证，信息未知', databases:[{database,label}]})),
    quality:descriptors.map(([provider,,database,label,source]) => {
      const failure = problem ? { kind:problem[0], message:problem[1], http_status:problem[2] ?? null,
        attempted_at:configured ? now : null, elapsed_ms:configured ? 12 : null } : null
      const fields = !problem || history ? [{label:'代理',kind:'boolean',value:false},
        ...(database === 'dbip-v2' ? [{label:'纬度',kind:'latitude',value:0}] : [])] : []
      const success = fields.length ? at : null, until = success ? success+86400 : null
      return { ip, provider, checked_at:now, expires_at:until ?? 0, status:problem ? 'failed' : 'succeeded',
        last_attempt_at:configured ? now : null,last_success_at:success,fresh_until:until,last_error:failure ? {[database]:failure} : {},
        databases:[{database,label,provider,execution:'node',source,target_ip:ip,observed_ip:configured ? ip : null,
          status:problem ? 'failed' : 'succeeded',fields,error:failure?.message ?? null,error_kind:failure?.kind ?? null,
          http_status:failure?.http_status ?? null,attempted_at:failure?.attempted_at ?? (configured ? at : null),elapsed_ms:failure?.elapsed_ms ?? (configured ? 12 : null),
          last_attempt_at:configured ? now : null,last_success_at:success,fresh_until:until,last_error:failure,
          historical:Boolean(problem && history),available:configured,unavailable_reason:configured ? null : '节点尚未配置正式私有凭证，信息未知'}] }
    }) }
}
let state = {view:view(), next:view(), postStatus:201}, posts = [], unexpected = []
const server = createServer(async (request,response) => {
  const path = new URL(request.url,'http://127.0.0.1').pathname
  if (path.startsWith('/api/')) {
    let answer
    if (request.method === 'GET' && path === '/api/dashboard/access') answer = {authenticated:true,public_dashboard:false}
    else if (request.method === 'GET' && path === '/api/me') answer = {}
    else if (request.method === 'GET' && path === '/api/servers/1') answer = {id:1,name:'TEST_ONLY 节点正式来源',online:true,static_info:{},latest_metrics:{},capabilities:[]}
    else if (request.method === 'GET' && path === '/api/servers/1/ip-quality') answer = state.view
    else if (request.method === 'POST' && path === '/api/servers/1/ip-quality/node-query') {
      let body = ''; for await (const chunk of request) body += chunk
      posts.push(JSON.parse(body))
      if (state.postStatus !== 201) { response.writeHead(state.postStatus,{'Content-Type':'application/json'}).end(JSON.stringify({error:'TEST_ONLY 设备已有诊断任务，请等待或取消'})); return }
      state.view = state.next
      answer = {id,status:'queued',job:{plugin:'nodequality',version:'a92fca6c0067df29ddd03fdc2fee6f3000f64545-r21',options:{mode:'ip',ip_version:'both'}}}
    } else { unexpected.push(`${request.method} ${path}`); response.writeHead(404).end(); return }
    response.writeHead(request.method === 'POST' ? 201 : 200,{'Content-Type':'application/json','Cache-Control':'no-store'}).end(JSON.stringify(answer)); return
  }
  const file = resolve(dist,path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200,{'Content-Type':({'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'})[extname(file)] ?? 'application/octet-stream'}).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({headless:true,...(process.env.SINAN_CHROME_PATH ? {executablePath:process.env.SINAN_CHROME_PATH} : {})})
const receipt = []
try {
  for (const width of [1440,390]) {
    const context = await browser.newContext({viewport:{width,height:1000}}), page = await context.newPage(), errors = [], external = [], cases = []
    page.on('pageerror', error => errors.push(error.message))
    await context.route('**/*',route => {
      if (new URL(route.request().url()).origin === origin) return route.continue()
      external.push(route.request().url()); return route.abort()
    })
    async function load(fixture) {
      state = {view:fixture,next:fixture,postStatus:201}
      // A response from the document replaced by reload can lose its body; wait for the fixture itself.
      let observed
      const answer = page.waitForResponse(async response => {
        if (new URL(response.url()).pathname !== '/api/servers/1/ip-quality' || response.request().method() !== 'GET') return false
        try { observed = await response.json() } catch { return false }
        return isDeepStrictEqual(observed, fixture)
      })
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#/servers/1/ip-info`); await page.reload()
      await answer
      assert.deepEqual(observed, fixture)
      await page.getByRole('heading',{name:'服务器 IP 信息',exact:true}).waitFor()
      await page.getByRole('button',{name:'节点正式 IP 查询',exact:true}).waitFor()
    }
    async function chapter(label) {
      const element = page.locator('details.quality-database').filter({has:page.locator('summary').getByText(label,{exact:true})})
      await element.locator('summary').click(); return element
    }
    async function field(chapter,label) { return chapter.locator('dl > div').filter({has:page.locator('dt').getByText(label,{exact:true})}).locator('dd').innerText() }
    await load(view())
    assert(await page.getByRole('button',{name:'节点正式 IP 查询',exact:true}).isEnabled())
    for (const [, , , label, source] of descriptors) {
      const element = await chapter(label)
      assert.equal(await field(element,'代理'),'否')
      const text = await element.innerText()
      assert(text.includes('执行位置：Agent 节点'))
      assert(text.includes(`本次接口观察出口：${ip}`))
      assert(text.includes(source))
      assert(text.includes('最近成功结果'))
      if (source.includes('db-ip')) assert.equal(await field(element,'纬度'),'0')
    }
    assert((await page.locator('.quality-body').innerText()).includes('流媒体解锁：未知'))
    cases.push('typed-false-zero-node-source-and-streaming-unknown')
    const count = posts.length
    await page.getByRole('button',{name:'节点正式 IP 查询',exact:true}).click()
    await page.getByText(`节点任务已保存：${id}。等待 Agent 回报；页面自动更新，历史结果继续保留。`,{exact:true}).waitFor()
    assert.equal(posts.length,count+1); assert.deepEqual(posts.at(-1),{ip_version:'both'})
    cases.push('dedicated-create-with-no-credential-or-target-in-request')
    for (const problem of [['http_403','节点正式接口拒绝访问（HTTP 403），信息未知',403],
      ['http_429','节点正式接口限制请求频率（HTTP 429），信息未知',429],['timeout','节点正式接口查询超时，信息未知',null]]) {
      for (const history of [false,true]) {
        await load(view(problem,history))
        for (const [, , , label, source] of descriptors) {
          const element = await chapter(label), text = await element.innerText()
          assert(text.includes(problem[1]))
          if (history) {
            assert(text.includes('历史结果')); assert.equal(await field(element,'代理'),'否')
            if (source.includes('db-ip')) assert.equal(await field(element,'纬度'),'0')
          } else { assert.equal(await element.locator('dl').count(),0); assert(text.includes('没有已保存的成功结果，信息未知。')) }
        }
        cases.push(`${problem[0]}-${history ? 'history-preserved' : 'fresh-unknown'}`)
      }
    }
    await load(view(['not_attempted','节点尚未执行该来源的正式查询，信息未知'],true,true,false))
    const historical = await chapter('DB-IP 正式节点查询')
    assert((await historical.innerText()).includes('入口当前不可用'))
    assert.equal(await field(historical,'纬度'),'0'); assert.equal(await field(historical,'代理'),'否')
    cases.push('removed-credential-keeps-history')
    await load(view(null,false,false))
    assert(await page.getByRole('button',{name:'节点正式 IP 查询',exact:true}).isDisabled())
    assert(await page.getByText('TEST_ONLY 正式节点查询 r21 制品尚未上传',{exact:true}).isVisible())
    cases.push('missing-artifact-readiness-gate')
    await load(view()); state.postStatus = 409
    await page.getByRole('button',{name:'节点正式 IP 查询',exact:true}).click()
    await page.getByText('TEST_ONLY 设备已有诊断任务，请等待或取消',{exact:true}).waitFor()
    assert.equal(await field(await chapter('DB-IP 正式节点查询'),'纬度'),'0')
    cases.push('duplicate-job-error-keeps-visible-current-success')
    assert.deepEqual(errors,[]); assert.deepEqual(external,[])
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    receipt.push({width,cases,tests:cases.length,pageErrors:errors,externalRequests:external})
    await context.close()
  }
  assert.deepEqual(unexpected,[])
  console.log(JSON.stringify({suite:'node-ip-provider',receipt,posts,unexpected},null,2))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
