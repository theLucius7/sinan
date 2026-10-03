import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Exercise the shipped bundle with controlled API responses; backend behavior is
// verified separately by the PostgreSQL/WebSocket/HTTP integration tests.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1280,390]) {
    const page = await browser.newPage({ viewport:{width,height:950} })
    page.setDefaultTimeout(10000)
    const errors=[], writes=[]
    page.on('pageerror',error=>errors.push(error.message))
    const now=Math.floor(Date.now()/1000)
    const make=(id,state,extra={})=>({spec:{id:`00000000-0000-0000-0000-00000000000${id}`,command:`echo fixture-${id}`,timeout_secs:30,expires_at:now+60},requested_at:now-15,state,lifecycle_version:1,claimed_at:state==='queued'?null:now-12,started_at:state==='running'?now-10:null,cancel_requested_at:null,finished_at:null,cancel_supported:true,result:null,...extra})
    const commands=[make(1,'queued'),make(2,'running'),make(3,'claimed',{lifecycle_version:0,cancel_supported:false}),make(4,'running',{cancel_supported:false}),make(5,'succeeded',{started_at:now-10,finished_at:now-5,result:{status:'succeeded',stdout:'已保留的标准输出',stderr:'已保留的错误输出',finished_at:now-5,timed_out:false,truncated:true}})]
    let enabled=true
    await page.route('**/api/**',async route=>{
      const path=new URL(route.request().url()).pathname,method=route.request().method()
      let value
      if(path==='/api/dashboard/access')value={authenticated:true,public_dashboard:false}
      else if(path==='/api/servers/1')value={id:1,name:'命令生命周期夹具',online:false,device_public_key:'TEST_ONLY',static_info:{},latest_metrics:{},last_seen:now,manifest_rev:0,capabilities:enabled?['command:execute','command:lifecycle:v1','command:cancel:v1']:[]}
      else if(path==='/api/plugins/sing-box/servers/1')value={id:1,name:'命令生命周期夹具',enabled:false,source:null,read_only:false,online:false,agent_supported:true}
      else if(path==='/api/servers/1/agent-settings')value={sample_interval_secs:1,upload_interval_secs:5,discover_public_ips:false,auto_update:false}
      else if (path === '/api/servers/1/telemetry-settings') value = { persist_interval_secs: 60 }
      else if(path==='/api/servers/1/commands')value=commands
      else if(path.startsWith('/api/servers/1/commands/')&&path.endsWith('/cancel')){
        assert.equal(method,'POST');writes.push(path)
        const item=commands.find(item=>path.includes(item.spec.id));assert.ok(item)
        item.state=item.state==='queued'?'cancelled':'cancel_requested';item.cancel_requested_at=now;if(item.state==='cancelled')item.finished_at=now
        value={...item,id:item.spec.id}
      }else if(['/api/servers/1/probes','/api/servers/1/probe-results'].includes(path))value=[]
      else {errors.push(`${method} ${path}`);return route.fulfill({status:404,json:{error:'Unexpected API'}})}
      await route.fulfill({json:value})
    })
    await page.goto(`http://127.0.0.1:${server.address().port}/#/servers/1`)
    const panel=page.locator('section.panel').filter({has:page.getByRole('heading',{name:'远程命令',exact:true})})
    const record=id=>panel.locator('details').filter({has:page.locator('pre',{hasText:`echo fixture-${id}`})})
    for(const id of [1,2,3,4,5])await record(id).locator('summary').click()
    await record(1).getByRole('button',{name:'取消排队',exact:true}).click()
    await record(1).locator('summary').filter({hasText:'已取消'}).waitFor()
    await record(2).getByRole('button',{name:'取消执行',exact:true}).click()
    await record(2).locator('summary').filter({hasText:'取消中，等待设备确认'}).waitFor()
    await record(2).getByRole('status').filter({hasText:'此时不能视为已停止'}).waitFor()
    assert.equal(await record(2).locator('summary').filter({hasText:'已取消'}).count(),0)
    assert.equal(await record(3).getByRole('button',{name:'取消执行',exact:true}).count(),0)
    assert.equal(await record(4).getByRole('button',{name:'取消执行',exact:true}).count(),0)
    await record(3).getByText(/旧设备未上报，无法确认/).waitFor()
    await record(5).getByText('已保留的标准输出',{exact:true}).waitFor()
    await record(5).getByText('已保留的错误输出',{exact:true}).waitFor()
    await record(5).getByText('输出超过上限，已截断。',{exact:true}).waitFor()
    await record(5).getByText(/执行时间：5 秒/).waitFor()
    const running=commands[1];running.state='cancelled';running.finished_at=now;running.result={status:'cancelled',stdout:'取消前输出',stderr:'',finished_at:now,timed_out:false,truncated:false}
    await record(2).locator('summary').filter({hasText:'已取消'}).waitFor()
    await record(2).getByText('取消前输出',{exact:true}).waitFor()
    assert.equal(writes.length,2)
    enabled=false
    await page.reload()
    await panel.getByText(/远程命令默认关闭/).waitFor()
    assert.equal(await panel.getByRole('button',{name:'提交命令',exact:true}).isDisabled(),true)
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true)
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: command lifecycle desktop/mobile, queued cancellation, confirmation pending, legacy/platform capability gates, durations, preserved output and local opt-in')
} finally { await browser.close(); await new Promise(resolve=>server.close(resolve)) }
