import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Shipped dist with controlled API responses; PostgreSQL verifies migration/data.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const httpServer = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => httpServer.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1280, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    const errors = [], writes = [], now = Math.floor(Date.now() / 1000)
    page.on('pageerror', error => errors.push(error.message))
    const metadata = { id:1,name:'运维夹具',enabled:true,source:'agent_capability',read_only:true,online:true,agent_supported:true }
    const server = { id:1,name:metadata.name,online:true,device_public_key:'TEST_ONLY',static_info:{},latest_metrics:{},last_seen:now,manifest_rev:2,capabilities:[] }
    const status = { module:'singbox',target_rev:2,applied_rev:2,last_result_rev:2,healthy:true,last_error:null,updated_at:now }
    const view = { supported:true,online:true,retiring:false,operations:[] }
    const snapshot = { observed_at:now,applied_revision:2,service:'active',healthy:true,logs_available:true,logs_service_events:false,logs_truncated:true,logs:[{timestamp:now,level:'error',kind:'connection_failed'}] }
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname, method = route.request().method()
      let value
      if (path === '/api/dashboard/access') value = { authenticated:true,public_dashboard:false }
      else if (path === '/api/me') value = { authenticated:true }
      else if (path === '/api/servers/1') value = server
      else if (path === '/api/plugins/sing-box/servers/1') value = metadata
      else if (path.endsWith('/runtime-operations')) {
        if (method === 'POST') {
          const body = route.request().postDataJSON(); writes.push(body)
          if (body.operation === 'retry_deployment') return route.fulfill({status:409,json:{error:'期望版本已改变，请刷新后重试'}})
          const spec = { id:String(writes.length),operation:body.operation,requested_at:now,expires_at:now+600 }
          view.operations.unshift({ spec,dispatched_at:now,result:body.operation==='inspect'?{error:null,snapshot,finished_at:now}:null })
          value=spec
        } else value=view
      }
      else if (path.endsWith('/deployments')) value = {status,history:[]}
      else if (path.endsWith('/nodes') || path.endsWith('/chains')) value=[]
      else if (path.endsWith('/agent-settings')) value = {sample_interval_secs:10,upload_interval_secs:30,auto_update:false,discover_public_ips:false}
      else if (path === '/api/servers/1/telemetry-settings' && method === 'GET') value = {persist_interval_secs:60}
      else if (['/probes','/probe-results','/commands','/metrics'].some(suffix=>path.endsWith(suffix))) value=[]
      else { errors.push(`Unexpected ${method}: ${path}`); return route.fulfill({status:404,json:{}}) }
      return route.fulfill({json:value})
    })
    const url=`http://127.0.0.1:${httpServer.address().port}/#/servers/1`
    await page.goto(url)
    const operations=page.locator('.runtime-operations')
    await operations.getByRole('button',{name:'读取状态与日志',exact:true}).click()
    await operations.getByRole('log').getByText(/连接错误/).waitFor()
    assert.deepEqual(writes[0],{operation:'inspect',expected_revision:null})
    await operations.getByRole('button',{name:'重启运行时',exact:true}).click()
    await operations.getByText(/重启会短暂中断现有连接/).waitFor()
    assert.equal(writes.length,1)
    await operations.getByRole('button',{name:'确认重启',exact:true}).click()
    await operations.getByRole('status').getByText(/等待执行结果/).waitFor()
    assert.deepEqual(writes[1],{operation:'restart',expected_revision:2})
    assert.equal(await operations.getByRole('button',{name:'重启运行时',exact:true}).isDisabled(),true)
    view.operations[0].result={error:'operation_failed',snapshot,finished_at:now}
    status.last_error='夹具部署失败'
    await page.reload()
    await operations.getByText('操作失败，已按部署流程处理恢复；请检查状态及本机日志',{exact:true}).waitFor()
    await operations.getByRole('button',{name:'重试失败部署',exact:true}).click()
    await operations.getByRole('button',{name:'确认重试',exact:true}).click()
    await operations.getByRole('alert').getByText('期望版本已改变，请刷新后重试',{exact:true}).waitFor()
    assert.deepEqual(writes[2],{operation:'retry_deployment',expected_revision:2})
    view.supported=false
    await page.reload()
    await operations.getByText('此 Agent 尚不支持运行时运维，请先升级 Agent。',{exact:true}).waitFor()
    assert.equal(await operations.getByRole('button',{name:'读取状态与日志',exact:true}).isDisabled(),true)
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true)
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: runtime operations desktop/mobile, inspection log, restart confirmation, in-flight exclusion, stale retry and legacy Agent gate')
} finally { await browser.close(); await new Promise(resolve => httpServer.close(resolve)) }
