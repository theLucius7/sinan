import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { resolve, extname, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const host = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) return response.writeHead(400).end()
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html':'text/html', '.js':'text/javascript', '.css':'text/css' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => host.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${host.address().port}`
const browser = await chromium.launch({ headless:true, ...(process.env.SINAN_CHROME_PATH ? { executablePath:process.env.SINAN_CHROME_PATH } : {}) })
try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport:{ width, height:950 } }), errors=[], writes=[]
    page.on('pageerror', error => errors.push(error.message))
    let retention=30, persist=60, fail=true
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname, method=route.request().method()
      const reply = (json, status=200) => route.fulfill({json,status})
      if (path === '/api/dashboard/access') return reply({authenticated:true,public_dashboard:false})
      if (path === '/api/exchange-rates') return reply({base:'CNY',rates:{CNY:1},rate_dates:{},rate_date:null,source:null,source_url:null,fetched_at:null,attempted_at:null,next_refresh_at:0,stale:true,status:'unavailable',error_code:null})
      if (path === '/api/settings') return reply({public_dashboard:false,notification_enabled:true,offline_alerts:true,offline_minutes:5,telegram_enabled:false,telegram_chat_id:'',telegram_token_configured:false})
      if (path === '/api/telemetry/policy') {
        if (method === 'PATCH') {
          const body=route.request().postDataJSON(); writes.push({path,body})
          if (fail) return reply({error:'测试：策略保存失败'},503)
          retention=body.history_retention_days
        }
        return reply({history_retention_days:retention})
      }
      if (path === '/api/notifications/webhook') return reply({enabled:false,preset:'custom',url_configured:false,headers_configured:false,body_configured:false})
      if (path === '/api/notifications/channels' || path === '/api/alert-rules' || path === '/api/servers') return reply([])
      if (path === '/api/servers/1') return reply({id:1,name:'历史设置夹具',online:true,device_public_key:'TEST_ONLY',static_info:{},latest_metrics:{},manifest_rev:0,capabilities:[]})
      if (path === '/api/plugins/sing-box/servers/1') return reply({id:1,name:'历史设置夹具',enabled:false,online:true,agent_supported:true,read_only:false,source:null})
      if (path === '/api/servers/1/agent-settings') {
        if (method !== 'GET') throw new Error('Historical settings must not overwrite legacy AgentSettings')
        return reply({sample_interval_secs:1,upload_interval_secs:3,discover_public_ips:false,auto_update:false})
      }
      if (path === '/api/servers/1/telemetry-settings') {
        if (method === 'PATCH') { const body=route.request().postDataJSON(); writes.push({path,body}); persist=body.persist_interval_secs }
        return reply({persist_interval_secs:persist})
      }
      if (['probes','probe-results','commands'].some(name => path === `/api/servers/1/${name}`)) return reply([])
      errors.push(`${method} ${path}`); return reply({error:'Unexpected fixture API'},404)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/system/settings`)
    const policy = page.locator('section.panel').filter({has:page.getByRole('heading',{name:'监控历史保存',exact:true})})
    const days=policy.getByLabel('监控历史保留天数',{exact:false})
    await days.waitFor()
    assert.equal(await days.inputValue(),'30')
    await days.fill('7')
    const save=policy.getByRole('button',{name:'保存历史策略',exact:true})
    assert.equal(await save.isDisabled(),true)
    await policy.getByRole('checkbox').check()
    await save.click()
    await policy.getByRole('alert').filter({hasText:'策略保存失败'}).waitFor()
    assert.equal(await days.inputValue(),'7')
    assert.equal(retention,30)
    fail=false
    await save.click()
    await policy.getByRole('status').waitFor()
    assert.equal(retention,7)
    await days.fill('90')
    assert.equal(await policy.getByRole('checkbox').count(),0)
    await save.click()
    await policy.getByRole('status').waitFor()
    assert.equal(retention,90)
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/1`)
    const settings=page.locator('section.panel').filter({has:page.getByRole('heading',{name:'数据上报与保存',exact:true})})
    const interval=settings.getByLabel('历史批量写入间隔（秒）',{exact:false})
    await interval.waitFor()
    assert.equal(await interval.inputValue(),'60')
    await interval.fill('14')
    const before=writes.length
    await settings.getByRole('button',{name:'保存历史写入间隔',exact:true}).click()
    assert.equal(writes.length,before)
    await interval.fill('120')
    await settings.getByRole('button',{name:'保存历史写入间隔',exact:true}).click()
    await settings.getByRole('status').waitFor()
    assert.deepEqual(writes.at(-1),{path:'/api/servers/1/telemetry-settings',body:{persist_interval_secs:120}})
    assert.equal(await page.getByLabel('实时上报间隔（秒）',{exact:true}).inputValue(),'3')
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true)
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: retention reduction confirmation, failure preserves edits, period increase, independent durable reporting interval and desktop/mobile layouts')
} finally { await browser.close(); await new Promise(resolve => host.close(resolve)) }
