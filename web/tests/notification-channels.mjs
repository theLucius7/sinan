import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const browser = await chromium.launch({headless:true,...(process.env.SINAN_CHROME_PATH ? {executablePath:process.env.SINAN_CHROME_PATH} : {})})
if(process.env.SINAN_UI_SCREENSHOT_DIR) await mkdir(process.env.SINAN_UI_SCREENSHOT_DIR,{recursive:true})
try {
  for(const width of [1440,390,320]) {
    const page=await browser.newPage({viewport:{width,height:1000}}), errors=[],writes=[]
    page.on('pageerror',error=>errors.push(error.message))
    const now=Math.floor(Date.now()/1000)
    const empty={enabled:false,preset:'custom',url_configured:false,headers_configured:false,body_configured:false}
    let webhook={...empty}, failure=true, test=null
    await page.route('**/api/**',async route=>{
      const path=new URL(route.request().url()).pathname, method=route.request().method()
      const reply=(json,status=200)=>route.fulfill({json,status})
      if(path==='/api/dashboard/access')return reply({authenticated:true,public_dashboard:false})
      if(path==='/api/exchange-rates'&&method==='GET')return reply({base:'CNY',rates:{CNY:1},rate_dates:{},rate_date:null,source:null,source_url:null,fetched_at:null,attempted_at:null,next_refresh_at:0,stale:true,status:'unavailable',error_code:null})
      if(path==='/api/settings')return reply({public_dashboard:false,notification_enabled:true,offline_alerts:true,offline_minutes:5,telegram_enabled:false,telegram_chat_id:'',telegram_token_configured:false})
      if(path==='/api/telemetry/policy')return reply({history_retention_days:30})
      if(path==='/api/servers'||path==='/api/alert-rules')return reply([])
      if(path==='/api/notifications/webhook') {
        if(method==='PATCH') { const body=route.request().postDataJSON(); writes.push(body); webhook={enabled:body.enabled,preset:body.preset,url_configured:true,headers_configured:!body.clear_headers,body_configured:true};test=null }
        if(method==='DELETE'){webhook={...empty};test=null}
        return reply(webhook)
      }
      if(path==='/api/notifications/webhook/test') {
        test={attempted_at:now,success:!failure,last_error:failure?'Webhook 未接受通知（HTTP 429），请稍后重试':null}
        return reply(failure?{error:test.last_error}:{sent:true},failure?400:200)
      }
      if(path==='/api/notifications/channels')return reply(['telegram','webhook'].map(channel=>({channel,configured:channel==='webhook'&&webhook.url_configured,enabled:channel==='webhook'&&webhook.enabled,notification_enabled:true,counts:{pending:channel==='webhook'?1:0,sent:channel==='telegram'?1:0,failed:0,next_attempt_at:now+123},last_delivery:null,test:channel==='webhook'?test:null})))
      if(path==='/api/notifications')return reply([{id:1,category:'resource',message:'CPU 95%',server_id:1,server_name:'渠道测试服务器',last_seen:now,opened_at:now-60,resolved_at:null,resolution:null,deliveries:[{id:1,channel:'telegram',kind:'alert',status:'sent',attempts:1,last_error:null,delivered_at:now-20},{id:2,channel:'webhook',kind:'alert',status:'pending',attempts:2,last_error:'Webhook HTTP 429',next_attempt_at:now+123}]}])
      errors.push(`${method} ${path}`);return reply({error:'Unexpected API'},404)
    })
    await page.goto(`http://127.0.0.1:${server.address().port}/#/system/settings`)
    const panel=page.locator('section').filter({has:page.getByRole('heading',{name:/^Webhook 通知/})})
    await panel.getByLabel('通知服务预设',{exact:false}).waitFor()
    assert.equal(await panel.getByLabel('通知服务预设',{exact:false}).locator('option').count(),9)
    assert.equal(await panel.getByRole('button',{name:'测试 Webhook',exact:true}).isDisabled(),true)
    await panel.getByLabel('通知服务预设',{exact:false}).selectOption('ntfy')
    assert.equal(await panel.getByLabel('Webhook 地址',{exact:false}).inputValue(),'https://ntfy.sh')
    assert.equal(JSON.parse(await panel.getByLabel('Webhook JSON 模板',{exact:false}).inputValue()).topic,'填写主题')
    await panel.getByText('地址填写 ntfy 服务根地址，主题填在 JSON 的 topic 中；私有主题的认证可放在请求头中。',{exact:true}).waitFor()
    await panel.getByLabel('通知服务预设',{exact:false}).selectOption('gotify')
    await panel.getByLabel('Webhook 地址',{exact:false}).fill('https://example.invalid/TEST_ONLY_URL_SECRET')
    await panel.getByLabel('Webhook 请求头（可选）',{exact:false}).fill('X-Gotify-Key: TEST_ONLY_HEADER_SECRET')
    await panel.getByLabel('Webhook JSON 模板',{exact:false}).fill('{"title":"{{title}}","message":"{{server}}\\n{{message}}","key":"TEST_ONLY_BODY_SECRET"}')
    await panel.getByRole('switch',{name:/^启用 Webhook/}).check()
    await panel.getByText('查看 Webhook 模板预览',{exact:true}).click()
    await panel.locator('pre').filter({hasText:'示例服务器'}).waitFor()
    await panel.getByRole('button',{name:'保存 Webhook',exact:true}).click()
    await panel.getByRole('status').filter({hasText:'Webhook 设置已保存'}).waitFor()
    assert.equal(writes[0].preset,'gotify');assert.ok(writes[0].headers.includes('TEST_ONLY_HEADER_SECRET'))
    for(const label of ['Webhook 地址','Webhook 请求头（可选）','Webhook JSON 模板'])assert.equal(await panel.getByLabel(label,{exact:false}).inputValue(),'')
    assert.equal((await page.locator('body').textContent()).includes('TEST_ONLY'),false)
    await panel.getByRole('button',{name:'测试 Webhook',exact:true}).click()
    await panel.getByRole('alert').filter({hasText:'HTTP 429'}).waitFor()
    await page.locator('.notification-channel-grid').getByText(/最近测试：.*未成功/).waitFor()
    failure=false
    await panel.getByRole('button',{name:'测试 Webhook',exact:true}).click()
    await panel.getByRole('status').filter({hasText:'服务已接受测试消息'}).waitFor()
    await page.locator('.notification-channel-grid').getByText(/最近测试：.*服务已接受/).waitFor()
    await panel.getByLabel('清除已保存的请求头').check()
    assert.equal(await panel.getByRole('button',{name:'测试 Webhook',exact:true}).isDisabled(),true)
    await panel.getByRole('button',{name:'保存 Webhook',exact:true}).click()
    await panel.getByRole('status').filter({hasText:'设置已保存'}).waitFor()
    assert.equal(writes.at(-1).url,'');assert.equal(writes.at(-1).body,'');assert.equal(writes.at(-1).clear_headers,true)
    if(process.env.SINAN_UI_SCREENSHOT_DIR)await page.screenshot({path:resolve(process.env.SINAN_UI_SCREENSHOT_DIR,`notifications-${width}.png`),fullPage:true})
    const overflow=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,elements:[...document.querySelectorAll('body *')].filter(element=>element.getBoundingClientRect().right>innerWidth+1).map(element=>({tag:element.tagName,classes:element.className,right:element.getBoundingClientRect().right,text:element.textContent?.slice(0,45)})).slice(0,15)}))
    assert.equal(overflow.scroll<=width,true,JSON.stringify(overflow))
    await panel.getByRole('button',{name:'删除 Webhook 配置',exact:true}).click()
    await panel.getByRole('button',{name:'确认删除 Webhook',exact:true}).click()
    await panel.getByRole('status').filter({hasText:'配置已删除'}).waitFor()
    assert.equal(await panel.getByRole('button',{name:'测试 Webhook',exact:true}).isDisabled(),true)
    await page.goto(`http://127.0.0.1:${server.address().port}/#/system/notifications`)
    await page.getByText(/Telegram · 告警：已发送/).waitFor()
    await page.getByText(/Webhook · 告警：等待发送或重试/).waitFor()
    await page.getByText(/下次尝试：/).waitFor()
    assert.deepEqual(errors,[])
    await page.close()
  }
  console.log('PASS: notification settings on desktop/mobile, nine presets, write-only secrets, saved-config tests, independent delivery states, validation errors and deletion')
} finally {await browser.close();await new Promise(resolve=>server.close(resolve))}
