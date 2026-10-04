import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

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
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const results = []

try {
  for (const width of [1440, 390, 320]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 } })
    const page = await context.newPage(), errors = [], unexpected = [], writes = []
    page.on('pageerror', error => errors.push(error.message))
    let tasks = [], rules = [], taskFailure = true, testFailure = true
    const servers = [
      { id: 1, name: '东京服务器', online: true, asset_settings: { region: 'JP', group_name: '亚洲' } },
      { id: 2, name: '香港服务器', online: false, asset_settings: { region: 'HK', group_name: '亚洲' } },
    ]
    const settings = { public_dashboard: false, notification_enabled: true, offline_alerts: true, offline_minutes: 5, expiry_alert_days: 0, traffic_alert_percentage: 0, telegram_enabled: false, telegram_chat_id: '-100000', telegram_token_configured: true, telegram_thread_id: null, telegram_template: '{{title}}\n{{server}}\n{{message}}\n{{time}}\n{{event}}' }
    const second = Math.floor(Date.now() / 1000)
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/dashboard/access') return respond({ authenticated: true, public_dashboard: false })
      if (path === '/api/servers') return respond(servers)
      if (path === '/api/probes/overview') return respond([])
      if (method !== 'GET') writes.push({ path, method, body: request.postDataJSON() })
      if (path === '/api/latency-tasks') {
        if (method === 'POST') {
          if (taskFailure) return respond({ error: '测试：节点拨测已满，未保存任何修改' }, 409)
          const body = request.postDataJSON()
          tasks.push({ ...body, id: 'task-1', revision: 1 })
          return respond(tasks[0], 201)
        }
        return respond(tasks)
      }
      if (path === '/api/latency-tasks/task-1') {
        if (method === 'DELETE') { tasks = []; return route.fulfill({ status: 204 }) }
        tasks[0] = { ...request.postDataJSON(), id: 'task-1', revision: tasks[0].revision + 1 }
        return respond(tasks[0])
      }
      if (path === '/api/exchange-rates') return respond({base:'CNY',rates:{CNY:1},rate_dates:{},rate_date:null,source:null,source_url:null,fetched_at:null,attempted_at:null,next_refresh_at:0,stale:true,status:'unavailable',error_code:null})
      if (path === '/api/settings') {
        if (method === 'PATCH') {
          const body = request.postDataJSON()
          if (body.telegram_template.includes('{{unknown}}')) return respond({ error: '测试：模板变量无效' }, 400)
          Object.assign(settings, body)
          if (settings.telegram_thread_id === 0) settings.telegram_thread_id = null
          delete settings.telegram_token
        }
        return respond(settings)
      }
      if (path === '/api/notifications/webhook') return respond({enabled:false,preset:'custom',url_configured:false,headers_configured:false,body_configured:false})
      if (path === '/api/notifications/channels') return respond([])
      if (path === '/api/telemetry/policy') return respond({history_retention_days:30})
      if (path === '/api/notifications/telegram/test') return respond(testFailure ? { error: '测试：Telegram 暂时不可用' } : { sent: true }, testFailure ? 400 : 200)
      if (path === '/api/alert-rules') {
        if (method === 'POST') { rules.push({ ...request.postDataJSON(), id: 'rule-1', revision: 1 }); return respond(rules[0], 201) }
        return respond(rules)
      }
      if (path === '/api/alert-rules/rule-1') {
        if (method === 'DELETE') { rules = []; return route.fulfill({ status: 204 }) }
        rules[0] = { ...request.postDataJSON(), id: 'rule-1', revision: rules[0].revision + 1 }
        return respond(rules[0])
      }
      if (path === '/api/notifications') return respond(['offline', 'resource', 'expiry', 'traffic'].map((category, index) => ({ id: index + 1, category, message: `测试事件 ${category}`, server_id: 1, server_name: '东京服务器', last_seen: second - 600, opened_at: second - 300, resolved_at: index === 1 ? second : null, resolution: index === 1 ? 'recovered' : null, deliveries: [{ kind: index === 0 ? 'offline' : 'alert', status: 'pending', attempts: 1, last_error: '测试：等待重试' }] })))
      unexpected.push(`${method} ${path}`); return respond({ error: 'Unexpected request' }, 500)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/latency`)
    await page.getByRole('heading', { name: '延迟检测', exact: true }).waitFor()
    await page.getByRole('button', { name: '添加任务', exact: true }).click()
    let dialog = page.getByRole('dialog')
    await dialog.getByLabel('任务名称').fill('亚洲回显')
    await dialog.getByLabel('检测方式').selectOption('icmp')
    assert.equal(await dialog.getByLabel('目标端口').count(), 0)
    await dialog.getByLabel('目标地址', { exact: false }).fill('probe.example.com')
    await dialog.getByLabel('检测间隔（秒）').fill('45')
    await dialog.getByLabel('线路备注').fill('telecom')
    await dialog.getByLabel('目标地区', { exact: false }).fill('华东')
    await dialog.getByLabel('网络版本').selectOption('ipv4')
    await dialog.getByLabel('目标授权依据').selectOption('owned')
    await dialog.getByLabel('授权来源').fill('TEST_ONLY-owned-asset-1')
    await dialog.getByLabel('授权适用范围').fill('ICMP，每45秒，自有回环夹具')
    await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    await dialog.getByLabel('目标地址', { exact: false }).fill('other.example.com')
    assert.equal(await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false)
    await dialog.getByLabel('目标地址', { exact: false }).fill('probe.example.com')
    assert.equal(await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false)
    await dialog.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    await dialog.getByLabel('搜索服务器').fill('东京')
    await dialog.getByRole('button', { name: '全选当前结果' }).click()
    await dialog.getByLabel('搜索服务器').fill('香港')
    await dialog.getByRole('button', { name: '全选当前结果' }).click()
    await dialog.getByRole('switch', { name: /^默认分配给新服务器/ }).check()
    await dialog.getByRole('button', { name: '保存任务' }).click()
    await dialog.getByRole('alert').filter({ hasText: '未保存任何修改' }).waitFor()
    assert.equal(await dialog.getByLabel('任务名称').inputValue(), '亚洲回显')
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false)
    if (screenshots) { await dialog.evaluate(element => { element.scrollTop = 0 }); await page.screenshot({ path: resolve(screenshots, `monitoring-latency-${width}.png`), animations: 'disabled' }) }
    taskFailure = false
    await dialog.getByRole('button', { name: '保存任务' }).click()
    await dialog.waitFor({ state: 'detached' })
    const taskWrite = writes.filter(write => write.path === '/api/latency-tasks').at(-1).body
    assert.deepEqual(taskWrite.server_ids, [1, 2]); assert.equal(taskWrite.spec.port, null); assert.equal(taskWrite.spec.interval_secs, 45); assert.equal(taskWrite.default_enabled, true)
    assert.equal(taskWrite.spec.monitor.authorization.kind, 'owned'); assert.equal(taskWrite.spec.monitor.region, '华东'); assert.equal(taskWrite.spec.monitor.authorization.expires_at, null)
    assert.equal(Object.hasOwn(taskWrite.spec, 'authorization'), false, 'Spec retains the original eight fields')
    await page.getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    assert.equal(await dialog.getByLabel('目标地址', { exact: false }).isDisabled(), true)
    assert.equal(await dialog.getByLabel('检测方式').isDisabled(), true)
    assert.equal(await dialog.getByLabel('线路备注').isDisabled(), true)
    await page.keyboard.press('Escape')
    await page.getByRole('button', { name: '暂停', exact: true }).click()
    await page.getByRole('button', { name: '启用', exact: true }).waitFor()
    assert.equal(tasks[0].spec.enabled, false)
    await page.getByRole('button', { name: '删除', exact: true }).click()
    await page.getByRole('dialog').getByRole('button', { name: '确认删除' }).click()
    await page.getByRole('heading', { name: '尚未配置统一延迟任务' }).waitFor()
    await page.getByRole('link', { name: '看板与通知', exact: true }).click()
    await page.getByRole('heading', { name: '看板与通知', exact: true }).waitFor()
    assert.equal(await page.getByRole('textbox', { name: /^机器人令牌/ }).inputValue(), '')
    await page.getByLabel('到期提前提醒（天）', { exact: false }).fill('7')
    await page.getByLabel('流量提醒起始阈值（%）', { exact: false }).fill('80')
    await page.getByLabel('话题 ID（可选）', { exact: false }).fill('42')
    await page.getByRole('switch', { name: /^Telegram 通知/ }).check()
    assert.equal(await page.getByRole('button', { name: '发送测试通知' }).isDisabled(), true)
    await page.getByLabel('消息模板', { exact: false }).fill('{{unknown}}')
    await page.getByRole('button', { name: '保存设置' }).click()
    await page.getByRole('alert').filter({ hasText: '模板变量无效' }).waitFor()
    await page.getByLabel('消息模板', { exact: false }).fill('{{title}}\n{{server}}\n{{message}}\n{{time}}\n{{event}}')
    await page.getByText('查看模板预览', { exact: true }).click()
    await page.locator('form.monitoring-settings .monitoring-preview').filter({ hasText: '示例服务器' }).waitFor()
    await page.getByRole('button', { name: '保存设置' }).click()
    await page.getByRole('status').filter({ hasText: '设置已保存' }).waitFor()
    const saved = writes.filter(write => write.path === '/api/settings').at(-1).body
    assert.equal(Object.hasOwn(saved, 'telegram_token'), false); assert.equal(saved.telegram_thread_id, 42); assert.equal(saved.expiry_alert_days, 7); assert.equal(saved.traffic_alert_percentage, 80)
    await page.getByRole('button', { name: '发送测试通知' }).click()
    await page.getByRole('alert').filter({ hasText: 'Telegram 暂时不可用' }).waitFor()
    testFailure = false
    await page.getByRole('button', { name: '发送测试通知' }).click()
    await page.getByRole('status').filter({ hasText: 'Telegram 已接受测试消息' }).waitFor()
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `monitoring-settings-${width}.png`), fullPage: true, animations: 'disabled' })
    await page.getByRole('button', { name: '新增规则' }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByLabel('规则名称').fill('内存紧张')
    await dialog.getByLabel('监控指标').selectOption('memory')
    await dialog.getByLabel('阈值（%）').fill('85')
    await dialog.getByLabel('时间窗口（分钟）').fill('3')
    await dialog.getByLabel('判断方式').selectOption('continuous')
    await dialog.getByRole('switch', { name: /^全部服务器/ }).uncheck()
    assert.equal(await dialog.getByRole('button', { name: '保存规则' }).isDisabled(), true)
    await dialog.getByRole('checkbox', { name: /东京服务器/ }).check()
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false)
    if (screenshots) await page.screenshot({ path: resolve(screenshots, `monitoring-rule-${width}.png`), animations: 'disabled' })
    await dialog.getByRole('button', { name: '保存规则' }).click()
    await dialog.waitFor({ state: 'detached' })
    assert.equal(rules[0].spec.metric, 'memory'); assert.equal(rules[0].spec.aggregation, 'continuous'); assert.deepEqual(rules[0].spec.server_ids, [1])
    await page.getByRole('button', { name: '暂停', exact: true }).click()
    await page.getByRole('button', { name: '启用', exact: true }).waitFor()
    assert.equal(rules[0].spec.enabled, false)
    await page.getByRole('button', { name: '删除', exact: true }).click()
    await page.getByRole('dialog').getByRole('button', { name: '确认删除' }).click()
    await page.getByText('尚未配置资源规则。', { exact: false }).waitFor()
    await page.getByRole('link', { name: '告警通知', exact: true }).click()
    await page.getByText(/^测试事件 offline/).waitFor()
    assert.equal(await page.locator('tbody tr').count(), 4)
    await page.getByLabel('事件类型').selectOption('resource')
    assert.equal(await page.locator('tbody tr').count(), 1)
    await page.getByLabel('事件状态').selectOption('active')
    await page.getByRole('heading', { name: '暂无符合条件的告警' }).waitFor()
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
    results.push({ width, assignment: 'passed', notificationConfig: 'passed', rules: 'passed', history: 'passed' })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally { await browser.close(); server.close() }
