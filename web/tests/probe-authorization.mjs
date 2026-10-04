import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const http = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': ({ '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' })[extname(file)] ?? 'application/octet-stream' }).end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${http.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []
const permission = { kind: 'owned', source: 'TEST_ONLY 自有清单', scope: 'TEST_ONLY 管理记录', enabled: true, expires_at: null, identity: { kind: 'tcp', target: 'probe.example.com', port: 443, address_family: 'any' } }

async function fillAuthorization(scope) {
  await scope.getByLabel('目标地区').fill('测试地区')
  await scope.getByLabel('目标授权依据').selectOption('owned')
  await scope.getByLabel('授权来源', { exact: false }).fill('TEST_ONLY 自有清单')
  await scope.getByLabel('授权适用范围', { exact: false }).fill('TEST_ONLY 管理记录')
  await scope.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
}

try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1100 } })
    const page = await context.newPage(), errors = [], writes = [], unexpected = []
    page.on('pageerror', error => errors.push(error.message))
    await page.clock.install()
    const servers = [{ id: 1, name: '测试离线服务器', online: false, asset_settings: { region: 'TEST', group_name: '' } }]
    const legacy = { id: 'legacy-task', spec: { id: 'legacy-task', name: '旧未登记目标', kind: 'tcp', target: '127.0.0.1', port: 443, interval_secs: 30, carrier: '', enabled: true }, default_enabled: false, server_ids: [1], revision: 1 }
    let tasks = [legacy], taskMode = 'ready', serverMode = 'ready', releasePending, targetPending = null
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
      const respond = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/probes/overview') return respond([])
      if (path === '/api/dashboard/access') return respond({ authenticated: true, public_dashboard: false })
      if (method !== 'GET') writes.push({ method, path, body: request.postDataJSON() })
      if (method === 'GET' && ['/api/servers', '/api/latency-tasks'].includes(path)) {
        const mode = path === '/api/servers' ? serverMode : taskMode
        if (mode === 'failure') return respond({ error: 'TEST_ONLY 最新读取失败' }, 503)
        if (mode === 'pending') { targetPending = path; await new Promise(resolve => { releasePending = resolve }) }
        return respond(path === '/api/servers' ? servers : tasks)
      }
      if (path === '/api/latency-tasks' && method === 'POST') {
        const body = request.postDataJSON()
        tasks.push({ ...body, id: 'new-task', revision: 1 })
        return respond(tasks.at(-1), 201)
      }
      if (path.startsWith('/api/latency-tasks/') && method === 'PATCH') {
        const index = tasks.findIndex(task => task.id === path.split('/').at(-1)), body = request.postDataJSON()
        if (index < 0 || body.revision !== tasks[index].revision) return respond({ error: 'TEST_ONLY 版本冲突' }, 409)
        tasks[index] = { ...body, id: tasks[index].id, revision: tasks[index].revision + 1 }
        return respond(tasks[index])
      }
      if (path.startsWith('/api/latency-tasks/') && method === 'DELETE') {
        const task = tasks.find(task => task.id === path.split('/').at(-1))
        if (!task || request.postDataJSON().revision !== task.revision) return respond({ error: 'TEST_ONLY 版本冲突' }, 409)
        tasks = tasks.filter(item => item.id !== task.id)
        return route.fulfill({ status: 204 })
      }
      unexpected.push(`${method} ${path}`); return respond({ error: 'Unexpected request' }, 500)
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/latency`)
    await page.getByText('未取得执行授权', { exact: true }).waitFor()
    await page.getByRole('button', { name: '添加任务', exact: true }).click()
    let dialog = page.getByRole('dialog')
    await dialog.getByLabel('任务名称').fill('保留的目标草稿')
    await dialog.getByLabel('目标地址', { exact: false }).fill('probe.example.com')
    await dialog.getByRole('checkbox', { name: /测试离线服务器/ }).check()
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await dialog.getByRole('alert').filter({ hasText: '授权' }).waitFor()
    assert.equal(writes.length, 0, 'Missing authorization cannot reach the POST callback')
    await fillAuthorization(dialog)
    for (const dependency of ['tasks', 'servers']) {
      if (dependency === 'tasks') taskMode = 'failure'; else serverMode = 'failure'
      await page.clock.runFor(5001)
      await dialog.getByRole('alert').filter({ hasText: '读取失败' }).waitFor()
      assert.equal(await dialog.getByRole('button', { name: '保存任务', exact: true }).isDisabled(), true)
      await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
      assert.equal(writes.length, 0, 'Direct submit during a failed GET must send zero writes')
      assert.equal(await dialog.getByLabel('任务名称').inputValue(), '保留的目标草稿')
      if (dependency === 'tasks') taskMode = 'ready'; else serverMode = 'ready'
      await page.clock.runFor(5001)
      await dialog.getByRole('button', { name: '保存任务', exact: true }).waitFor()
      if (dependency === 'tasks') taskMode = 'pending'; else serverMode = 'pending'
      targetPending = null
      await page.clock.runFor(5001)
      await dialog.getByRole('alert').filter({ hasText: '正在刷新' }).waitFor()
      assert.equal(targetPending, dependency === 'tasks' ? '/api/latency-tasks' : '/api/servers')
      await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
      assert.equal(writes.length, 0, 'Direct submit during a pending GET must send zero writes')
      if (dependency === 'tasks') taskMode = 'ready'; else serverMode = 'ready'
      releasePending()
      await dialog.getByRole('button', { name: '保存任务', exact: true }).waitFor()
      await page.waitForFunction(() => !document.querySelector('[role="dialog"] button[type="submit"]')?.disabled)
    }
    servers.splice(0, 1)
    await page.clock.runFor(5001)
    await dialog.getByRole('alert').filter({ hasText: '已不存在' }).waitFor()
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    assert.equal(writes.length, 0, 'A removed selected server is rejected after a successful refresh')
    assert.equal(await dialog.getByLabel('任务名称').inputValue(), '保留的目标草稿')
    const missingServer = dialog.getByRole('checkbox', { name: '服务器 #1（已不存在，原选择保留）', exact: false })
    assert.equal(await missingServer.isChecked(), true)
    // Cancelling this missing choice removes its controlled checkbox from the DOM.
    await missingServer.click()
    await missingServer.waitFor({ state: 'hidden' })
    assert.equal(await missingServer.count(), 0)
    assert.equal(writes.length, 0, 'Explicitly removing a missing server edits only the retained local draft')
    await dialog.getByRole('button', { name: '保存任务', exact: true }).click()
    await dialog.waitFor({ state: 'detached' })
    assert.equal(writes.length, 1)
    assert.deepEqual(writes[0].body.spec.monitor.authorization, permission)
    assert.equal(Object.keys(writes[0].body.spec).length, 9)
    assert.deepEqual(writes[0].body.server_ids, [])
    await page.getByRole('row').filter({ hasText: '保留的目标草稿' }).getByRole('button', { name: '编辑', exact: true }).click()
    dialog = page.getByRole('dialog')
    await dialog.getByLabel('任务名称').fill('版本变化后仍保留')
    tasks[1] = { ...tasks[1], revision: 2 }
    await page.clock.runFor(5001)
    await dialog.getByRole('alert').filter({ hasText: '延迟任务目标或版本已变化' }).waitFor()
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    assert.equal(writes.length, 1, 'An updated task revision blocks a preserved old draft')
    assert.equal(await dialog.getByLabel('任务名称').inputValue(), '版本变化后仍保留')
    await page.keyboard.press('Escape')
    await page.getByRole('row').filter({ hasText: '保留的目标草稿' }).getByRole('button', { name: '删除', exact: true }).click()
    dialog = page.getByRole('dialog')
    tasks[1] = { ...tasks[1], revision: 3 }
    const revisionReadback = page.waitForResponse(async response => new URL(response.url()).pathname === '/api/latency-tasks'
      && response.request().method() === 'GET' && response.status() === 200
      && (await response.json()).some(task => task.id === 'new-task' && task.revision === 3))
    await page.clock.runFor(5001)
    await revisionReadback
    await dialog.getByRole('alert').filter({ hasText: '延迟任务目标或版本已变化' }).waitFor()
    const remove = dialog.getByRole('button', { name: '确认删除', exact: true })
    assert.equal(await remove.isDisabled(), true)
    await remove.evaluate(button => { const disabled = button.disabled; try { button.disabled = false; button.click() } finally { button.disabled = disabled } })
    await dialog.getByRole('alert').filter({ hasText: '延迟任务目标或版本已变化' }).waitFor()
    assert.equal(writes.length, 1, 'A stale delete confirmation sends no DELETE')
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false)
    assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
    results.push({ width, legacy: 'pending authorization', save: 'authorized only', reads: 'failed and pending zero writes', refreshedIdentity: 'rechecked', staleDelete: 'zero writes' })
    await context.close()
  }
  console.log(JSON.stringify(results))
} finally { await browser.close(); http.close() }
