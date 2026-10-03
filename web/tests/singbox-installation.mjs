import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Exercise the actual dist with loopback fixtures; no Agent, release, or production access.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(dist, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(dist.endsWith(sep) ? dist : `${dist}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})

let browser
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  const origin = `http://127.0.0.1:${server.address().port}`
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: 1000 }, serviceWorkers: 'block' })
    context.setDefaultTimeout(10000)
    const page = await context.newPage()
    const errors = [], unexpected = [], reads = [], writes = []
    const prefix = '/api/plugins/sing-box/servers'
    const name = '能力支持但尚未启用服务器'
    const otherName = '另一台未启用服务器'
    const missingArtifact = '清单准备失败：目标版本 1：缺少此平台的已验签 sing-box 1.14.2 制品，请先导入可信发布制品'
    let enabled = false, targetRev = 0, preparationError = null
    const device = { downloaded: false, appliedRev: 0, healthy: false }
    const installation = () => {
      const revisions = { target_rev: targetRev, applied_rev: device.appliedRev }
      if (!enabled) return { ...revisions, state: 'not_enabled', reason: '尚未启用插件；设备支持此插件不代表已安装' }
      if (!targetRev) return { ...revisions, state: 'queued', reason: '启用请求已保存，正在生成初始运行配置' }
      if (preparationError) return { ...revisions, state: 'failed', reason: preparationError }
      // Neither enablement nor downloading bytes establishes a device application/health result.
      if (device.appliedRev === targetRev && device.healthy) return { ...revisions, state: 'ready', reason: '设备已确认应用目标版本，运行时健康检查通过' }
      return { ...revisions, state: 'pending', reason: '等待设备下载已签制品、应用配置并确认健康；尚未确认安装完成' }
    }
    const selected = () => ({ id: 1, name, enabled, online: true, agent_supported: true, read_only: false, source: enabled ? 'administrator' : null, installation: installation() })
    const other = { id: 2, name: otherName, enabled: false, online: false, agent_supported: false, read_only: false, source: null, installation: { state: 'not_enabled', reason: '尚未启用插件', target_rev: 0, applied_rev: 0 } }
    page.on('pageerror', error => errors.push(error.message))
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), method = request.method(), pathname = url.pathname
      if (url.origin !== origin) {
        unexpected.push(`External request refused: ${method} ${url.origin}${pathname}`)
        await route.abort('blockedbyclient'); return
      }
      if (!pathname.startsWith('/api/')) { await route.continue(); return }
      let value
      if (method === 'GET') {
        reads.push(pathname)
        if (pathname === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
        else if (pathname === '/api/me') value = { authenticated: true }
        else if (pathname === prefix) value = [selected(), other]
        else if (pathname === `${prefix}/1`) value = selected()
        else if (pathname === `${prefix}/2`) value = other
      } else if (pathname === `${prefix}/1/enable` && method === 'POST') {
        const payload = request.postDataJSON()
        assert.deepEqual(payload, {})
        writes.push({ pathname, method, payload })
        enabled = true
        value = selected()
      }
      if (value === undefined) {
        unexpected.push(`${method} ${pathname}`)
        await route.fulfill({ status: 404, json: { error: '测试拒绝未知接口' } }); return
      }
      await route.fulfill({ json: value })
    })

    await page.goto(`${origin}/#/system/plugins`)
    await page.getByRole('heading', { name: 'sing-box 安装与运行状态', exact: true }).waitFor()
    assert.equal(await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '服务器插件', exact: true }).getAttribute('aria-current'), 'page')
    assert.equal(await page.title(), '服务器插件 · 司南')
    const row = page.locator('tbody tr').filter({ has: page.getByRole('link', { name, exact: true }) })
    await row.getByText('设备支持 sing-box', { exact: true }).waitFor()
    assert.equal(await row.getByText('未启用', { exact: true }).count(), 1)
    assert.equal(await row.getByRole('link', { name: '管理节点', exact: true }).count(), 0)
    assert.equal(await row.getByText('已安装并运行', { exact: true }).count(), 0)
    assert.equal(await row.getByRole('button', { name: '启用并安装 sing-box', exact: true }).isEnabled(), true)
    assert.equal(writes.length, 0, 'capability discovery must not implicitly enable a server')

    await row.getByRole('button', { name: '启用并安装 sing-box', exact: true }).click()
    await row.getByText('安装已安排', { exact: true }).waitFor()
    await row.getByText('启用请求已保存，正在生成初始运行配置', { exact: true }).waitFor()
    assert.deepEqual(writes, [{ pathname: `${prefix}/1/enable`, method: 'POST', payload: {} }])
    assert.equal(device.appliedRev, 0)
    assert.equal(await row.getByText('已安装并运行', { exact: true }).count(), 0)
    assert.equal(await row.getByRole('button', { name: '启用并安装 sing-box', exact: true }).count(), 0)
    assert.equal(await page.locator('tbody tr').filter({ hasText: otherName }).getByRole('button', { name: '启用并安装 sing-box', exact: true }).count(), 1)

    const refresh = async (label, reason) => {
      const response = page.waitForResponse(response => new URL(response.url()).pathname === prefix && response.request().method() === 'GET')
      await page.getByRole('button', { name: '刷新', exact: true }).click()
      await response
      await row.getByText(label, { exact: true }).waitFor()
      if (reason) await row.getByText(reason, { exact: true }).waitFor()
      assert.equal(await row.getByText('已安装并运行', { exact: true }).count(), label === '已安装并运行' ? 1 : 0)
      assert.equal(writes.length, 1, 'refreshing installation evidence must not install again')
    }
    targetRev = 1
    await refresh('等待应用配置', '等待设备下载已签制品、应用配置并确认健康；尚未确认安装完成')
    preparationError = missingArtifact
    await refresh('安装或部署失败', missingArtifact)
    assert.equal(device.appliedRev, 0, 'a preparation failure must not claim a device application')
    preparationError = null
    device.downloaded = true
    await refresh('等待应用配置')
    assert.equal(device.healthy, false)
    device.appliedRev = 1
    await refresh('等待应用配置')
    assert.equal(device.downloaded, true)
    device.healthy = true
    await refresh('已安装并运行', '设备已确认应用目标版本，运行时健康检查通过')

    // The existing per-server route must use only the selected metadata endpoint.
    const beforeSingle = reads.length
    await page.goto(`${origin}/#/servers/1/plugins`)
    await page.getByRole('heading', { name: 'sing-box 安装与运行状态', exact: true }).waitFor()
    await page.getByText('已安装并运行', { exact: true }).waitFor()
    assert.equal(await page.locator('tbody tr').count(), 1)
    assert.equal(await page.getByRole('link', { name: otherName, exact: true }).count(), 0)
    assert.equal(await page.getByRole('navigation', { name: '服务器导航' }).getByRole('link', { name: '服务器插件', exact: true }).getAttribute('aria-current'), 'page')
    assert(reads.slice(beforeSingle).includes(`${prefix}/1`))
    assert.equal(reads.slice(beforeSingle).includes(prefix), false, 'per-server view must not load the entire collection')
    assert.equal(writes.length, 1)
    assert.deepEqual(unexpected, [])
    assert.deepEqual(errors, [])
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await context.close()
  }
  console.log('PASS: dist 1440/390, explicit enable once, queued/pending/missing artifact reason, readiness requires fixture device evidence, per-server scope, unexpected API/errors=0')
} finally {
  try { await browser?.close() }
  finally { await new Promise(resolve => server.close(resolve)) }
}
