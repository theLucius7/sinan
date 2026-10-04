import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

// Exercise the shipped bundle against loopback fixtures, never production Agents.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const http = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.writeHead(404).end() }
})
await new Promise(resolve => http.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${http.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const packageFor = (name, version, arch) => ({ name, version, arch, bytes: 1024, sha256: 'a'.repeat(64) })
const packages = [
  packageFor('sing-box', '1.14.2', 'arm64'), packageFor('sing-box', '1.14.2', 'amd64'), packageFor('sing-box', '1.13.0', 'amd64'),
  packageFor('nodequality', `${'a'.repeat(40)}-r12`, 'amd64'), packageFor('nodequality', `${'a'.repeat(40)}-r12`, 'arm64'),
  packageFor('tcpquality', '0.3.0-TEST_ONLY-r1', 'amd64'), packageFor('tcpquality', '0.3.0-TEST_ONLY-r1', 'arm64'),
  packageFor('agent', '0.3.0', 'amd64'), packageFor('agent', '0.3.0', 'arm64'),
  packageFor('custom-component', '1', 'amd64'), packageFor('custom-component', '1', 'arm64'),
]

try {
  for (const width of [1440, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    const errors = [], mutations = [], reads = []
    let inventory = packages, artifactFailure = false, serverFailure = false, noServers = false, metadataFailure = false
    const metadata = { id: 2, name: '所选服务器', enabled: false, online: true, agent_supported: true, read_only: false, source: null, installation: { state: 'not_enabled', reason: '尚未启用插件；设备支持此插件不代表已安装', target_rev: 0, applied_rev: 0 } }
    const servers = [
      { id: 1, name: '另一台服务器', online: false, device_public_key: null, static_info: {} },
      { id: 2, name: metadata.name, online: true, device_public_key: 'TEST_ONLY', static_info: {} },
    ]
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname
      let value
      if (request.method() !== 'GET') {
        mutations.push({ path, method: request.method(), body: request.postDataJSON() })
        if (path !== '/api/plugins/sing-box/servers/2/enable' || request.method() !== 'POST') {
          errors.push(`Unexpected mutation: ${path}`); await route.fulfill({ status: 400, json: { error: 'UNEXPECTED_MUTATION' } }); return
        }
        Object.assign(metadata, { enabled: true, source: 'administrator', installation: { state: 'queued', reason: '启用请求已保存，正在生成初始运行配置', target_rev: 0, applied_rev: 0 } }); value = metadata
      } else {
        reads.push(path)
        if (path === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
        else if (path === '/api/me') value = { authenticated: true }
        else if (path === '/api/plugins/ddns/accounts') value = []
        else if (path === '/api/plugins/ddns/rules') value = []
        else if (path === '/api/plugins/ddns/servers') value = [{ id: 2, name: 'DDNS 测试服务器', online: true, enabled: false }]
        else if (path === '/api/artifacts') {
          if (artifactFailure) { await route.fulfill({ status: 403, json: { error: 'CATALOG_READ_FAILED' } }); return }
          value = inventory
        } else if (path === '/api/servers') {
          if (serverFailure) { await route.fulfill({ status: 403, json: { error: 'SERVER_READ_FAILED' } }); return }
          value = noServers ? [] : servers
        } else if (path === '/api/plugins/sing-box/servers/2') {
          if (metadataFailure) { await route.fulfill({ status: 403, json: { error: 'PLUGIN_STATE_UNKNOWN' } }); return }
          value = metadata
        } else if (path === '/api/servers/2') value = servers[1]
        else if (path === '/api/servers/2/node-quality/reports') value = { plugin_ready: false, plugin_reason: '测试安全门禁', full_ready: false, full_reason: '测试安全门禁', cancel_supported: false, reports: [] }
        else if (path === '/api/servers/2/diagnostics') value = { cancel_supported: false, plugins: [{ plugin: 'tcpquality', title: 'TCP 连接诊断', version: 'TEST_ONLY', ready: false, reason: '测试安全门禁' }], reports: [] }
        else if (path === '/api/plugins/tcpquality/servers/2/targets') value = []
        else { errors.push(`Unexpected read: ${path}`); await route.fulfill({ status: 404, json: {} }); return }
      }
      await route.fulfill({ json: value })
    })

    const cards = page.locator('[data-catalog-plugin]')
    const singbox = page.locator('[data-catalog-plugin="sing-box"]')
    const openCatalog = async (path = '/plugins/catalog') => {
      await installControlCenterFixtures(page)
      await page.goto(`${origin}/#${path}`)
      await page.getByRole('heading', { name: '插件目录', exact: true }).waitFor()
      await page.getByText('有已验证下载包', { exact: true }).first().waitFor()
    }
    await openCatalog('/artifacts')
    const ddns = page.locator('[data-catalog-plugin="ddns"]')
    await ddns.getByRole('button', { name: '选择服务器' }).click()
    const ddnsDialog = page.getByRole('dialog')
    await ddnsDialog.getByLabel('目标服务器').selectOption('2')
    await ddnsDialog.getByRole('button', { name: '前往服务器管理' }).click()
    await page.waitForURL(`${origin}/#/servers/2/ddns`)
    await page.getByRole('button', { name: '启用 DDNS 插件', exact: true }).waitFor()
    assert.deepEqual(mutations, [])
    await openCatalog('/artifacts')
    assert.equal(await cards.count(), 5)
    assert.equal(await page.getByRole('navigation', { name: '主导航' }).getByRole('link', { name: '插件目录' }).getAttribute('aria-current'), 'page')
    assert.equal(await page.title(), '插件目录 · 司南')
    assert.equal(await page.getByRole('link', { name: '制品', exact: true }).count(), 0)
    assert.equal(await page.locator('.catalog-grid, .catalog-unknown').locator('form, input').count(), 0)
    assert.equal(await page.getByRole('button', { name: /导入|安装/ }).count(), 0)
    assert.equal(await page.getByRole('heading', { name: '服务器 Agent', exact: true }).count(), 1)
    assert.equal(await page.getByRole('heading', { name: 'custom-component', exact: true }).count(), 1)
    assert.equal(await page.locator('.catalog-unknown').getByRole('button', { name: /选择服务器|安装|启用/ }).count(), 0)
    assert.equal(reads.filter(path => path === '/api/servers').length, 1)
    assert.equal(await singbox.locator('.catalog-architectures .badge').count(), 2)
    await singbox.locator('summary').click()
    assert.equal(await singbox.locator('.catalog-version').count(), 2)
    assert.equal(await singbox.locator('tbody tr').count(), 3)
    const oldVersion = singbox.getByRole('region', { name: '版本 1.13.0' })
    assert.equal(await oldVersion.locator('tbody tr').count(), 1)
    assert.equal((await oldVersion.innerText()).includes('arm64'), false)
    assert.deepEqual(mutations, [])
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    if (process.env.SINAN_UI_SCREENSHOT_DIR) await page.screenshot({ path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `plugin-catalog-${width}.png`), fullPage: true })

    // Failed refreshes retain historical version details but never imply readiness.
    artifactFailure = true
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByText('CATALOG_READ_FAILED', { exact: true }).waitFor()
    assert.equal(await page.getByText('版本状态未知', { exact: true }).count(), 3)
    assert.equal(await page.getByText('有已验证下载包', { exact: true }).count(), 0)
    assert.equal(await singbox.locator('.catalog-version').count(), 2)
    artifactFailure = false
    await page.getByRole('button', { name: '重试', exact: true }).click()
    await page.getByText('有已验证下载包', { exact: true }).first().waitFor()

    // Descriptions are independent of the package inventory, including an empty one.
    inventory = []
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByText('暂无下载包', { exact: true }).first().waitFor()
    assert.equal(await cards.count(), 5)
    assert.equal(await page.locator('[data-catalog-plugin="ddns"]').getByText('面板插件', { exact: true }).count(), 1)
    assert.equal(await cards.locator('summary').count(), 0)
    inventory = packages
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByText('有已验证下载包', { exact: true }).first().waitFor()

    // A failed/empty server lookup cannot default to the panel or an arbitrary ID.
    serverFailure = true
    await singbox.getByRole('button', { name: '选择服务器' }).click()
    let dialog = page.getByRole('dialog')
    await dialog.getByText('SERVER_READ_FAILED', { exact: true }).waitFor()
    assert.equal(await dialog.getByRole('button', { name: '前往服务器管理' }).isDisabled(), true)
    serverFailure = false; noServers = true
    await dialog.getByRole('button', { name: '重试' }).click()
    await dialog.getByRole('heading', { name: '还没有服务器' }).waitFor()
    assert.equal(await dialog.getByRole('button', { name: '前往服务器管理' }).isDisabled(), true)
    await dialog.getByRole('button', { name: '取消', exact: true }).click()
    noServers = false

    for (const [plugin, destination] of [['nodequality', '/node-quality'], ['tcpquality', '/tcp-quality'], ['sing-box', '/plugins']]) {
      await page.locator(`[data-catalog-plugin="${plugin}"]`).getByRole('button', { name: '选择服务器' }).click()
      dialog = page.getByRole('dialog')
      await dialog.getByLabel('目标服务器').waitFor()
      assert.equal(await dialog.getByRole('button', { name: '前往服务器管理' }).isDisabled(), true)
      await dialog.getByLabel('目标服务器').selectOption('2')
      assert.equal(await dialog.getByRole('option').count(), 3)
      await dialog.getByRole('button', { name: '前往服务器管理' }).click()
      await page.waitForURL(`${origin}/#/servers/2${destination}`)
      if (plugin === 'sing-box') {
        await page.getByRole('button', { name: '启用并安装 sing-box', exact: true }).waitFor()
        assert.equal(await page.locator('tbody tr').count(), 1)
        assert.equal(await page.getByRole('link', { name: metadata.name, exact: true }).count(), 1)
      } else {
        await page.getByText('测试安全门禁', { exact: false }).first().waitFor()
        for (const name of plugin === 'nodequality' ? ['日常检查', '完整验机'] : ['开始 TCP 诊断']) {
          assert.equal(await page.getByRole('button', { name, exact: true }).isDisabled(), true)
        }
        await openCatalog()
      }
      assert.deepEqual(mutations, [])
    }
    assert.equal(reads.includes('/api/plugins/sing-box/servers'), false)
    metadataFailure = true
    await page.getByRole('button', { name: '刷新', exact: true }).click()
    await page.getByText('PLUGIN_STATE_UNKNOWN', { exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: '启用并安装 sing-box', exact: true }).isDisabled(), true)
    metadataFailure = false
    await page.getByRole('button', { name: '重试', exact: true }).click()
    await page.getByText('PLUGIN_STATE_UNKNOWN', { exact: true }).waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: '启用并安装 sing-box', exact: true }).click()
    await page.getByText('管理员明确启用', { exact: true }).waitFor()
    await page.getByText('安装已安排', { exact: true }).waitFor()
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)
    assert.deepEqual(mutations, [{ path: '/api/plugins/sing-box/servers/2/enable', method: 'POST', body: {} }])
    await page.getByText('安装已安排', { exact: true }).waitFor()
    assert.equal(await page.getByText('已安装并运行', { exact: true }).count(), 0)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    assert.deepEqual(errors, [])
    await page.close()
    console.log(`PASS: ${width}px catalog grouping, legacy route, empty/error recovery, explicit server selection, read-only browsing and server-scoped activation`)

    // A public dashboard must not make the catalog or server controls public.
    const anonymous = await browser.newPage({ viewport: { width, height: 1000 } })
    const privateReads = []
    await anonymous.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/api/dashboard/access') await route.fulfill({ json: { authenticated: false, public_dashboard: true } })
      else { privateReads.push(path); await route.fulfill({ status: 403, json: {} }) }
    })
    for (const path of ['/plugins/catalog', '/artifacts', '/servers/2/plugins']) {
      await anonymous.goto(`${origin}/#${path}`)
      await anonymous.getByRole('heading', { name: '欢迎回来', exact: true }).waitFor()
      assert.equal(await anonymous.locator('[data-catalog-plugin]').count(), 0)
    }
    assert.deepEqual(privateReads, [])
    await anonymous.close()
    console.log(`PASS: ${width}px public dashboard does not expose the catalog or server plugin controls`)
  }
} finally { await browser.close(); await new Promise(resolve => http.close(resolve)) }
