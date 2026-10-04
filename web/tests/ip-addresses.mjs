import { installControlCenterFixtures } from './control-center-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const path = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, path === '/' ? 'index.html' : `.${path}`)
  if (!file.startsWith(`${root.replace(/\/$/, '')}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) } catch { response.writeHead(404).end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const results = []
try {
  for (const width of [1280, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 900 } })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    // Reserved documentation addresses stand in for the server-classified public group.
    const publicIps = ['192.0.2.1', '2001:db8::1']
    const privateIps = ['10.0.0.2', '172.17.0.1', '192.168.0.1', 'fd00::1', 'fd12:3456:789a:abcd:1234:5678:9abc:def0']
    let mode = 'mixed', refreshes = 0
    await page.route('**/api/**', async route => {
      const request = route.request(), path = new URL(request.url()).pathname.replace('/api/dashboard/', '/api/')
      let data
      if (path === '/api/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (path === '/api/me') data = {}
      else if (path === '/api/servers/1') data = { id: 1, name: 'IP 分类验收夹具', online: true, static_info: {}, latest_metrics: {}, capabilities: [] }
      else if (path === '/api/servers/1/ip-quality') {
        const exposed = ['mixed', 'public'].includes(mode) ? publicIps : []
        const internal = ['mixed', 'private'].includes(mode) ? privateIps : []
        data = { ip_addresses: [...exposed, ...internal], public_ip_addresses: exposed, private_ip_addresses: internal, quality: [], providers: [] }
      } else if (path === '/api/servers/1/ip-quality/refresh' && request.method() === 'POST') { refreshes++; data = [] }
      else throw new Error(`Unexpected API: ${request.method()} ${path}`)
      await route.fulfill({ json: data })
    })
    await installControlCenterFixtures(page)
    await page.goto(`${origin}/#/servers/1/ip-info`)
    const refresh = page.getByRole('button', { name: '刷新 IP 质量', exact: true })
    const group = page.locator('details.quality-private-addresses')
    const summary = group.locator('summary')
    await summary.waitFor()
    assert.equal(await page.locator('article.quality-address').count(), 2)
    for (const ip of publicIps) assert(await page.getByText(ip, { exact: true }).isVisible())
    for (const ip of privateIps) assert.equal(await page.getByText(ip, { exact: true }).isVisible(), false)
    assert.equal(await group.getAttribute('open'), null)
    assert.equal(await summary.innerText(), '内网地址（5）')
    await summary.focus()
    await page.keyboard.press('Enter')
    for (const ip of privateIps) assert(await page.getByText(ip, { exact: true }).isVisible())
    assert.equal(await group.locator('.quality-result').count(), 0)
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth))
    assert(await refresh.isEnabled())
    await refresh.click()
    await page.waitForFunction(() => document.querySelector('.panel-heading button')?.textContent.includes('刷新 IP 质量'))
    assert.equal(refreshes, 1)
    assert.notEqual(await group.getAttribute('open'), null)
    if (process.env.SINAN_UI_SCREENSHOT_DIR) await page.screenshot({ path: resolve(process.env.SINAN_UI_SCREENSHOT_DIR, `ip-addresses-${width}.png`), fullPage: true })
    mode = 'private'
    await page.reload()
    await page.getByText('尚未识别到公网 IP 地址，暂不能查询公网 IP 质量。', { exact: true }).waitFor()
    assert(await refresh.isDisabled())
    assert.equal(await page.locator('article.quality-address').count(), 0)
    assert.equal(await group.getAttribute('open'), null)
    await summary.click()
    for (const ip of privateIps) assert(await page.getByText(ip, { exact: true }).isVisible())
    mode = 'public'
    await page.reload()
    await page.getByText(publicIps[0], { exact: true }).waitFor()
    assert.equal(await group.count(), 0)
    assert(await refresh.isEnabled())
    mode = 'empty'
    await page.reload()
    await page.getByText('设备尚未上报 IP 地址，请升级 Agent 或等待设备上报。', { exact: true }).waitFor()
    assert(await refresh.isDisabled())
    assert.equal(await group.count(), 0)
    assert.equal(refreshes, 1)
    assert.deepEqual(errors, [])
    results.push({ width, publicVisible: true, privateCollapsed: true, keyboardExpand: true, privateOnly: true, publicOnly: true, empty: true, browserErrors: errors.length })
    await page.close()
  }
  console.log(JSON.stringify(results))
} finally { await browser.close(); await new Promise(resolve => server.close(resolve)) }
