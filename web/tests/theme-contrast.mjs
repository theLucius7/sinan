import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { readFile, readdir } from 'node:fs/promises'
import { resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

// TEST_ONLY: after rebuilding web/dist, run `node web/tests/theme-contrast.mjs`.
// This offline DOM consumes the actual entry CSS and lazy dashboard CSS in their
// application order. It never starts the application, calls an API, or reads CSS
// from src. Environment overrides match the existing browser suites.
const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE
  ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const dist = fileURLToPath(new URL('../dist/', import.meta.url))
const entry = await readFile(resolve(dist, 'index.html'), 'utf8')
const entryStyles = [...entry.matchAll(/<link\b[^>]*>/gi)].flatMap(([tag]) => {
  const relation = /\brel\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]
  const href = /\bhref\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1]
  return relation?.split(/\s+/).includes('stylesheet') && href ? [href] : []
})
assert(entryStyles.length > 0, 'The built index must declare its stylesheet')
const displayStyles = (await readdir(resolve(dist, 'assets')))
  .filter(name => /^ServerDisplay-[^/]+\.css$/.test(name))
assert.equal(displayStyles.length, 1, 'The built dashboard must have one current stylesheet')
const styles = [...entryStyles, `/assets/${displayStyles[0]}`]
assert.equal(new Set(styles).size, styles.length, 'Do not load a stylesheet twice')
const assets = new Map()
for (const href of styles) {
  const url = new URL(href, 'http://fixture.invalid/')
  assert.equal(url.origin, 'http://fixture.invalid', 'Fixture CSS must be local')
  assert(!url.search && !url.hash && url.pathname.endsWith('.css'), 'Expected a built CSS path')
  const file = resolve(dist, `.${url.pathname}`)
  assert(file.startsWith(`${dist.replace(/\/$/, '')}${sep}`), 'CSS must remain inside dist')
  const bytes = await readFile(file)
  assets.set(url.pathname, bytes)
}
const stylesheetManifest = [...assets].map(([path, bytes]) => ({
  path, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'),
}))
const stylesheetLinks = [...assets.keys()]
  .map(href => `<link rel="stylesheet" href="${href}">`).join('\n')

function fixture(theme) {
  assert(['light', 'dark'].includes(theme))
  // Inline layout only gives the isolated specimens room; all tested colours,
  // state selectors and filters come from the built product stylesheets.
  return `<!doctype html><html lang="zh-CN" data-theme="${theme}"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>TEST_ONLY 主题状态夹具</title><link rel="icon" href="data:,">${stylesheetLinks}
  </head><body><main style="max-width:780px;margin:0 auto;padding:24px">
    <h1 style="font-size:18px;margin-bottom:20px">主题状态夹具</h1>
    <nav class="node-views ui-tab-list" aria-label="节点视图">
      <a id="node-active" class="active" href="#active" aria-current="page">当前视图</a>
      <a id="node-hover" href="#hover">其他视图</a>
    </nav>
    <button id="icon-action" class="icon-button" type="button" aria-label="刷新">
      <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden="true"><path d="M4 10a6 6 0 1 0 2-4" fill="none" stroke="currentColor"/></svg>
    </button>
    <ol class="server-setup-steps" aria-label="添加服务器进度" style="margin-top:24px">
      <li id="step-complete" class="is-complete"><span>✓</span><div><strong>已完成</strong><small>配置服务器</small></div></li>
      <li id="step-current" class="is-current" aria-current="step"><span>2</span><div><strong>当前步骤</strong><small>安装与接入</small></div></li>
      <li id="step-waiting"><span>3</span><div><strong>下一步</strong><small>等待上线</small></div></li>
    </ol>
    <section class="server-setup-section server-enrollment-status is-online" aria-label="设备在线状态" style="margin-top:24px">
      <div class="server-setup-heading"><div><h3 id="online-heading">设备在线</h3><p>已收到采样</p></div>
        <svg id="online-icon" width="23" height="23" viewBox="0 0 23 23" aria-hidden="true"><path d="m4 12 5 5 10-11" fill="none" stroke="currentColor"/></svg>
      </div>
    </section>
    <div class="server-enrollment-command"><div class="copy-field"><code id="enrollment-code">TEST_ONLY 接入命令</code></div></div>
    <label class="field"><span>禁用输入</span><input id="disabled-input" disabled value="TEST_ONLY"></label>
    <label class="field"><span>禁用选择</span><select id="disabled-select" disabled><option>测试项</option></select></label>
    <div id="quiet-notice" class="notice quiet-notice">
      <svg id="quiet-notice-icon" width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="7" fill="none" stroke="currentColor"/></svg>
      <div><strong id="quiet-notice-title">等待检测</strong><p>尚未收到检测结果</p></div>
    </div>
    <section class="server-display" data-theme="${theme}" aria-label="看板状态" style="min-height:0;padding:16px">
      <article id="quality-card" class="d-card d-glass">
        <div class="d-card-body" style="padding:16px"><span id="poor-value" class="d-quality-value d-quality-poor">检测质量较差</span></div>
      </article>
      <article id="offline-card" class="d-card d-glass d-offline" style="margin-top:16px;min-height:120px">
        <div class="d-card-body" style="padding:16px"><span>离线前的采样</span></div>
        <div id="offline-overlay" class="d-offline-overlay"><strong id="offline-title">服务器离线</strong><span id="offline-detail">等待重新连接</span></div>
      </article>
    </section>
  </main></body></html>`
}

const totals = {
  stylesheetManifest, contexts: 0, pages: 0, closedContexts: 0,
  browserClosed: false, serverClosed: false, requests: [],
  externalRequests: [], unexpectedRequests: [], pageErrors: [], results: [],
}
const server = createServer((request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1')
  if (!['GET', 'HEAD'].includes(request.method)) return response.writeHead(405).end()
  let bytes, type
  if (url.pathname === '/__theme_fixture' && ['light', 'dark'].includes(url.searchParams.get('theme'))) {
    bytes = Buffer.from(fixture(url.searchParams.get('theme'))); type = 'text/html; charset=utf-8'
  } else if (assets.has(url.pathname) && !url.search) {
    bytes = assets.get(url.pathname); type = 'text/css; charset=utf-8'
  } else return response.writeHead(404).end()
  response.writeHead(200, { 'Content-Type': type, 'Content-Length': bytes.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' })
  response.end(request.method === 'HEAD' ? undefined : bytes)
})

async function colour(page, selector, property = 'color') {
  return page.locator(selector).evaluate((element, property) => getComputedStyle(element)[property], property)
}
async function referenceColour(page, selector, value) {
  return page.locator(selector).evaluate((element, value) => {
    const probe = document.createElement('span')
    probe.style.cssText = 'position:absolute;visibility:hidden;pointer-events:none'
    probe.style.color = value.startsWith('--') ? getComputedStyle(element).getPropertyValue(value) : value
    document.body.append(probe)
    try { return getComputedStyle(probe).color } finally { probe.remove() }
  }, value)
}
async function assertColour(page, selector, value, description) {
  const actual = await colour(page, selector), expected = await referenceColour(page, selector, value)
  assert.equal(actual, expected, description)
  return actual
}
async function hover(page, selector) {
  await page.locator(selector).hover()
  // Wait for the actual CSS transitions instead of sampling an intermediate colour.
  await page.evaluate(() => Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))))
}
async function poorContrast(page) {
  return page.locator('#poor-value').evaluate(element => {
    const canvas = document.createElement('canvas'); canvas.width = canvas.height = 1
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) throw Error('Canvas colour conversion is unavailable')
    const rgba = colour => {
      context.clearRect(0, 0, 1, 1); context.fillStyle = colour; context.fillRect(0, 0, 1, 1)
      const [r, g, b, a] = context.getImageData(0, 0, 1, 1).data
      return [r, g, b, a / 255]
    }
    const composite = (front, back) => {
      const alpha = front[3] + back[3] * (1 - front[3])
      return [...front.slice(0, 3).map((channel, index) => (channel * front[3] + back[index] * back[3] * (1 - front[3])) / alpha), alpha]
    }
    // The real glass card is translucent. Resolve all painted ancestor layers,
    // including the display background, rather than substituting a solid token.
    const ancestors = []
    for (let parent = element; parent; parent = parent.parentElement) ancestors.unshift(parent)
    let background = [255, 255, 255, 1]
    const layers = ancestors.map(parent => {
      const colour = getComputedStyle(parent).backgroundColor
      background = composite(rgba(colour), background)
      return { tag: parent.tagName, id: parent.id, colour }
    })
    const foreground = getComputedStyle(element).color
    const renderedForeground = composite(rgba(foreground), background)
    const luminance = value => value.slice(0, 3).map(channel => {
      const normalized = channel / 255
      return normalized <= .04045 ? normalized / 12.92 : ((normalized + .055) / 1.055) ** 2.4
    }).reduce((sum, channel, index) => sum + channel * [.2126, .7152, .0722][index], 0)
    const first = luminance(renderedForeground), second = luminance(background)
    return { foreground, background: background.slice(0, 3), layers, ratio: (Math.max(first, second) + .05) / (Math.min(first, second) + .05) }
  })
}

async function run() {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  const origin = `http://127.0.0.1:${server.address().port}`
  let browser
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
    for (const width of [1440, 390, 340]) for (const theme of ['light', 'dark']) {
      const context = await browser.newContext({ viewport: { width, height: 1200 }, colorScheme: theme, serviceWorkers: 'block' })
      ++totals.contexts
      const result = { width, theme, normalClose: false }, requests = []
      totals.results.push(result)
      try {
        context.on('request', request => {
          const url = new URL(request.url())
          const record = { width, theme, method: request.method(), origin: url.origin, path: url.pathname }
          requests.push(record); totals.requests.push(record)
        })
        context.on('page', created => {
          ++totals.pages
          created.on('pageerror', error => totals.pageErrors.push({ width, theme, error: error.message }))
          if (context.pages().length > 1) totals.unexpectedRequests.push({ width, theme, path: 'unexpected-page' })
        })
        // Interception is context-wide, including any unexpected popup or worker.
        await context.route('**/*', async route => {
          const request = route.request(), url = new URL(request.url())
          if (url.origin !== origin) { totals.externalRequests.push({ width, theme, url: url.href }); return route.abort() }
          if (request.method() !== 'GET' || (!assets.has(url.pathname) && url.pathname !== '/__theme_fixture')) {
            totals.unexpectedRequests.push({ width, theme, method: request.method(), path: url.pathname }); return route.abort()
          }
          return route.continue()
        })
        const page = await context.newPage()
        page.setDefaultTimeout(10000)
        const response = await page.goto(`${origin}/__theme_fixture?theme=${theme}`, { waitUntil: 'load' })
        assert.equal(response.status(), 200)
        const loadedStyles = await page.locator('link[rel="stylesheet"]').evaluateAll(links => links.map(link => ({ path: new URL(link.href).pathname, loaded: Boolean(link.sheet) })))
        assert.deepEqual(loadedStyles, [...assets.keys()].map(path => ({ path, loaded: true })), 'Every actual built CSS asset must load in order')
        const active = await assertColour(page, '#node-active', '--ink', 'Active node navigation must keep its theme foreground')
        assert.equal(await colour(page, '#node-active', 'borderBottomColor'), await referenceColour(page, '#node-active', '--green'))
        const idleNode = await colour(page, '#node-hover')
        await hover(page, '#node-hover')
        const hoveredNode = await assertColour(page, '#node-hover', '--green', 'Hovered node navigation must keep its theme accent')
        assert.notEqual(hoveredNode, idleNode, 'Hover must remain distinct from idle navigation')
        await hover(page, '#node-active')
        await assertColour(page, '#node-active', '--green', 'Hovered active navigation must keep its theme accent')
        const idleIcon = await colour(page, '#icon-action')
        await hover(page, '#icon-action')
        const hoveredIcon = await assertColour(page, '#icon-action', '--green', 'Hovered icon action must use the shared control accent')
        assert.notEqual(hoveredIcon, idleIcon, 'Icon hover must remain distinct from idle')
        const currentStep = await assertColour(page, '#step-current', '#215e49', 'Current setup step must keep its existing state colour')
        const completeStep = await assertColour(page, '#step-complete', '#557762', 'Completed setup step must keep its existing state colour')
        assert.notEqual(currentStep, completeStep)
        assert.notEqual(currentStep, await colour(page, '#step-waiting'))
        const currentMarker = await referenceColour(page, '#step-current > span', '#215e49')
        assert.equal(await colour(page, '#step-current > span', 'backgroundColor'), currentMarker)
        assert.equal(await colour(page, '#step-current > span', 'borderTopColor'), currentMarker)
        await assertColour(page, '#step-current > span', '#fff', 'Current step marker must retain its foreground')
        const onlineIcon = await assertColour(page, '#online-icon', '#4b773f', 'Online enrollment icon must retain the online state colour')
        assert.equal(await colour(page, '#online-heading'), onlineIcon)
        const enrollmentCode = await assertColour(page, '#enrollment-code', '#476540', 'Enrollment command must retain its own code colour')
        const disabledValue = theme === 'dark' ? '--ink' : '#6f756a'
        const disabledInput = await assertColour(page, '#disabled-input', disabledValue, 'Disabled input must retain the theme foreground')
        const disabledSelect = await assertColour(page, '#disabled-select', disabledValue, 'Disabled select must retain the theme foreground')
        const quietNotice = await assertColour(page, '#quiet-notice', theme === 'dark' ? '--ink' : '#66725b', 'Combined quiet notice must retain the notice state foreground')
        assert.equal(await colour(page, '#quiet-notice-title'), quietNotice, 'Combined quiet notice title must inherit its state foreground')
        assert.equal(await colour(page, '#quiet-notice-icon'), quietNotice, 'Combined quiet notice icon must inherit its state foreground')
        await assertColour(page, '#poor-value', '--d-poor-bar', 'Poor quality text must use its paired theme tone')
        const contrast = await poorContrast(page)
        assert(contrast.ratio >= 4.5, `${theme}/${width}: poor quality text contrast ${contrast.ratio.toFixed(3)} is below 4.5`)
        const overlay = await page.locator('#offline-overlay').evaluate(element => {
          const style = getComputedStyle(element)
          const ancestors = []
          for (let parent = element; parent; parent = parent.parentElement) ancestors.push({ tag: parent.tagName, id: parent.id, filter: getComputedStyle(parent).filter })
          const text = [...element.children].map(child => ({ id: child.id, filter: getComputedStyle(child).filter, backdropFilter: getComputedStyle(child).backdropFilter }))
          return { backdropFilter: style.backdropFilter, ancestors, text }
        })
        assert.match(overlay.backdropFilter, /saturate\(/, 'Offline overlay must desaturate its backdrop')
        assert(overlay.ancestors.every(layer => layer.filter === 'none'), 'A foreground filter must not affect overlay text')
        assert(overlay.text.every(text => text.filter === 'none' && text.backdropFilter === 'none'), 'Offline labels must stay outside the backdrop filter')
        await assertColour(page, '#offline-title', '--d-danger', 'Offline title retains the unfiltered theme danger colour')
        await assertColour(page, '#offline-detail', '--d-muted-text', 'Offline detail retains the unfiltered theme muted colour')
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Fixture state specimens must fit this viewport')
        assert.equal(requests.filter(request => request.path === '/__theme_fixture').length, 1)
        for (const path of assets.keys()) assert.equal(requests.filter(request => request.path === path).length, 1, 'Each stylesheet must actually be requested once')
        assert.equal(requests.length, assets.size + 1, 'Only the fixture document and built CSS may be requested')
        Object.assign(result, { active, hoveredNode, hoveredIcon, currentStep, completeStep, onlineIcon, enrollmentCode, disabledInput, disabledSelect, quietNotice, contrast, overlay, requests: requests.length })
      } finally {
        await context.close(); result.normalClose = true; ++totals.closedContexts
      }
    }
    assert.equal(totals.contexts, 6); assert.equal(totals.pages, 6); assert.equal(totals.closedContexts, 6)
    assert.deepEqual(totals.externalRequests, []); assert.deepEqual(totals.unexpectedRequests, []); assert.deepEqual(totals.pageErrors, [])
  } finally {
    try { if (browser) { await browser.close(); totals.browserClosed = true } }
    finally { await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); totals.serverClosed = true }
  }
}

try { await run() }
catch (error) { process.exitCode = 1; totals.failure = error.stack ?? String(error) }
finally { console.log(JSON.stringify(totals, null, 2)) }
