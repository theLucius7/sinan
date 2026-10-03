import { catalogResourceFixtures } from './proxy-resource-fixtures.mjs'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile } from 'node:fs/promises'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { resolve, extname, sep } from 'node:path'
import { flatResourceFixtures, proxyResourceFixtures } from './proxy-resource-fixtures.mjs'

// Exercise the actual dist; every API request is intercepted by an owned fixture.
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
const results = []
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
  const origin = `http://127.0.0.1:${server.address().port}`
  for (const width of [1280, 390]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } })
    page.setDefaultTimeout(5000)
    await page.clock.install()
    const errors = [], writes = [], failures = new Set(), heldReads = new Map()
    const prefix = '/api/plugins/sing-box'
    const paths = ['ordered-proxy-resources', 'nodes', 'servers'].map(name => `${prefix}/${name}`)
    const baseNodes = [1, 2, 3].map(id => ({ id, server_id: id, name: `节点 ${id}`, enabled: true, protocol: 'vless-reality', public_host: 'proxy.example.com', port: 443, sni: 'www.example.com', public_key: 'TEST_ONLY', short_id: '0123abcd' }))
    let nodes = baseNodes.map(value => ({ ...value }))
    const servers = [1, 2, 3].map(id => ({ id, name: `服务器 ${id}`, enabled: true, online: false, agent_supported: true, read_only: false, source: 'administrator' }))
    const baseServers = servers.map(server => ({...server}))
    const previous = { id: 100, name: '保留的旧链路', entry_node_id: 3, exit_node_id: 2, available: true }
    let chains = [{ ...previous }]
    let nextId = 101
    page.on('pageerror', error => errors.push(error.message))
    await page.route('**/api/**', async route => {
      const request = route.request(), pathname = new URL(request.url()).pathname, method = request.method()
      if (method !== 'GET') writes.push({ pathname, method, payload: method === 'POST' ? request.postDataJSON() : null })
      if (method === 'GET' && failures.has(pathname)) { await route.fulfill({ status: 500, json: { error: `链路夹具读取失败：${pathname}` } }); return }
      if (method === 'GET' && heldReads.has(pathname)) {
        const gate = heldReads.get(pathname)
        heldReads.delete(pathname); gate.enter(); await gate.released
      }
      let value
      if (method === 'GET' && pathname === '/api/dashboard/access') value = { authenticated: true, public_dashboard: false }
      else if (method === 'GET' && pathname === '/api/me') value = { authenticated: true }
      else if (method === 'GET' && pathname === `${prefix}/nodes`) value = nodes
      else if (method === 'GET' && pathname === `${prefix}/servers`) value = servers
      else if (method === 'GET' && pathname === `${prefix}/usage`) value = {total:'0',uplink:'0',downlink:'0',by_node:[],by_user:[]}
      else if (method === 'GET' && [ `${prefix}/subscription-sources`, `${prefix}/ordered-subscription-sources` ].includes(pathname)) value = []
      else if (method === 'GET' && pathname === `${prefix}/proxy-resources`) value = flatResourceFixtures(nodes, [...servers,...baseServers.filter(base => !servers.some(server => server.id === base.id))], chains)
      else if (method === 'GET' && pathname === `${prefix}/node-catalog`) value = catalogResourceFixtures(flatResourceFixtures(nodes, [...servers,...baseServers.filter(base => !servers.some(server => server.id === base.id))], chains))
      else if (method === 'GET' && pathname === `${prefix}/ordered-proxy-resources`) value = proxyResourceFixtures(nodes, [...servers,...baseServers.filter(base => !servers.some(server => server.id === base.id))], chains)
      else if (method === 'GET' && pathname === `${prefix}/chains`) value = chains
      else if (method === 'POST' && pathname === `${prefix}/chains/ordered-batch`) {
        const payload = request.postDataJSON()
        assert.match(payload.request_id,/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
        assert.deepEqual(payload.items,[{name:'完整保留的创建草稿',entry:{mode:'existing',node_id:1},hops:[{kind:'managed',node_id:2}]}])
        const chain = {name:payload.items[0].name,entry_node_id:1,exit_node_id:2,id:nextId++,available:true,path_kind:'ordered'}; chains.push(chain)
        value = {request_id:payload.request_id,chain_ids:[chain.id],entry_node_ids:[1]}
      } else if (method === 'DELETE' && pathname === `${prefix}/ordered-proxy-resources/chain/100`) {
        assert(chains.some(chain => chain.id === 100), 'deletion must never use a disappeared ID')
        chains = chains.filter(chain => chain.id !== 100)
        await route.fulfill({ status: 204, body: '' }); return
      } else {
        errors.push(`Unexpected API: ${method} ${pathname}`)
        await route.fulfill({ status: 404, json: { error: '夹具拒绝未知接口' } }); return
      }
      await route.fulfill({ json: value })
    })

    const createButton = page.getByRole('button', { name: '创建两跳链路', exact: true })
    const refreshButton = page.locator('header.page-header').getByRole('button', { name: '刷新', exact: true })
    const oldRow = page.getByRole('row').filter({ has: page.getByText(previous.name, { exact: true }) })
    const refreshLists = async () => {
      // An open modal covers the page Refresh button; exercise the real polling loader.
      if (await page.getByRole('dialog').count()) await page.clock.fastForward(5000)
      else await refreshButton.click()
    }
    const enabled = async locator => {
      await locator.waitFor()
      const deadline = Date.now() + 5000
      while (await locator.isDisabled() && Date.now() < deadline) await page.waitForTimeout(20)
      assert.equal(await locator.isDisabled(), false)
    }
    const noWrites = async (operation, message) => {
      const count = writes.length
      await operation()
      await page.waitForTimeout(75)
      assert.equal(writes.length, count, message)
    }
    const forceOpeners = async (includeDelete) => {
      for (const button of [createButton, ...(includeDelete ? [oldRow.getByRole('button', { name: '删除', exact: true })] : [])]) {
        await button.evaluate(element => {
          element.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }))
          const key = Object.keys(element).find(key => key.startsWith('__reactProps$'))
          const props = key && element[key]
          if (typeof props?.onClick !== 'function') throw new Error('actual Chains opening callback was not found in this dist')
          props.onClick()
        })
      }
    }
    const failedRead = async pathname => {
      failures.add(pathname)
      const response = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'GET' && response.status() === 500)
      // Keep a failed trigger's original exception instead of an unhandled close rejection.
      void response.catch(() => {})
      await refreshLists(); await response
      await page.getByRole('alert').filter({ hasText: `链路夹具读取失败：${pathname}` }).first().waitFor()
    }
    const pendingRead = async (pathname, trigger, during) => {
      let enter, release
      const arrived = new Promise(resolve => { enter = resolve })
      const released = new Promise(resolve => { release = resolve })
      heldReads.set(pathname, { enter, released })
      const response = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'GET' && response.status() === 200)
      let timer
      try {
        await trigger()
        await Promise.race([arrived, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('owned pending read did not arrive')), 5000) })])
        clearTimeout(timer)
        await page.waitForFunction(() => [...document.querySelectorAll('button')].find(button => button.textContent === '创建两跳链路')?.disabled === true)
        await during()
      } finally { clearTimeout(timer); release(); await response }
    }
    const recover = async (pathname, dialog, during) => {
      failures.delete(pathname)
      await pendingRead(pathname, () => (dialog ? dialog.getByRole('button', { name: '重试', exact: true }) : page.getByRole('button', { name: '重试', exact: true }).first()).click(), during)
      await enabled(createButton)
    }
    const inspectDraft = async dialog => {
      assert.equal(await dialog.locator('[name="name"]').inputValue(), '完整保留的创建草稿')
      assert.equal(await dialog.locator('[name="entry_node_id"]').inputValue(), '1')
      assert.equal(await dialog.locator('[name="exit_node_id"]').inputValue(), '2')
      assert.equal(await dialog.getByRole('button', { name: '取消', exact: true }).isDisabled(), false)
    }
    const forceCreate = async dialog => {
      await dialog.locator('form').evaluate(form => {
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
        // Also call the real Chains callback, bypassing FormDialog's disabled guard.
        const key = Object.keys(form).find(key => key.startsWith('__reactFiber$'))
        let fiber = key && form[key]
        while (fiber?.return) fiber = fiber.return
        // DOM fibers may point to an alternate; only search the currently committed tree.
        const pending = [fiber?.stateNode?.current].filter(Boolean)
        let visited = 0
        while (pending.length && visited++ < 20000) {
          fiber = pending.pop()
          const props = fiber.memoizedProps
          if (props?.title === '创建两跳链路' && props.submitLabel === '创建未授权链路' && typeof props.onSubmit === 'function') {
            const data = new FormData()
            for (const name of ['name', 'entry_node_id', 'exit_node_id']) data.set(name, form.querySelector(`[name="${name}"]`).value)
            props.onSubmit(data); return
          }
          if (fiber.sibling) pending.push(fiber.sibling)
          if (fiber.child) pending.push(fiber.child)
        }
        throw new Error('actual Chains submit callback was not found in this dist')
      })
    }
    const forceDelete = async dialog => {
      await dialog.getByRole('button', { name: '确认删除', exact: true }).evaluate(button => {
        button.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }))
        // Also call the real Chains callback, bypassing Confirm's disabled guard.
        const key = Object.keys(button).find(key => key.startsWith('__reactFiber$'))
        let fiber = key && button[key]
        while (fiber?.return) fiber = fiber.return
        const pending = [fiber?.stateNode?.current].filter(Boolean)
        let visited = 0
        while (pending.length && visited++ < 20000) {
          fiber = pending.pop()
          const props = fiber.memoizedProps
          if (props?.title === '删除「保留的旧链路」？' && typeof props.onConfirm === 'function') { props.onConfirm(); return }
          if (fiber.sibling) pending.push(fiber.sibling)
          if (fiber.child) pending.push(fiber.child)
        }
        throw new Error('actual Chains delete callback was not found in this dist')
      })
    }
    const blockedCreate = async dialog => {
      assert.equal(await dialog.getByRole('button', { name: '创建未授权链路', exact: true }).isDisabled(), true)
      await inspectDraft(dialog)
      await noWrites(() => forceCreate(dialog), 'disabled and direct create callbacks must send zero POSTs')
    }
    const blockedDelete = async dialog => {
      assert.equal(await dialog.getByRole('button', { name: '确认删除', exact: true }).isDisabled(), true)
      assert.equal(await dialog.getByRole('button', { name: '取消', exact: true }).isDisabled(), false)
      await dialog.getByRole('heading', { name: '删除「保留的旧链路」？', exact: true }).waitFor()
      await noWrites(() => forceDelete(dialog), 'disabled and direct delete callbacks must send zero DELETEs')
    }

    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains`)
    await enabled(createButton)
    await oldRow.waitFor()
    for (const pathname of paths) {
      await failedRead(pathname)
      assert.equal(await createButton.isDisabled(), true)
      assert.equal(await oldRow.getByRole('button', { name: '删除', exact: true }).isDisabled(), pathname === `${prefix}/ordered-proxy-resources`)
      if (pathname === `${prefix}/ordered-proxy-resources`) await oldRow.getByText('资源状态待确认', { exact: true }).waitFor()
      await noWrites(() => forceOpeners(pathname === `${prefix}/ordered-proxy-resources`), 'failed opening callbacks must send zero business writes')
      assert.equal(await page.getByRole('dialog').count(), 0)
      await recover(pathname, null, async () => {
        assert.equal(await createButton.isDisabled(), true)
        if (pathname === `${prefix}/ordered-proxy-resources`) assert.equal(await oldRow.getByRole('button', { name: '删除', exact: true }).isDisabled(),true)
        else await enabled(oldRow.getByRole('button', { name: '删除', exact: true }))
        await noWrites(() => forceOpeners(pathname === `${prefix}/ordered-proxy-resources`), 'pending opening callbacks must send zero business writes')
        assert.equal(await page.getByRole('dialog').count(), 0)
        assert.equal(writes.length, 0)
      })
    }
    await createButton.click()
    const creating = page.getByRole('dialog')
    await creating.locator('[name="entry_mode"]').selectOption('existing')
    await creating.locator('[name="name"]').fill('完整保留的创建草稿')
    await creating.locator('[name="entry_node_id"]').selectOption('1')
    await creating.locator('[name="exit_node_id"]').selectOption('2')
    for (const pathname of paths) {
      await failedRead(pathname); await blockedCreate(creating)
      await recover(pathname, creating, () => blockedCreate(creating))
      await enabled(creating.getByRole('button', { name: '创建未授权链路', exact: true }))
      await inspectDraft(creating)
      await pendingRead(pathname, refreshLists, () => blockedCreate(creating))
      await enabled(creating.getByRole('button', { name: '创建未授权链路', exact: true }))
    }
    for (const change of ['missing-node', 'disabled-node', 'protocol', 'missing-server', 'disabled-server', 'chain-role']) {
      if (change === 'missing-node') nodes = nodes.filter(node => node.id !== 1)
      if (change === 'disabled-node') nodes[0].enabled = false
      if (change === 'protocol') nodes[0].protocol = 'hysteria2'
      if (change === 'missing-server') servers[0].id = 99
      if (change === 'disabled-server') servers[0].enabled = false
      if (change === 'chain-role') chains.push({ id: 102, name: '并发创建的链路', entry_node_id: 1, exit_node_id: 2, available: true })
      const pathname = change.includes('server') ? `${prefix}/servers` : change === 'chain-role' ? `${prefix}/ordered-proxy-resources` : `${prefix}/nodes`
      const response = page.waitForResponse(response => new URL(response.url()).pathname === pathname && response.request().method() === 'GET' && response.status() === 200)
      await refreshLists(); await response
      await creating.getByRole('alert').filter({ hasText: change === 'chain-role' ? '链路身份已变更' : '已选节点已不可用' }).waitFor()
      await blockedCreate(creating)
      nodes = baseNodes.map(value => ({ ...value })); servers[0].id = 1; servers[0].enabled = true
      chains = chains.filter(chain => chain.id !== 102)
      await refreshLists()
      await enabled(creating.getByRole('button', { name: '创建未授权链路', exact: true }))
      await inspectDraft(creating)
    }
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await creating.getByRole('button', { name: '创建未授权链路', exact: true }).click()
    await page.getByRole('dialog').waitFor({ state: 'hidden' })
    await page.getByText('完整保留的创建草稿', { exact: true }).waitFor()
    assert.equal(writes.length,1)
    assert.deepEqual(writes[0], { pathname: `${prefix}/chains/ordered-batch`, method: 'POST', payload: { request_id:writes[0].payload.request_id,items:[{name:'完整保留的创建草稿',entry:{mode:'existing',node_id:1},hops:[{kind:'managed',node_id:2}]}] } })
    await enabled(oldRow.getByRole('button', { name: '删除', exact: true }))
    await oldRow.getByRole('button', { name: '删除', exact: true }).click()
    const deleting = page.getByRole('dialog')
    for (const pathname of [`${prefix}/ordered-proxy-resources`]) {
      await failedRead(pathname); await blockedDelete(deleting)
      await recover(pathname, deleting, () => blockedDelete(deleting))
      await enabled(deleting.getByRole('button', { name: '确认删除', exact: true }))
      await pendingRead(pathname, refreshLists, () => blockedDelete(deleting))
      await enabled(deleting.getByRole('button', { name: '确认删除', exact: true }))
    }
    chains = chains.filter(chain => chain.id !== 100)
    const disappeared = page.waitForResponse(response => new URL(response.url()).pathname === `${prefix}/ordered-proxy-resources` && response.request().method() === 'GET' && response.status() === 200)
    await refreshLists(); await disappeared
    await deleting.getByRole('alert').filter({ hasText: '此资源已不可用' }).waitFor()
    await blockedDelete(deleting)
    chains.push({ ...previous, available: false })
    await deleting.getByRole('button', { name: '重试', exact: true }).click()
    await enabled(deleting.getByRole('button', { name: '确认删除', exact: true }))
    await oldRow.getByText('资源已不可用', { exact: true }).waitFor()
    await deleting.getByRole('button', { name: '确认删除', exact: true }).click()
    await page.getByRole('dialog').waitFor({ state: 'hidden' })
    await oldRow.waitFor({ state: 'hidden' })
    assert.deepEqual(writes.at(-1), { pathname: `${prefix}/ordered-proxy-resources/chain/100`, method: 'DELETE', payload: null })
    assert.equal(writes.length, 2)

    // A blocked editor remains closable, and a failed filtered read keeps the last list.
    await enabled(createButton); await createButton.click()
    await creating.locator('[name="name"]').fill('可关闭的草稿')
    await failedRead(`${prefix}/servers`)
    await creating.getByRole('button', { name: '取消', exact: true }).click()
    await page.getByRole('dialog').waitFor({ state: 'hidden' })
    await recover(`${prefix}/servers`, null, async () => assert.equal(writes.length, 2))
    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains&server=2`)
    await page.waitForFunction(() => document.querySelector('select[aria-label="按服务器筛选"]')?.value === '2')
    // The cancelled server=1 draft survives this route change and must not silently retarget server=2.
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('2')
    assert.equal(await createButton.isDisabled(), true)
    await noWrites(() => forceOpeners(false), 'The preserved entry draft conflicts with the current server filter')
    assert.equal(await page.getByRole('dialog').count(), 0)
    await page.goto(`${origin}/#/plugins/sing-box/nodes`)
    await page.waitForFunction(() => document.querySelector('select[aria-label="按服务器筛选"]')?.value === '')
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('')
    await enabled(createButton); await createButton.click()
    assert.equal(await creating.locator('[name="name"]').inputValue(), '可关闭的草稿')
    assert.equal(await creating.locator('[name="server_id"]').inputValue(), '1')
    await creating.locator('[name="server_id"]').selectOption('2')
    await creating.getByRole('button', { name: '取消', exact: true }).click()
    await creating.waitFor({ state: 'hidden' })
    assert.equal(writes.length, 2, 'Explicitly choosing the new scope edits only the local draft')
    await page.goto(`${origin}/#/plugins/sing-box/nodes?kind=chains&server=2`)
    await page.waitForFunction(() => document.querySelector('select[aria-label="按服务器筛选"]')?.value === '2')
    await page.getByRole('combobox', { name: '按服务器筛选', exact: true }).selectOption('2')
    await enabled(createButton)
    const retained = page.getByRole('row').filter({ has: page.getByText('完整保留的创建草稿', { exact: true }) })
    await retained.waitFor()
    await failedRead(`${prefix}/nodes`)
    await retained.waitFor()
    await retained.getByText('资源存在', { exact: true }).waitFor()
    assert.equal(await createButton.isDisabled(), true)
    assert.equal(writes.length, 2)
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    assert.deepEqual(errors, [])
    results.push({ width, writes: writes.length, failed_dependencies: paths.length, browser_errors: errors.length,
      checked: ['buttons-failed-and-pending', 'open-create-and-delete-failed-and-pending', 'direct-callback-zero-writes', 'draft-and-old-list-retained', 'recovered-missing-disabled-protocol-and-role-refused', 'deleted-id-refused', 'explicit-unavailable-chain-cleanup', 'cancel-and-retry', 'filtered-history', 'no-overflow'] })
    await page.close()
  }
  console.log(JSON.stringify({ passed: results }))
} finally {
  if (browser) await browser.close()
  await new Promise(resolve => server.close(resolve))
}
