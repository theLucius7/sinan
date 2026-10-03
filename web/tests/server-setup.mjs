import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { extname, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const { chromium } = await import(process.env.SINAN_PLAYWRIGHT_MODULE ? pathToFileURL(process.env.SINAN_PLAYWRIGHT_MODULE).href : 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const mime = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' }
const server = createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://127.0.0.1').pathname
  const file = resolve(root, pathname === '/' ? 'index.html' : `.${pathname}`)
  if (!file.startsWith(root.endsWith(sep) ? root : `${root}${sep}`)) { response.writeHead(400).end(); return }
  try { const body = await readFile(file); response.writeHead(200, { 'Content-Type': mime[extname(file)] ?? 'application/octet-stream' }); response.end(body) }
  catch { response.end() }
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
const origin = `http://127.0.0.1:${server.address().port}`
const browser = await chromium.launch({ headless: true, ...(process.env.SINAN_CHROME_PATH ? { executablePath: process.env.SINAN_CHROME_PATH } : {}) })
const screenshots = process.env.SINAN_UI_SCREENSHOT_DIR
if (screenshots) await mkdir(screenshots, { recursive: true })
const results = []
const installCommand = (version, platform = 'unix', target = 'auto') => platform === 'windows'
  ? `& { param($Version,$Panel,$Token,$Target) Write-Output "TEST_ONLY: $Version $Panel $Token $Target" } '${version}' 'https://panel.example.com' 'TEST_ONLY' '${target}'`
  : `sh -c 'set -eu; d=$(mktemp -d); curl -fsSL "$1" -o "$d/bootstrap.sh"; printf "%s  %s\\n" "$2" "$d/bootstrap.sh" | sha256sum -c -; /bin/sh "$d/bootstrap.sh" --version "$3" --panel "$4" --token "$5" --target "$6"' sinan-bootstrap 'https://api.github.com/repos/theLucius7/sinan/git/blobs/${'1'.repeat(40)}' '${'a'.repeat(64)}' '${version}' 'https://panel.example.com' 'TEST_ONLY' '${target}'`
const signedVersion = (version, targets, cached_targets = targets) => ({ version, tag: `agent-v${version}`, targets, cached_targets, protocol_min: 1, protocol_max: 1 })
const catalogue = [signedVersion('0.3.1', ['windows-amd64', 'windows-arm64', 'macos-arm64', 'freebsd-amd64']), signedVersion('0.3.0', ['linux-musl-arm64', 'linux-gnu-amd64'], ['linux-musl-arm64']), signedVersion('0.2.9', ['arm64']), signedVersion('0.2.8', ['linux-gnu-amd64'])]
const matchesTarget = (entry, target) => {
  const arch = target.split('-').at(-1)
  if (target.startsWith('linux-gnu-')) return entry.targets.some(value => [target, `linux-musl-${arch}`, arch].includes(value))
  if (target.startsWith('linux-musl-')) return entry.targets.some(value => [target, arch].includes(value))
  return entry.targets.includes(target)
}

try {
  for (const width of [1440, 390]) {
    const context = await browser.newContext({ viewport: { width, height: width > 800 ? 1000 : 844 } })
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin })
    const page = await context.newPage(), errors = [], unexpected = [], creates = [], enrollments = [], enrollmentTargets = [], enrollmentPlatforms = []
    page.on('pageerror', error => errors.push(error.message))
    let entry, settings, probes = [], createFailure = true, enrollmentMode = 'failure', statusFailure = false, windowsVersionsMissing = false, allVersionsMissing = false
    await page.route('**/api/**', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace('/api/dashboard/', '/api/')
      const fulfill = (json, status = 200) => route.fulfill({ status, json })
      if (path === '/api/access') return route.fulfill({ json: { authenticated: true, public_dashboard: false } })
      if (path === '/api/me') return fulfill({ id: 1 })
      if (path === '/api/artifacts') return fulfill(allVersionsMissing ? [] : catalogue.flatMap(item => item.cached_targets.map(arch => ({ name: 'agent', version: item.version, arch, sha256: 'a'.repeat(64), bytes: 1024 }))))
      if (path === '/api/artifacts/agent-versions') {
        const platform = url.searchParams.get('platform'), target = url.searchParams.get('target')
        let versions = allVersionsMissing ? [] : catalogue
        if (platform === 'windows') versions = windowsVersionsMissing ? [] : versions.filter(item => item.targets.some(value => value.startsWith('windows-')))
        if (platform === 'unix') versions = versions.filter(item => item.targets.some(value => !value.startsWith('windows-')))
        if (target) versions = versions.filter(item => matchesTarget(item, target))
        return fulfill({ versions })
      }
      if (path === '/api/servers' && request.method() === 'GET') return fulfill(entry ? [entry] : [])
      if (path === '/api/servers' && request.method() === 'POST') {
        const body = request.postDataJSON(); creates.push(body)
        if (createFailure) return fulfill({ error: '测试：创建失败，请重试' }, 400)
        await new Promise(resolve => setTimeout(resolve, 100))
        settings = body.agent_settings; probes = body.probes
        entry = { id: 1, name: body.name, device_public_key: null, online: false, static_info: {}, latest_metrics: {}, manifest_rev: 0, capabilities: [], metrics_stale: false, metrics_sampled_at: null }
        return fulfill(entry, 201)
      }
      if (path === '/api/servers/1') return fulfill(statusFailure ? { error: '测试：状态暂不可用' } : entry, statusFailure ? 503 : 200)
      if (path === '/api/servers/1/enrollment' && request.method() === 'POST') {
        enrollments.push(url.searchParams.get('agent_version'))
        enrollmentTargets.push(url.searchParams.get('agent_target'))
        enrollmentPlatforms.push(url.searchParams.get('platform'))
        if (enrollmentMode === 'failure') return fulfill({ error: '测试：命令接口暂不可用' }, 503)
        const version = url.searchParams.get('agent_version') ?? 'latest', target = url.searchParams.get('agent_target') ?? 'auto', platform = url.searchParams.get('platform') ?? 'unix'
        return fulfill({ token: 'TEST_ONLY', expires_at: Math.floor(Date.now() / 1000) + (enrollmentMode === 'expired' ? -1 : 86400), installation: enrollmentMode === 'missing' ? null : { version, tag: version === 'latest' ? null : `agent-v${version}`, target, platform }, install_command: enrollmentMode === 'missing' ? null : installCommand(version, platform, target), warning: enrollmentMode === 'missing' ? '测试：请维护者准备兼容的签名发布' : null })
      }
      if (path === '/api/servers/1/agent-settings') return fulfill(settings)
      if (path === '/api/servers/1/telemetry-settings') return fulfill({ persist_interval_secs: 60 })
      if (path === '/api/servers/1/probes') return fulfill(probes)
      if (path === '/api/servers/1/probe-results' || path === '/api/servers/1/commands') return fulfill([])
      if (path === '/api/plugins/sing-box/servers/1') return fulfill({ id: 1, name: entry.name, enabled: false, online: entry.online, agent_supported: false, read_only: false, source: null })
      unexpected.push(`${request.method()} ${path}`)
      return fulfill({ error: 'Unexpected fixture request' }, 500)
    })
    await page.goto(`${origin}/#/servers`)
    await page.getByRole('button', { name: '添加服务器', exact: true }).first().click()
    const dialog = page.getByRole('dialog')
    await dialog.getByText('连接一台新的服务器', { exact: true }).waitFor()
    if (width > 800) assert.ok((await dialog.boundingBox()).width >= 800, 'Desktop setup uses the wider layout')
    assert.equal(await dialog.getByLabel('采样间隔（秒）', { exact: false }).inputValue(), '1')
    assert.equal(await dialog.getByRole('switch', { name: /自动更新 Agent/ }).isChecked(), false)
    assert.equal(await dialog.getByRole('switch', { name: /自动识别公网地址/ }).isChecked(), true)
    if (screenshots) await page.screenshot({ animations: 'disabled', path: resolve(screenshots, `setup-empty-${width}.png`) })
    await dialog.getByLabel('服务器名称', { exact: false }).fill('   ')
    await dialog.getByRole('button', { name: '创建并继续' }).click()
    assert.equal(creates.length, 0)
    await dialog.getByLabel('服务器名称', { exact: false }).fill(' 东京 · 主节点 ')
    await dialog.getByRole('button', { name: /均衡/ }).click()
    await dialog.getByLabel('采样间隔（秒）', { exact: false }).fill('11')
    await dialog.getByRole('button', { name: '创建并继续' }).click()
    assert.equal(creates.length, 0, 'Upload interval must not be smaller than sampling')
    await dialog.getByRole('button', { name: /均衡/ }).click()
    await dialog.getByRole('switch', { name: /自动更新 Agent/ }).check()
    await dialog.getByRole('switch', { name: /自动识别公网地址/ }).uncheck()
    await dialog.getByRole('button', { name: '添加目标' }).click()
    const tcp = dialog.getByRole('group', { name: '拨测目标 1', exact: true })
    await tcp.getByLabel('拨测名称').fill('主站连通性')
    await tcp.getByLabel('目标地址').fill('probe.example.com')
    await tcp.getByLabel('目标端口').fill('8443')
    await tcp.getByLabel('拨测间隔（秒）').fill('45')
    await tcp.getByLabel('线路备注').fill('测试线路')
    await dialog.locator('form').evaluate(form => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })))
    await dialog.getByRole('alert').filter({ hasText: '授权' }).waitFor()
    assert.equal(creates.length, 0, 'Example and loopback addresses never imply target authority')
    assert.equal(await tcp.getByLabel('目标端口').inputValue(), '8443', 'The unauthorized enrollment preserves all target fields')
    await tcp.getByLabel('目标授权依据').selectOption('owned')
    await tcp.getByLabel('授权来源').fill('TEST_ONLY-owned-server')
    await tcp.getByLabel('授权适用范围').fill('TCP 8443，每45秒')
    await tcp.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    for (const [label, changed, original, select] of [
      ['目标地址', 'other.example.com', 'probe.example.com', false],
      ['目标端口', '9443', '8443', false],
      ['检测方式', 'icmp', 'tcp', true],
      ['网络版本', 'ipv6', 'auto', true],
    ]) {
      const field = tcp.getByLabel(label)
      await (select ? field.selectOption(changed) : field.fill(changed))
      assert.equal(await tcp.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false, `${label} must invalidate previous consent`)
      await (select ? field.selectOption(original) : field.fill(original))
      assert.equal(await tcp.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).isChecked(), false, 'Returning to the original target never silently restores consent')
      await dialog.getByRole('button', { name: '创建并继续' }).click()
      assert.equal(creates.length, 0, 'A fresh manual confirmation is required before posting the server')
      await tcp.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    }
    await dialog.getByRole('button', { name: '添加目标' }).click()
    const icmp = dialog.getByRole('group', { name: '拨测目标 2', exact: true })
    await icmp.getByLabel('检测方式').selectOption('icmp')
    assert.equal(await icmp.getByLabel('目标端口').count(), 0)
    await icmp.getByLabel('拨测名称').fill('本地回显')
    await icmp.getByLabel('目标地址').fill('::1')
    await icmp.getByLabel('网络版本').selectOption('ipv6')
    await icmp.getByLabel('目标授权依据').selectOption('owned')
    await icmp.getByLabel('授权来源').fill('TEST_ONLY-owned-loopback')
    await icmp.getByLabel('授权适用范围').fill('ICMP，自有IPv6回环')
    await icmp.getByRole('switch', { name: /^确认该范围内允许周期探测/ }).check()
    await dialog.getByRole('button', { name: '添加目标' }).click()
    await dialog.getByRole('button', { name: '移除目标 3' }).click()
    assert.equal(await dialog.getByRole('group', { name: /拨测目标/ }).count(), 2)
    assert.equal(await tcp.getByLabel('目标地址').inputValue(), 'probe.example.com')
    await dialog.getByRole('button', { name: '创建并继续' }).click()
    await dialog.getByRole('alert').filter({ hasText: '测试：创建失败' }).waitFor()
    assert.equal(await tcp.getByLabel('目标端口').inputValue(), '8443', 'Failed creation preserves the form')
    assert.equal(await dialog.getByRole('switch', { name: /自动更新 Agent/ }).isChecked(), true)
    const overflow = await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1)
    assert.equal(overflow, false, `Dialog overflows horizontally at ${width}px`)
    if (screenshots) { await dialog.evaluate(element => { element.scrollTop = 0 }); await page.screenshot({ animations: 'disabled', path: resolve(screenshots, `setup-probes-${width}.png`) }) }
    createFailure = false
    await dialog.locator('form').evaluate(form => { form.requestSubmit(); form.requestSubmit() })
    await dialog.getByRole('alert').filter({ hasText: '测试：命令接口暂不可用' }).waitFor()
    assert.equal(creates.length, 2, 'Repeated submission must not duplicate the successful creation')
    assert.equal(enrollments.length, 1)
    assert.equal(creates[1].name, '东京 · 主节点')
    assert.deepEqual(creates[1].telemetry_settings, { persist_interval_secs: 60 })
    assert.deepEqual(settings, { sample_interval_secs: 3, upload_interval_secs: 10, auto_update: true, discover_public_ips: false })
    assert.deepEqual(probes.map(({ kind, port, interval_secs }) => ({ kind, port, interval_secs })), [{ kind: 'tcp', port: 8443, interval_secs: 45 }, { kind: 'icmp', port: null, interval_secs: 30 }])
    assert.deepEqual(probes.map(probe => probe.monitor.authorization.identity), [
      { kind: 'tcp', target: 'probe.example.com', port: 8443, address_family: 'any' },
      { kind: 'icmp', target: '::1', port: null, address_family: 'ipv6' },
    ])
    enrollmentMode = 'ok'
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).waitFor()
    await dialog.getByRole('button', { name: '复制安装命令' }).click()
    await dialog.getByRole('button', { name: '已复制' }).waitFor()
    const copied = await page.evaluate(() => navigator.clipboard.readText())
    assert.equal(copied, installCommand('latest'), 'Automatic enrollment lets the actual machine choose its compatible signed version')
    assert.equal(/[\r\n]/.test(copied), false, 'The copied command contains exactly one physical line')
    assert.equal(await dialog.locator('code').evaluate(element => getComputedStyle(element).whiteSpace), 'pre', 'The command preview is also displayed on one line')
    assert.equal(await dialog.evaluate(element => element.scrollWidth > element.clientWidth + 1), false, `The URL command overflows the dialog at ${width}px`)
    assert.equal(creates.length, 2, 'Retrying enrollment must not recreate the server')
    const versionSelect = dialog.getByLabel('Agent 版本', { exact: false }), targetSelect = dialog.getByLabel('目标系统与架构', { exact: false }), platformSelect = dialog.getByLabel('服务器系统', { exact: false })
    assert.equal(await versionSelect.inputValue(), '')
    assert.equal(await targetSelect.inputValue(), '')
    await targetSelect.selectOption('linux-gnu-amd64')
    await versionSelect.locator('option[value="0.2.8"]').waitFor({ state: 'attached' })
    assert.equal(await versionSelect.locator('option[value="0.2.9"]').count(), 0, 'An AMD target excludes ARM-only versions')
    assert.equal(await versionSelect.locator('option[value="0.3.0"]').count(), 1, 'A signed AMD variant remains selectable when only ARM is cached')
    await versionSelect.selectOption('0.2.8')
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.locator('code').filter({ hasText: '0.2.8' }).waitFor()
    assert.equal(enrollmentTargets.at(-1), 'linux-gnu-amd64')
    assert.equal(enrollments.at(-1), '0.2.8')
    await targetSelect.selectOption('linux-musl-arm64')
    await versionSelect.locator('option[value="0.2.9"]').waitFor({ state: 'attached' })
    assert.equal(await versionSelect.inputValue(), '', 'Changing target resets the old version choice')
    assert.equal(await versionSelect.locator('option[value="0.2.8"]').count(), 0, 'A musl ARM target excludes GNU AMD versions')
    await versionSelect.selectOption('0.2.9')
    assert.equal(await dialog.getByRole('button', { name: '复制安装命令' }).count(), 0, 'Changing the version hides the old command')
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.locator('code').filter({ hasText: '0.2.9' }).waitFor()
    assert.equal(enrollments.at(-1), '0.2.9')
    await platformSelect.selectOption('windows')
    await versionSelect.locator('option[value="0.3.1"]').waitFor({ state: 'attached' })
    assert.equal(await dialog.locator('code').count(), 0, 'Switching to PowerShell hides the old Unix command')
    assert.equal(await targetSelect.locator('option[value="linux-musl-arm64"]').count(), 0)
    assert.equal(await versionSelect.locator('option[value="0.2.9"]').count(), 0)
    await targetSelect.selectOption('windows-arm64')
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).click()
    await dialog.getByRole('button', { name: '已复制' }).waitFor()
    const windowsCommand = await page.evaluate(() => navigator.clipboard.readText())
    assert.equal(windowsCommand, installCommand('latest', 'windows', 'windows-arm64'), 'Windows receives and copies the PowerShell command')
    assert.equal(/[\r\n]/.test(windowsCommand), false)
    assert.equal(enrollmentPlatforms.at(-1), 'windows')
    await versionSelect.selectOption('0.3.1')
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.locator('code').filter({ hasText: '0.3.1' }).waitFor()
    assert.equal(enrollments.at(-1), '0.3.1')
    await platformSelect.selectOption('unix')
    await versionSelect.locator('option[value="0.2.9"]').waitFor({ state: 'attached' })
    await targetSelect.selectOption('macos-arm64')
    await versionSelect.locator('option[value="0.3.1"]').waitFor({ state: 'attached' })
    assert.equal(await versionSelect.locator('option[value="0.3.0"]').count(), 0, 'macOS lists only compatible native versions')
    await targetSelect.selectOption('freebsd-amd64')
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).waitFor()
    assert.equal(enrollmentTargets.at(-1), 'freebsd-amd64')
    assert.equal(enrollmentPlatforms.at(-1), null)
    windowsVersionsMissing = true
    await platformSelect.selectOption('windows')
    await dialog.getByText(/当前没有适合此系统与架构的已签名版本/).waitFor()
    assert.equal(await dialog.getByRole('button', { name: '重新生成命令' }).isDisabled(), true, 'No published compatible Windows version cannot produce a misleading install command')
    assert.equal(await dialog.locator('code').count(), 0)
    windowsVersionsMissing = false
    await platformSelect.selectOption('unix')
    await versionSelect.locator('option[value="0.2.9"]').waitFor({ state: 'attached' })
    await versionSelect.selectOption('0.2.9')
    enrollmentMode = 'expired'
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByText('接入令牌已过期，请重新生成命令。', { exact: true }).waitFor()
    assert.equal(await dialog.locator('code').count(), 0)
    enrollmentMode = 'missing'
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByText(/测试：请维护者准备兼容的签名发布/).waitFor()
    assert.equal(await dialog.locator('code').count(), 0)
    enrollmentMode = 'ok'
    await dialog.getByRole('button', { name: '重新生成命令' }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).waitFor()
    entry = { ...entry, device_public_key: 'TEST_ONLY' }
    await dialog.getByRole('heading', { name: '已注册，等待设备连接' }).waitFor({ timeout: 10000 })
    entry = { ...entry, online: true, static_info: { agent_version: '0.3.0' } }
    await dialog.getByRole('heading', { name: '服务器已上线' }).waitFor({ timeout: 10000 })
    if (screenshots) { await dialog.evaluate(element => { element.scrollTop = 0 }); await page.screenshot({ animations: 'disabled', path: resolve(screenshots, `enrollment-online-${width}.png`) }) }
    statusFailure = true
    await dialog.getByRole('button', { name: '立即检查' }).click()
    await dialog.getByRole('heading', { name: '暂时无法确认设备状态' }).waitFor()
    assert.equal(await dialog.getByRole('heading', { name: '服务器已上线' }).count(), 0)
    statusFailure = false
    await dialog.getByRole('button', { name: '立即检查' }).click()
    await dialog.getByRole('heading', { name: '服务器已上线' }).waitFor()
    await dialog.getByRole('button', { name: '设备迟迟未上线？' }).click()
    await dialog.getByText(/确认设备能访问命令中的面板地址/).waitFor()
    await dialog.getByRole('button', { name: '查看服务器' }).focus()
    await page.keyboard.press('Tab')
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('aria-label')), '关闭对话框', 'Tab stays inside the dialog')
    await dialog.getByRole('button', { name: '查看服务器' }).click()
    await page.waitForURL('**/#/servers/1')
    await page.getByRole('heading', { name: '东京 · 主节点', exact: true }).waitFor()
    await page.getByRole('button', { name: '接入 / 升级', exact: true }).click()
    await dialog.getByRole('button', { name: '复制安装命令' }).waitFor()
    await dialog.getByRole('heading', { name: '设备当前在线' }).waitFor()
    assert.equal(await dialog.getByRole('heading', { name: '服务器已上线' }).count(), 0, 'An already online device does not confirm an upgrade')
    await page.keyboard.press('Escape')
    await dialog.waitFor({ state: 'hidden' })
    allVersionsMissing = true
    const previousEnrollmentCount = enrollments.length
    await page.getByRole('button', { name: '接入 / 升级', exact: true }).click()
    await dialog.getByText(/当前没有适合此系统与架构的已签名版本/).waitFor()
    await dialog.getByText(/请维护者准备对应的 Agent 发布后重试/).waitFor()
    assert.equal(await dialog.getByRole('button', { name: '复制安装命令' }).count(), 0, 'An empty signed catalogue offers no install command')
    assert.equal(enrollments.length, previousEnrollmentCount, 'An empty catalogue does not issue an unusable enrollment token')
    assert.equal(await dialog.getByRole('link', { name: /导入/ }).count(), 0, 'Enrollment does not link to a removed import form')
    const catalogLink = dialog.getByRole('link', { name: '查看已收录版本', exact: true })
    assert.equal(await catalogLink.getAttribute('href'), '#/plugins/catalog')
    await catalogLink.click()
    await dialog.waitFor({ state: 'hidden' })
    await page.getByRole('heading', { name: '插件目录', exact: true }).waitFor()
    await page.getByRole('heading', { name: '服务器 Agent', exact: true }).waitFor()
    assert.equal(await page.getByRole('button', { name: /导入|安装/ }).count(), 0, 'The retained catalogue only displays available packages')
    assert.equal(enrollments.length, previousEnrollmentCount, 'Opening the catalogue does not issue an enrollment token')
    assert.equal(creates.length, 2)
    assert.deepEqual(unexpected, [])
    assert.deepEqual(errors, [])
    results.push({ width, creation: 'passed', enrollment: 'passed', signedVersions: 'passed', platforms: 'passed', singleLineCopy: 'passed', recovery: 'passed', liveStatus: 'passed', keyboard: 'passed', emptyCatalogueNavigation: 'passed' })
    await context.close()
  }
  console.log(JSON.stringify(results, null, 2))
} finally {
  await browser.close()
  await new Promise(resolve => server.close(resolve))
}
