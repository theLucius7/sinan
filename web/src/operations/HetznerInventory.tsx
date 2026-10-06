import { useEffect, useState } from 'react'
import { api, errorMessage } from '../api'
import type { Server } from '../types'
import type { ActionRunner } from './types'
import { time } from './types'

type Actor = { role: string; all_servers: boolean; capabilities: string[] }
type Account = { id: string; name: string; credential_id: string; archived: boolean; revision: number; last_attempt_at: number | null; last_read_at: number | null; last_error: string | null }
type Provider = { id: string; inventory_read: boolean; resource_linking: boolean; history: boolean; billing: boolean; balance: boolean; remote_writes: boolean; official_source: string }
type Snapshot = {
  status: string
  ipv4: string | null
  ipv6: string | null
  created_at: string | null
  server_type: { id: number; name: string; cores: number | null; memory_gb: number | null; disk_gb: number | null; architecture: string | null }
  location: { id: number | null; name: string | null; country: string | null; city: string | null }
  datacenter: { id: number; name: string }
  traffic: { included_bytes: string | null; ingoing_bytes: string | null; outgoing_bytes: string | null }
  protection: { delete: boolean | null; rebuild: boolean | null }
}
type Resource = {
  id: string
  account_id: string
  account_name: string
  account_archived: boolean
  cloud_id: string
  name: string
  snapshot: Snapshot | null
  presence: 'observed' | 'absent' | 'unknown'
  last_seen_at: number | null
  last_attempt_at: number | null
  verified_at: number | null
  stale: boolean
  error_code: string | null
  link: { server_id: number | null; notes: string; updated_at: number; updated_by: number } | null
}
type Inventory = { resources: Resource[]; provider: Provider; served_at: number; inventory_stale_after_secs: number; limits: { page_size: number; max_pages: number; max_resources: number; list_limit: number; list_truncated: boolean } }
type ReadResult = { account_id: string; complete: boolean; pages: number; observed: number; total_cached: number; error_code: string | null; last_read_at: number | null }
type History = { id: string; resource_id: string; observed_at: number; source: string; presence: 'observed' | 'absent' | 'unknown'; snapshot: Snapshot | null; changes: unknown; refresh_id: string }
type AccountDraft = { id: string | null; name: string; credential_id: string; expected_revision: number | null }
const emptyAccount: AccountDraft = { id: null, name: '', credential_id: '', expected_revision: null }
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const presenceNames = { observed: '完整清单已发现', absent: '完整清单未发现', unknown: '存在状态未知' }
const statusNames: Record<string, string> = { initializing: '初始化中', starting: '启动中', running: '运行中', stopping: '停止中', off: '已关闭', deleting: '删除中', rebuilding: '重装中', migrating: '迁移中', unknown: '未知' }
const errorNames: Record<string, string> = { credential_unavailable: '加密凭据不可用', credential_invalid: '凭据格式不符合提供方要求', network_timeout: '官方读取超时', network_error: '官方连接失败', http_401: '官方凭据验证失败', http_403: '官方接口拒绝访问', http_429: '官方接口限流', http_5xx: '官方服务异常', http_other: '官方接口返回其他错误', invalid_response: '官方响应无法解析', pagination_inconsistent: '分页结果不一致', inventory_limit: '清单超过受控读取上限' }
const describeError = (code: string | null) => code ? `${errorNames[code] ?? '读取出现其他错误'}（${code}）` : ''

export default function HetznerInventory({ servers, run, version }: { servers: Server[]; run: ActionRunner; version: number }) {
  const [actor, setActor] = useState<Actor | null>(null)
  const [accounts, setAccounts] = useState<Account[]>([])
  const [inventory, setInventory] = useState<Inventory | null>(null)
  const [accountDraft, setAccountDraft] = useState<AccountDraft>(emptyAccount)
  const [accountError, setAccountError] = useState('')
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [readingAccount, setReadingAccount] = useState<string | null>(null)
  const [readResults, setReadResults] = useState<Record<string, ReadResult>>({})
  const [resource, setResource] = useState<Resource | null>(null)
  const [serverId, setServerId] = useState('')
  const [notes, setNotes] = useState('')
  const [linkError, setLinkError] = useState('')
  const [historyResource, setHistoryResource] = useState<Resource | null>(null)
  const [history, setHistory] = useState<History[]>([])
  const allows = (capability: string) => actor?.role === 'owner' || Boolean(actor?.capabilities.includes(capability))
  const globalActor = actor?.role === 'owner' || Boolean(actor?.all_servers)
  const canReadAccounts = globalActor && allows('cloud:read')
  const canManageAccounts = globalActor && allows('cloud:write')
  const canEditLinks = allows('cloud:write')
  const canChooseServers = allows('servers:read')

  const refresh = async () => {
    setLoading(true)
    setError('')
    try {
      const principal = await api<Actor>('/api/control-center/me')
      setActor(principal)
      const globalRead = (principal.role === 'owner' || principal.all_servers) && (principal.role === 'owner' || principal.capabilities.includes('cloud:read'))
      const [resourceResult, accountResult] = await Promise.allSettled([
        api<Inventory>('/api/operations/cloud/hetzner/resources'),
        globalRead ? api<{ accounts: Account[]; provider: Provider }>('/api/operations/cloud/hetzner/accounts') : Promise.resolve(null),
      ])
      if (accountResult.status === 'fulfilled') { setAccounts(accountResult.value?.accounts ?? []); setAccountError('') }
      else setAccountError(errorMessage(accountResult.reason))
      if (resourceResult.status === 'rejected') throw resourceResult.reason
      setInventory(resourceResult.value)
    } catch (value) {
      setError(errorMessage(value))
      throw value
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { run(refresh) }, [version]) // eslint-disable-line react-hooks/exhaustive-deps

  const saveAccount = () => {
    const draft = { ...accountDraft }
    run(async () => {
      setAccountError('')
      setMessage('')
      try {
        if (!draft.name.trim() || !uuid.test(draft.credential_id.trim())) throw new Error('请填写账号名称和有效的加密云凭据引用编号。')
        await api('/api/operations/cloud/hetzner/accounts', 'POST', { ...(draft.id ? { id: draft.id, expected_revision: draft.expected_revision } : {}), name: draft.name.trim(), credential_id: draft.credential_id.trim() })
        setMessage('本地账号引用已保存。官方清单须另行明确读取。')
        await refresh()
        setAccountDraft(emptyAccount)
      } catch (value) {
        setAccountError(errorMessage(value))
        throw value
      }
    }, true)
  }
  const readAccount = (account: Account) => run(async () => {
    setReadingAccount(account.id)
    setAccountError('')
    try {
      const result = await api<ReadResult>(`/api/operations/cloud/hetzner/accounts/${account.id}/refresh`, 'POST')
      setReadResults(previous => ({ ...previous, [account.id]: result }))
      await refresh()
    } catch (value) {
      setAccountError(errorMessage(value))
      throw value
    } finally {
      setReadingAccount(null)
    }
  })
  const chooseResource = (value: Resource) => { setResource(value); setServerId(value.link?.server_id?.toString() ?? ''); setNotes(value.link?.notes ?? ''); setLinkError('') }
  const saveLink = () => {
    if (!resource) return
    const id = resource.id
    const selectedServer = serverId ? Number(serverId) : null
    const selectedNotes = notes
    run(async () => {
      setLinkError('')
      try {
        await api(`/api/operations/cloud/hetzner/resources/${id}/link`, 'POST', { server_id: selectedServer, notes: selectedNotes })
        await refresh()
        setResource(null)
        setMessage('本地资源关联与备注已保存。')
      } catch (value) {
        setLinkError(errorMessage(value))
        throw value
      }
    }, true)
  }

  return <section className="operations-card" aria-busy={loading}>
    <h3>Hetzner 官方只读资源清单</h3>
    <p>支持服务器清单、公网地址、机型、数据中心、状态以及本地资产关联和历史。官方来源为 Hetzner Cloud v1 的服务器接口；账单、余额、启停、带宽和安全组等远端修改当前不可用。</p>
    <button className="ui-button" type="button" disabled={loading} onClick={() => run(refresh)}>读取面板缓存与授权状态</button>
    {error && <p className="operations-error" role="alert">{error}{inventory && '；下方保留上次读取的缓存。'}</p>}
    {message && <p role="status">{message}</p>}
    {loading && <p role="status">正在读取面板中的资源记录。</p>}
    {actor && !canReadAccounts && <p>当前账号可查看已授权关联资源；提供方账号清单和官方读取入口需要所有服务器范围的云读取授权。</p>}
    {canReadAccounts && <>
      <h4>提供方账号</h4>
      {accountError && <p className="operations-error" role="alert">{accountError}</p>}
      {!accounts.length && !accountError && <p>尚未登记 Hetzner 账号。</p>}
      <div className="operations-table-wrap"><table><thead><tr><th>账号／凭据引用</th><th>官方读取记录</th><th>操作</th></tr></thead><tbody>{accounts.map(account => {
        const result = readResults[account.id]
        return <tr key={account.id}>
          <td>{account.name}<small>{account.archived ? '本地账号已归档' : `账号记录版本 ${account.revision}`}</small><small>加密凭据引用：{account.credential_id}</small></td>
          <td>最近完整读取 {time(account.last_read_at)}<small>最近尝试 {time(account.last_attempt_at)}</small>{account.last_error && <small>{describeError(account.last_error)}</small>}{result && <small>{result.complete ? '本次清单完整' : '本次读取不完整，未确认缺失资源'} · 已读取 {result.pages} 页、观测 {result.observed} 个资源 · 缓存共 {result.total_cached} 条{result.error_code ? ` · ${describeError(result.error_code)}` : ''}</small>}</td>
          <td><button className="ui-button" type="button" disabled={account.archived || readingAccount !== null} onClick={() => readAccount(account)}>{readingAccount === account.id ? '正在读取官方清单' : '从官方接口读取清单'}</button>{canManageAccounts && !account.archived && <><button className="ui-button" type="button" onClick={() => { setAccountDraft({ id: account.id, name: account.name, credential_id: account.credential_id, expected_revision: account.revision }); setAccountError(''); setMessage('') }}>编辑本地账号引用</button><button className="ui-button" type="button" onClick={() => run(async () => { await api(`/api/operations/cloud/hetzner/accounts/${account.id}`, 'DELETE'); setMessage('本地账号已归档，云服务器与历史记录保留。'); if (accountDraft.id === account.id) setAccountDraft(emptyAccount); await refresh() }, true)}>验证身份并归档本地账号</button></>}</td>
        </tr>
      })}</tbody></table></div>
      <p>只有明确点击官方读取入口才向提供方查询。分页不完整或读取失败时保留历史缓存与完整读取时间，不将缺失页面中的资源标为消失。</p>
    </>}
    {canManageAccounts && <form onSubmit={event => { event.preventDefault(); saveAccount() }}>
      <h4>{accountDraft.id ? '编辑本地账号引用' : '登记 Hetzner 账号'}</h4>
      <div className="operations-fields"><label>账号名称<input required maxLength={128} value={accountDraft.name} onChange={event => setAccountDraft({ ...accountDraft, name: event.target.value })} /></label><label>加密云凭据引用编号<input required value={accountDraft.credential_id} autoComplete="off" placeholder="填写凭据中心生成的编号" onChange={event => setAccountDraft({ ...accountDraft, credential_id: event.target.value })} /></label></div>
      <p>先在<a href="#/system/control-center">凭据中心</a>创建用途为云账号的加密凭据，正文将 provider 设为 hetzner，并用 api_token 字段保存官方只读令牌。此处只保存引用编号，不接收或展示令牌。</p>
      <div className="operations-actions"><button className="ui-button" type="submit">验证身份并保存账号引用</button>{accountDraft.id && <button className="ui-button" type="button" onClick={() => { setAccountDraft(emptyAccount); setAccountError('') }}>返回登记新账号</button>}</div>
    </form>}
    {inventory && <>
      <h4>资源缓存</h4>
      <p>面板读取时间 {time(inventory.served_at)}；来源 {inventory.provider.official_source}。完整验证后 {inventory.inventory_stale_after_secs / 3600} 小时内且没有后续读取错误的缓存才标为未过期。</p>
      <p>每次官方读取每页最多 {inventory.limits.page_size} 条、最多 {inventory.limits.max_pages} 页和 {inventory.limits.max_resources} 个资源；达到读取上限时，不用已读取页面推断其余资源的存在状态。</p>
      {inventory.limits.list_truncated && <p className="operations-error" role="status">当前列表已达 {inventory.limits.list_limit} 条显示上限；未显示部分的状态未知，请按账号核对完整读取记录。</p>}
      {!inventory.resources.length && <p>暂无可读取的资源缓存。缓存为空不能确认提供方没有资源。</p>}
      <div className="operations-table-wrap"><table><thead><tr><th>资源／账号</th><th>缓存状态与地址</th><th>机型与数据中心</th><th>证据时间</th><th>关联与历史</th></tr></thead><tbody>{inventory.resources.map(value => <tr key={value.id}>
        <td>{value.name}<small>{value.account_name} · 云资源编号 {value.cloud_id}</small>{value.account_archived && <small>提供方账号已在本地归档</small>}</td>
        <td>{presenceNames[value.presence]}<small>{value.stale ? '缓存已过期或缺少完整验证证据' : '缓存未过期'}</small><small>最近缓存的运行状态：{value.snapshot ? statusNames[value.snapshot.status] ?? '其他状态' : '未知'}</small><small>IPv4：{value.snapshot?.ipv4 ?? '未观测'}</small><small>IPv6：{value.snapshot?.ipv6 ?? '未观测'}</small>{value.error_code && <small>{describeError(value.error_code)}</small>}{value.presence === 'absent' && <small>完整清单未发现该资源；这不单独证明资源已删除。</small>}</td>
        <td>{value.snapshot ? <>{value.snapshot.server_type.name}<small>核心数 {value.snapshot.server_type.cores ?? '未知'} · 内存 {value.snapshot.server_type.memory_gb ?? '未知'} GB · 磁盘 {value.snapshot.server_type.disk_gb ?? '未知'} GB</small><small>架构 {value.snapshot.server_type.architecture ?? '未知'}</small><small>{value.snapshot.datacenter.name} · {value.snapshot.location.name ?? '地区未知'} · {value.snapshot.location.city ?? '城市未知'} · {value.snapshot.location.country ?? '国家未知'}</small></> : '尚无机型观测'}</td>
        <td>最后发现 {time(value.last_seen_at)}<small>完整验证 {time(value.verified_at)}</small><small>最近尝试 {time(value.last_attempt_at)}</small></td>
        <td>{value.link?.server_id !== null && value.link?.server_id !== undefined ? <small>关联服务器 {servers.find(server => server.id === value.link?.server_id)?.name ?? value.link.server_id}</small> : <small>独立云资源</small>}{value.link?.notes && <small>{value.link.notes}</small>}{canEditLinks && <button className="ui-button" type="button" onClick={() => chooseResource(value)}>编辑本地关联与备注</button>}<button className="ui-button" type="button" onClick={() => run(async () => { const entries = await api<History[]>(`/api/operations/cloud/hetzner/resources/${value.id}/history`); setHistoryResource(value); setHistory(entries) })}>查看来源与变化历史</button><details><summary>官方缓存原始字段</summary><pre>{JSON.stringify(value.snapshot, null, 2)}</pre></details></td>
      </tr>)}</tbody></table></div>
    </>}
    {resource && canEditLinks && <div className="operations-review">
      <h4>{resource.name} · 本地资产关联</h4>
      <p>保存只改变面板的关联与备注，不向 Hetzner 修改服务器。保存时重新核对原关联和新目标的授权。</p>
      {canChooseServers ? <label>关联服务器<select value={serverId} onChange={event => setServerId(event.target.value)}><option value="">独立云资源</option>{serverId && !servers.some(server => server.id === Number(serverId)) && <option value={serverId}>已关联服务器 {serverId}</option>}{servers.map(server => <option key={server.id} value={server.id}>{server.name}</option>)}</select></label> : <p>缺少服务器列表读取授权，保留现有关联：{serverId ? `服务器 ${serverId}` : '独立云资源'}。</p>}
      <label>本地备注<textarea maxLength={4096} value={notes} onChange={event => setNotes(event.target.value)} /></label>
      {linkError && <p className="operations-error" role="alert">{linkError}</p>}
      <div className="operations-actions"><button className="ui-button" type="button" onClick={saveLink}>验证身份并保存本地关联</button><button className="ui-button" type="button" onClick={() => setResource(null)}>关闭编辑</button></div>
    </div>}
    {historyResource && <details open><summary>{historyResource.name} · 来源与变化历史</summary>{!history.length && <p>暂无历史记录。</p>}{history.map(entry => <div key={entry.id}><p>{time(entry.observed_at)} · {presenceNames[entry.presence]} · 来源 {entry.source}<small>读取编号：{entry.refresh_id}</small></p><pre>{JSON.stringify({ changes: entry.changes, snapshot: entry.snapshot }, null, 2)}</pre></div>)}</details>}
  </section>
}
