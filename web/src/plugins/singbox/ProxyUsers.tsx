import { useEffect, useRef, useState } from 'react'
import UserEntitlements from './UserEntitlements'
import ExternalUserAccess from './ExternalUserAccess'
import UserPasskeyAccess from './UserPasskeyAccess'
import UserDiagnostics from './UserDiagnostics'
import BatchProxyAssignments from './BatchProxyAssignments'
import SubscriptionDialog from './SubscriptionDialog'
import type { SubscriptionFormat } from './SubscriptionDialog'
import type { ProxyResource } from './resourceTypes'
import { api } from '../../api'
import { Badge, Confirm, Empty, ErrorNotice, Field, FormDialog, Icon, Loading, Modal, PageHeader, Refresh, Stat } from '../../components'
import { bytes, totalBytes } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import type { Access, Node, Usage, ProxyUser } from '../../types'
import type { Entitlement } from './groupTypes'

export default function ProxyUsers() {
  const users = useResource<ProxyUser[]>('/api/plugins/sing-box/users')
  const nodes = useResource<Node[]>('/api/plugins/sing-box/nodes')
  const resources = useResource<ProxyResource[]>('/api/plugins/sing-box/proxy-resources')
  const usage = useResource<Usage>('/api/plugins/sing-box/usage')
  const action = useAction()
  const [selected, setSelected] = useState<number | null>(null)
  const selectedRef = useRef<number | null>(null)
  const selectUser = (id: number | null) => { selectedRef.current = id; setSelected(id) }
  const [editor, setEditor] = useState<ProxyUser | 'new' | null>(null)
  const [deleting, setDeleting] = useState<ProxyUser | null>(null)
  const [subscription, setSubscription] = useState<ProxyUser | null>(null)
  const [resetting, setResetting] = useState<ProxyUser | null>(null)
  const [format, setFormat] = useState<SubscriptionFormat>('singbox')
  const [notice, setNotice] = useState('')
  const [search, setSearch] = useState('')
  const [refreshRevision, setRefreshRevision] = useState(0)
  useEffect(() => {
    if (users.data && selectedRef.current === null) selectUser(users.data[0]?.id ?? null)
  }, [users.data])
  const accesses = useResource<Access[]>(selected ? `/api/plugins/sing-box/users/${selected}/accesses` : null)
  const entitlement = useResource<Entitlement>(selected ? `/api/plugins/sing-box/users/${selected}/entitlement` : null)
  const selectedUsage = useResource<Usage>(selected ? `/api/plugins/sing-box/usage?user_id=${selected}` : null)
  const user = users.data?.find(user => user.id === selected)
  const record = usage.data?.by_user.find(record => record.user_id === selected)
  const refresh = () => { users.reload(); nodes.reload(); resources.reload(); usage.reload(); accesses.reload(); entitlement.reload(); selectedUsage.reload(); setRefreshRevision(value => value + 1) }
  const userError = (id?: number) => {
    if (selected !== selectedRef.current) return '当前选择的代理用户已改变，请等待相关信息刷新后再操作；当前草稿已保留。'
    if (id !== undefined && users.isCurrent() && !users.getCurrent()?.some(value => value.id === id)) return '此代理用户已不存在，请重新选择；当前草稿已保留。'
    const stale = resourceWriteError(users, nodes, resources, ...(selected ? [accesses, entitlement] : []))
    if (stale) return stale
    if (id !== undefined && id !== selectedRef.current) return '当前选择的代理用户已改变，请关闭对话框后重新操作；当前草稿已保留。'
    return ''
  }
  const editorError = editor ? userError(editor === 'new' ? undefined : editor.id) : ''
  const deletingError = deleting ? userError(deleting.id) : ''
  const resettingError = resetting ? userError(resetting.id) : ''
  const edit = (value: ProxyUser | 'new') => { if (userError(value === 'new' ? undefined : value.id)) return; action.clearError(); setEditor(value) }
  const submit = (form: FormData) => {
    if (!editor || userError(editor === 'new' ? undefined : editor.id)) return
    void action.run(() => api<ProxyUser>(editor === 'new' ? '/api/plugins/sing-box/users' : `/api/plugins/sing-box/users/${editor?.id}`, editor === 'new' ? 'POST' : 'PATCH', { name: String(form.get('name')).trim() }), value => { setEditor(null); selectUser(value.id); users.reload() })
  }
  const grant = (node: Node, checked: boolean) => {
    if (!selected || userError(selected) || !nodes.getCurrent()?.some(value => value.id === node.id) || !resources.getCurrent()?.some(value => value.kind === 'direct' && value.id === node.id)) return
    setNotice('')
    void action.run(() => checked ? api(`/api/plugins/sing-box/users/${selected}/accesses`, 'POST', { node_id: node.id }) : api(`/api/plugins/sing-box/users/${selected}/accesses/${node.id}`, 'DELETE'), () => { accesses.reload(); setNotice(checked ? '授权已保存，设备应用新配置后会出现在订阅中。' : '授权已撤销，已从订阅移除；运行时将在新配置应用后更新。') })
  }
  const visible = users.data?.filter(user => user.name.toLocaleLowerCase().includes(search.toLocaleLowerCase())) ?? []
  return <>
    <PageHeader eyebrow="访问管理" title="代理用户" description="分别为代理用户分配策略组和套餐，管理订阅，并查看实际代理流量。"><Refresh onClick={refresh} /><button className="button button-primary" disabled={Boolean(userError())} onClick={() => edit('new')}><Icon name="plus" size={18} />创建代理用户</button></PageHeader>
    <div className="stats-grid"><Stat icon="users" label="代理用户总数" value={users.data?.length ?? '—'} note="每个代理用户拥有独立订阅" /><Stat icon="up" label="累计上传" value={usage.data ? bytes(usage.data.uplink) : '—'} note="认证端实际统计的上传流量" /><Stat icon="down" label="累计下载" value={usage.data ? bytes(usage.data.downlink) : '—'} note="含已删除代理用户的历史用量" /></div>
    {users.data?.length ? <BatchProxyAssignments users={users.data} userError={() => userError()} onChanged={refresh} /> : null}
    <ErrorNotice message={users.error || nodes.error || resources.error || usage.error} retry={refresh} /><ErrorNotice message={users.ready && selected && !user ? `代理用户 #${selected} 已不存在，请从列表重新选择。原选择没有自动切换。` : undefined} />{users.ready && selected && !user && <button className="button button-secondary button-small" disabled={action.busy} onClick={() => { if (users.isCurrent() && !users.getCurrent()?.some(value => value.id === selectedRef.current)) selectUser(null) }}>清除已删除的用户选择</button>}
    {users.loading && !users.data ? <section className="panel"><Loading /></section> : !users.data?.length ? <section className="panel"><Empty icon="users" title="创建代理用户，开始分配节点" description="每个代理用户在每个节点上的凭据相互独立，流量按代理用户和节点统计。"><button className="button button-primary" disabled={Boolean(userError())} onClick={() => edit('new')}><Icon name="plus" size={17} />创建代理用户</button></Empty></section> : <div className="users-layout"><section className="panel users-list"><div className="panel-heading"><h2>代理用户列表 <span className="count">{users.data.length}</span></h2></div><div className="search-box"><input aria-label="搜索代理用户" placeholder="搜索代理用户名称…" value={search} onChange={event => setSearch(event.target.value)} /></div><div className="user-roster">{visible.map(entry => { const total = usage.data?.by_user.find(record => record.user_id === entry.id); return <button key={entry.id} className={`user-row ${selected === entry.id ? 'selected' : ''}`} onClick={() => { selectUser(entry.id); setNotice(''); action.clearError() }} disabled={action.busy} aria-pressed={selected === entry.id}><span className="avatar">{entry.name.slice(0, 1)}</span><span><strong>{entry.name}</strong><small>{total ? bytes(totalBytes(total.uplink, total.downlink)) : usage.data ? '尚无流量记录' : '流量加载中…'}</small></span><Icon name="arrow" size={15} /></button> })}{!visible.length && <p className="inline-empty">没有匹配的代理用户。</p>}</div></section><div className="user-content">{user ? <><section className="panel"><div className="user-heading"><div className="entity"><span className="avatar avatar-large">{user.name.slice(0, 1)}</span><div><h2>{user.name}</h2><span className="subtle">代理用户 #{user.id}</span></div></div><div className="row-actions"><button className="text-button" disabled={Boolean(userError(user.id))} onClick={() => edit(user)}>编辑</button><button className="text-button danger-text" disabled={Boolean(userError(user.id))} onClick={() => { if (userError(user.id)) return; action.clearError(); setDeleting(user) }}>删除</button></div></div><div className="user-usage"><div><span>上传</span><strong>{record ? bytes(record.uplink) : usage.data ? '0 B' : '暂无数据'}</strong></div><div><span>下载</span><strong>{record ? bytes(record.downlink) : usage.data ? '0 B' : '暂无数据'}</strong></div><div><span>已授权节点</span><strong>{accesses.data?.length ?? '—'}</strong></div></div><div className="subscription-row"><div><strong>代理用户专属订阅</strong><p>仅包含已应用且健康的授权节点。</p></div><button className="button button-primary button-small" onClick={() => { setFormat('singbox'); setSubscription(user) }}><Icon name="copy" size={15} />订阅链接</button></div></section><UserEntitlements key={user.id} id={user.id} entitlement={entitlement} userError={() => userError(user.id)} refreshRevision={refreshRevision} onChange={refresh} /><section className="panel"><div className="panel-heading"><h2>单独节点授权</h2><span className="subtle">更改后自动发布</span></div><div className="panel-body"><ErrorNotice message={accesses.error || entitlement.error || userError(selected ?? undefined) || (!editor && !deleting && !resetting ? action.error : '')} retry={accesses.error ? accesses.reload : undefined} />{notice && <div className="notice notice-success" role="status">{notice}</div>}{accesses.loading && !accesses.data ? <Loading /> : !nodes.data?.length ? <Empty icon="nodes" title="还没有可授权的节点" description="先创建节点，再为代理用户开启访问权限。"><a className="button button-secondary" href="#/plugins/sing-box/nodes">前往节点</a></Empty> : <div className="grant-list">{nodes.data.filter(node => resources.data?.some(resource => resource.kind === 'direct' && resource.id === node.id)).map(node => { const access = accesses.data?.find(access => access.node_id === node.id); return <label className="grant-row" key={node.id}><span className="entity-icon"><Icon name="nodes" size={18} /></span><span className="grant-info"><strong>{node.name}</strong><small>{node.public_host}:{node.port}</small></span>{access && <Badge tone="good">{access.direct_grant ? '单独授权' : '来自策略组'}</Badge>}<input className="switch-input" type="checkbox" checked={Boolean(access?.direct_grant)} disabled={action.busy || Boolean(userError(user.id))} onChange={event => grant(node, event.target.checked)} aria-label={`授权 ${node.name}`} /><span className="switch" aria-hidden="true" /></label> })}</div>}<p className="helper">此开关只管理单独授权，不取消策略组授予的权限。只有全部授权来源移除后才撤销凭据；再次授权需要更新订阅。链路只能通过策略组分配。设备离线时等待重连应用。</p></div></section><section className="panel"><div className="panel-heading"><h2>该代理用户的节点流量</h2><span className="subtle">包含历史记录</span></div><ErrorNotice message={selectedUsage.error} retry={selectedUsage.reload} />{selectedUsage.loading && !selectedUsage.data ? <Loading /> : selectedUsage.data?.by_node.length ? <div className="table-wrap"><table><thead><tr><th>节点</th><th>上传</th><th>下载</th><th>合计</th></tr></thead><tbody>{selectedUsage.data.by_node.map(record => <tr key={record.node_id}><td>{record.name}{record.deleted && <span className="inline-tag">已删除</span>}</td><td>{bytes(record.uplink)}</td><td>{bytes(record.downlink)}</td><td>{bytes(totalBytes(record.uplink, record.downlink))}</td></tr>)}</tbody></table></div> : <div className="inline-empty">此代理用户尚无节点流量记录。使用代理后，通常在 1 至 2 分钟内更新。</div>}</section></> : <section className="panel"><div className="panel-body"><ErrorNotice message={selected ? `代理用户 #${selected} 已不存在，请从列表重新选择。原选择没有自动切换。` : undefined} /></div></section>}</div></div>}
    {selected !== null && <UserPasskeyAccess key={`portal-${selected}`} id={selected} userError={() => userError(selected)} refreshRevision={refreshRevision} />}
    {selected !== null && <UserDiagnostics key={`diagnosis-${selected}`} userId={selected} userError={() => userError(selected)} onChanged={refresh} />}
    {selected !== null && <ExternalUserAccess key="external-selected" userId={selected} userError={() => userError(selected)} refreshRevision={refreshRevision} onChanged={refresh} />}
    {usage.data?.by_user.some(record => record.deleted) && <section className="panel"><div className="panel-heading"><h2>历史代理用户流量</h2><span className="subtle">已删除代理用户的数据仍保留</span></div><div className="table-wrap"><table><thead><tr><th>代理用户</th><th>上传</th><th>下载</th></tr></thead><tbody>{usage.data.by_user.filter(record => record.deleted).map(record => <tr key={record.user_id}><td>{record.name} <span className="inline-tag">已删除</span></td><td>{bytes(record.uplink)}</td><td>{bytes(record.downlink)}</td></tr>)}</tbody></table></div></section>}
    {editor && <FormDialog title={editor === 'new' ? '创建代理用户' : '编辑代理用户'} onClose={() => setEditor(null)} onSubmit={submit} busy={action.busy} submitDisabled={Boolean(editorError)} error={editorError || action.error} submitLabel={editor === 'new' ? '创建代理用户' : '保存修改'}><Field label="代理用户名称"><input name="name" required maxLength={128} defaultValue={editor === 'new' ? '' : editor.name} placeholder="为使用者设置一个名称" autoComplete="off" /></Field></FormDialog>}
    {deleting && <Confirm title={`删除「${deleting.name}」？`} busy={action.busy} confirmDisabled={Boolean(deletingError)} error={deletingError || action.error} onClose={() => setDeleting(null)} onConfirm={() => { if (userError(deleting.id)) return; void action.run(() => api(`/api/plugins/sing-box/users/${deleting.id}`, 'DELETE'), () => { setDeleting(null); selectUser(null); refresh() }) }}>此代理用户的订阅链接将失效，全部节点授权会被撤销。历史用量保留，受管设备应用新配置后停止旧授权；已下载的外部凭据由提供方控制。</Confirm>}
    {resetting && <Modal title={`重置「${resetting.name}」的订阅链接？`} busy={action.busy} onClose={() => setResetting(null)}><div className="modal-body"><ErrorNotice message={resettingError || action.error} /><p className="confirm-copy">旧链接将立即失效，代理用户需要在客户端换成新链接。现有节点连接凭据和授权保持不变，已下载的配置仍可使用。</p></div><footer><button className="button button-secondary" disabled={action.busy} onClick={() => setResetting(null)}>取消</button><button className="button button-danger" disabled={action.busy || Boolean(resettingError)} onClick={() => { if (userError(resetting.id)) return; void action.run(() => api<ProxyUser>(`/api/plugins/sing-box/users/${resetting.id}/subscription/reset`, 'POST'), value => { setResetting(null); setSubscription(value); users.reload(); setNotice('订阅链接已重置，请将新链接提供给代理用户。') }) }}>{action.busy ? '正在重置…' : '确认重置'}</button></footer></Modal>}
    {subscription && <SubscriptionDialog user={subscription} format={format} onFormatChange={setFormat} onClose={() => setSubscription(null)} onReset={() => { if (userError(subscription.id)) return; action.clearError(); setResetting(subscription); setSubscription(null) }} />}
  </>
}
