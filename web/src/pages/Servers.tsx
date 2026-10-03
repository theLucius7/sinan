import ServerListView, { defaultServerView } from '../control-center/ServerListView'
import type { ServerView } from '../control-center/ServerListView'
import { Fragment, useState } from 'react'
import { api } from '../api'
import { Badge, Confirm, Empty, ErrorNotice, Icon, Loading, Meter, PageHeader, Refresh, Stat } from '../components'
import { bytes, navigate, percent } from '../format'
import { useAction, useResource } from '../hooks'
import type { Server } from '../types'
import ServerSetup from './ServerSetup'
import ServerEnrollment from './ServerEnrollment'
import ServerEdit from './ServerEdit'
import { assetDate, assetPrice, defaultAssets, expiryState, trafficSize } from '../server-assets'

export default function Servers() {
  const resource = useResource<Server[]>('/api/servers')
  const actor = useResource<{ role: string; capabilities: string[] }>('/api/control-center/me')
  const canWrite = actor.data?.role === 'owner' || Boolean(actor.data?.capabilities.includes('servers:write'))
  const action = useAction()
  const [editor, setEditor] = useState<Server | 'new' | null>(null)
  const [deleting, setDeleting] = useState<Server | null>(null)
  const [installation, setInstallation] = useState<Server | null>(null)
  const [view, setView] = useState<ServerView>(defaultServerView)
  const [selected, setSelected] = useState<number[]>([])
  const [batchResults, setBatchResults] = useState<Array<{ id: number; status: string }>>([])
  const allServers = resource.data ?? []
  const groupKey = (server: Server) => view.groupBy === 'group' ? server.asset_settings?.group_name || '未分组' : view.groupBy === 'region' ? server.asset_settings?.region || '地区未知' : ''
  const servers = allServers.filter(server => {
    const asset = { ...defaultAssets, ...server.asset_settings }
    return (view.online === 'all' || (view.online === 'online' ? server.online : !server.online))
      && (!view.group || asset.group_name === view.group)
      && `${server.name} ${asset.region} ${asset.tags.join(' ')}`.toLocaleLowerCase().includes(view.query.toLocaleLowerCase())
  }).sort((left, right) => groupKey(left).localeCompare(groupKey(right), 'zh-CN') || (view.sort === 'name' ? left.name.localeCompare(right.name, 'zh-CN') : view.sort === 'cpu' ? (right.latest_metrics.cpu_percent ?? -1) - (left.latest_metrics.cpu_percent ?? -1) : view.sort === 'expiry' ? (left.asset_settings?.expires_at ?? Number.MAX_SAFE_INTEGER) - (right.asset_settings?.expires_at ?? Number.MAX_SAFE_INTEGER) : left.id - right.id))
  const column = (key: string) => view.columns.includes(key)
  const availableSelected = selected.filter(id => allServers.some(server => server.id === id))
  const batchLifecycle = (lifecycle: string) => void action.run(async () => {
    const snapshot = [...availableSelected]
    const results: Array<{ id: number; status: string }> = []
    for (const id of snapshot) {
      try { await api(`/api/servers/${id}/fleet/lifecycle`, 'POST', { lifecycle, from: null, until: null, reason: '管理员列表批量操作' }); results.push({ id, status: '已保存' }) }
      catch (error) { results.push({ id, status: error instanceof Error ? error.message : '操作失败' }) }
      setBatchResults([...results])
    }
    resource.reload()
  })
  const edit = (value: Server | 'new') => { action.clearError(); setEditor(value) }
  return <>
    <PageHeader eyebrow="基础设施" title="服务器" description="连接你的服务器，集中查看运行状态与配置部署。"><Refresh onClick={resource.reload} /><button className="button button-primary" disabled={!canWrite} onClick={() => edit('new')}><Icon name="plus" size={18} />添加服务器</button></PageHeader>
    <div className="stats-grid"><Stat icon="server" label="服务器总数" value={resource.data ? servers.length : '—'} note="已添加到面板的服务器" /><Stat icon="activity" label="当前在线" value={resource.data ? servers.filter(server => server.online).length : '—'} note="最近 60 秒内收到设备消息" /><Stat icon="check" label="已发布配置" value={resource.data ? servers.filter(server => server.manifest_rev > 0).length : '—'} note="部署结果可在服务器详情查看" /></div>
    <ServerListView value={view} onChange={setView} groups={[...new Set(allServers.map(server => server.asset_settings?.group_name ?? '').filter(Boolean))]} />
    <div className="control-actions"><span>已选择 {availableSelected.length} 台，当前筛选 {servers.length} 台</span><button disabled={!resource.data || action.busy} onClick={() => setSelected([...new Set([...selected, ...servers.map(server => server.id)])])}>选择当前筛选</button><button onClick={() => setSelected([])}>清空选择</button><button disabled={!canWrite || !availableSelected.length || action.busy || Boolean(resource.error)} onClick={() => batchLifecycle('maintenance')}>进入维护</button><button disabled={!canWrite || !availableSelected.length || action.busy || Boolean(resource.error)} onClick={() => batchLifecycle('draining')}>停止接收新任务</button><button disabled={!canWrite || !availableSelected.length || action.busy || Boolean(resource.error)} onClick={() => batchLifecycle('active')}>恢复接收任务</button></div>
    {batchResults.length > 0 && <section className="notice"><div>{batchResults.map(result => <p key={result.id}>服务器 #{result.id}：{result.status}</p>)}</div></section>}
    <ErrorNotice message={resource.error || action.error || actor.error} retry={resource.reload} />{actor.data && !canWrite && <p className="subtle">当前账号只有服务器读取权限；修改、接入和维护操作需要服务器写入授权。</p>}
    <section className="panel"><div className="panel-heading"><h2>全部服务器 <span className="count">{servers.length}</span></h2><span className="subtle live-label"><span />每 5 秒刷新</span></div>
      {resource.loading && !resource.data ? <Loading /> : !servers.length ? <Empty icon="server" title="从第一台服务器开始" description="添加服务器后，在服务器上执行安装命令，即可自动接入。"><button className="button button-primary" disabled={!canWrite} onClick={() => edit('new')}><Icon name="plus" size={17} />添加服务器</button></Empty> : <div className={`table-wrap ${view.density === 'compact' ? 'control-compact-list' : ''}`}><table><thead><tr><th>选择</th><th>服务器</th><th>状态</th>{column('cpu') && <th>处理器</th>}{column('memory') && <th>内存</th>}{column('cost') && <th>成本 / 到期</th>}{column('traffic') && <th>本期观测 / 额度</th>}{column('version') && <th>设备版本</th>}<th className="align-right">操作</th></tr></thead><tbody>{servers.map((server, index) => {
        const asset = { ...defaultAssets, ...server.asset_settings }, expiry = expiryState(asset)
        const cpu = server.latest_metrics.cpu_percent
        const used = server.latest_metrics.memory_used, total = server.static_info.memory_total
        return <Fragment key={server.id}>{view.groupBy !== 'none' && (index === 0 || groupKey(servers[index - 1]) !== groupKey(server)) && <tr className="server-view-group"><th colSpan={4 + view.columns.length}>{groupKey(server)}</th></tr>}<tr><td><input type="checkbox" aria-label={`选择${server.name}`} checked={selected.includes(server.id)} onChange={event => setSelected(event.target.checked ? [...new Set([...selected, server.id])] : selected.filter(id => id !== server.id))} /></td><td><button className="entity-link" onClick={() => navigate(`/servers/${server.id}`)}><span className="entity-icon"><Icon name="server" size={18} /></span><span><strong>{server.name}</strong><small>{[asset.region, asset.group_name, server.static_info.hostname ?? `服务器 #${server.id}`].filter(Boolean).join(" · ")}{asset.hidden ? " · 展示隐藏" : ""}</small>{asset.tags.length > 0 && <small>{asset.tags.join(" · ")}</small>}</span></button></td><td><Badge tone={server.online ? 'good' : 'neutral'}>{server.online ? '在线' : server.device_public_key ? '离线' : '待接入'}</Badge></td>{column('cpu') && <td><div className="metric-cell"><span>{percent(cpu)}</span>{cpu !== undefined && <Meter value={cpu} />}</div></td>}{column('memory') && <td><div className="metric-cell"><span>{bytes(used)}{used !== undefined && total !== undefined ? <small> / {bytes(total)}</small> : null}</span>{used !== undefined && total ? <Meter value={used / total * 100} /> : null}</div></td>}{column('cost') && <td><span>{assetPrice(asset)}</span><small>{assetDate(asset.expires_at)} · <span className={expiry.tone === "bad" ? "danger-text" : ""}>{expiry.label}</span></small></td>}{column('traffic') && <td><span>{(server.traffic?.observed_from != null || server.traffic?.corrected) ? trafficSize(server.traffic.used) : "等待采样"} / {asset.traffic_limit === "0" ? "未设额度" : trafficSize(asset.traffic_limit)}</span>{server.traffic?.exceeded && <small className="danger-text">额度已用尽</small>}</td>}{column('version') && <td><span className="mono">{server.static_info.agent_version ?? '尚未上报'}</span></td>}<td><div className="row-actions"><button className="text-button" onClick={() => navigate(`/servers/${server.id}`)}>详情</button><button className="text-button" disabled={!canWrite} onClick={() => edit(server)}>编辑</button><button className="text-button danger-text" disabled={!canWrite} onClick={() => { action.clearError(); setDeleting(server) }}>删除</button></div></td></tr></Fragment>
      })}</tbody></table></div>}
    </section>
    <div className="page-footnote"><Icon name="lock" size={14} />设备主动连接面板；面板离线时，已应用的节点配置继续运行。</div>
    {editor === 'new' && <ServerSetup onClose={() => setEditor(null)} onCreated={server => { setEditor(null); setInstallation(server); resource.reload() }} />}
    {editor && editor !== 'new' && <ServerEdit key={editor.id} server={editor} onClose={() => setEditor(null)} onSaved={() => { setEditor(null); resource.reload() }} />}
    {deleting && <Confirm title={`删除「${deleting.name}」？`} busy={action.busy} error={action.error} onClose={() => setDeleting(null)} onConfirm={() => void action.run(() => api(`/api/servers/${deleting.id}`, 'DELETE'), () => { setDeleting(null); resource.reload() })}>此服务器将从面板和订阅中移除，历史流量仍会保留。设备在线时会先停止代理与诊断服务、清除本机凭证，确认后再删除；过程可能需要片刻。设备离线时仅移除面板记录，本地服务仍需手动停用。</Confirm>}
    {installation && <ServerEnrollment key={installation.id} server={installation} created onClose={() => setInstallation(null)} />}
  </>
}
