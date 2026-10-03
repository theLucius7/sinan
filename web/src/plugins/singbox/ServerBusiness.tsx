import { Badge, Empty, ErrorNotice, Icon, Loading } from '../../components'
import { navigate, time } from '../../format'
import { resourceWriteError, useResource } from '../../hooks'
import type { Deployment, Node, PluginServer, Server } from '../../types'
import { installationView, sourceLabel } from './Settings'
import RuntimeOperations from './RuntimeOperations'

export default function ServerBusiness({ server }: { server: Server }) {
  const metadata = useResource<PluginServer>(`/api/plugins/sing-box/servers/${server.id}`)
  const enabled = metadata.data?.enabled === true
  const deployment = useResource<Deployment>(enabled ? `/api/plugins/sing-box/servers/${server.id}/deployments` : null)
  const nodes = useResource<Node[]>(enabled ? '/api/plugins/sing-box/nodes' : null)
  const status = deployment.data?.status
  const refresh = () => { metadata.reload(); deployment.reload(); nodes.reload() }
  if (metadata.error) return <ErrorNotice message={metadata.error} retry={metadata.reload} />
  if (!enabled) return null
  const installation = installationView(metadata.data!)
  return <div data-plugin="sing-box"><div className="notice"><div><strong>sing-box 插件</strong> <Badge tone={installation.tone}>{installation.label}</Badge><p>{installation.reason}</p><p>{sourceLabel(metadata.data?.source)}{server.static_info.runtime_version && ` · 运行时 ${server.static_info.runtime_version}`}</p><div className="row-actions"><a className="text-button" href={`#/plugins/sing-box/nodes?server=${server.id}`}>创建代理节点</a><a className="text-button" href="#/plugins/sing-box/users">管理代理用户</a><a className="text-button" href="#/plugins/sing-box/nodes?kind=chains">创建链路</a></div></div></div>
    <ErrorNotice message={deployment.error || nodes.error} retry={refresh} />
<section className="panel"><div className="panel-heading"><h2>配置部署</h2>{status && <Badge tone={status.healthy ? 'good' : status.applied_rev ? 'bad' : 'warm'}>{status.healthy ? '当前配置健康' : status.applied_rev ? '健康检查未通过' : '等待应用'}</Badge>}</div>{deployment.loading && !deployment.data ? <Loading /> : !status ? <Empty icon="nodes" title="还没有发布记录" description="启用后先安装空运行时；新增有效节点须在下方运维入口采集并确认完整预检。尚无运行时账号时可明确首次安装空运行时，安装回执后再重新预检。" /> : <div className="panel-body"><div className="revision-grid"><div><span>目标版本</span><strong><small>版本</small> {status.target_rev}</strong></div><Icon name="arrow" /><div><span>已应用版本</span><strong><small>版本</small> {status.applied_rev || '—'}</strong></div></div>{status.last_error && <div className="notice notice-error"><div><strong>最近一次部署失败</strong><p className="break-all">{status.last_error}</p>{status.healthy && <p>旧配置仍健康，节点继续使用上次成功应用的版本。</p>}</div></div>}{status.target_rev > status.applied_rev && !status.last_error && <div className="notice">正在等待设备应用最新配置。设备离线时会在重连后继续。</div>}<div className="detail-caption">最后更新 {time(status.updated_at)}</div></div>}</section>
    <section className="panel"><div className="panel-body"><RuntimeOperations serverId={server.id} status={status} deploymentError={() => resourceWriteError(metadata, deployment)} getStatus={() => deployment.getCurrent()?.status} /></div></section>
    <section className="panel"><div className="panel-heading"><h2>部署历史</h2><span className="subtle">最近 6 次发布</span></div>{deployment.data?.history.length ? <div className="table-wrap"><table><thead><tr><th>版本</th><th>模块</th><th>配置包摘要</th><th>发布时间</th></tr></thead><tbody>{deployment.data.history.slice(0, 6).map(item => <tr key={item.rev}><td><strong>版本 {item.rev}</strong>{item.rev === status?.applied_rev && <span className="inline-tag">已应用</span>}</td><td>代理运行时</td><td><code title={item.bundle_sha256}>{item.bundle_sha256.slice(0, 16)}…</code></td><td>{time(item.created_at)}</td></tr>)}</tbody></table></div> : <div className="inline-empty">还没有发布记录。</div>}</section>
    <section className="panel"><div className="panel-heading"><h2>此服务器的节点</h2><button className="text-button" onClick={() => navigate(`/plugins/sing-box/nodes?server=${server.id}`)}>管理节点 <Icon name="arrow" size={14} /></button></div><div className="node-chips">{nodes.data?.filter(node => node.server_id === server.id).map(node => <span key={node.id}><Icon name="nodes" size={16} /><strong>{node.name}</strong><code>:{node.port}</code></span>)}{!nodes.data?.some(node => node.server_id === server.id) && <p className="subtle">尚未创建节点。</p>}</div></section>
  </div>
}
