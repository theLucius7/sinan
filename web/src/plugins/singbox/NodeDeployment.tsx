import { useState } from 'react'
import { api } from '../../api'
import { Badge, ErrorNotice, Loading, Modal, Refresh } from '../../components'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import type { Deployment, PluginServer } from '../../types'
import RuntimeOperations from './RuntimeOperations'

type Progress = Deployment & { pending: boolean; enabled_nodes: number; authorized_nodes: number }
type Readiness = { ready: boolean; checks: { name: string; passed: boolean; detail: string }[] }

export default function NodeDeployment({ serverId, server, onClose }: { serverId: number; server?: PluginServer; onClose: () => void }) {
  const path = `/api/plugins/sing-box/servers/${serverId}/deployments`
  const resource = useResource<Progress>(path)
  const action = useAction()
  const [check, setCheck] = useState<Readiness | null>(null)
  const current = resource.error ? null : resource.data
  const status = current?.status
  const revisionKnown = status && Number.isSafeInteger(status.target_rev) && status.target_rev > 0 && Number.isSafeInteger(status.applied_rev) && status.applied_rev >= 0
  const failed = status && revisionKnown && status.last_result_rev === status.target_rev && !!status.last_error
  const serverKnown = server?.enabled === true && server.online === true
  const applied = status && revisionKnown && status.applied_rev === status.target_rev && status.healthy === true && !failed && current?.pending === false && serverKnown
  const title = current?.pending ? '目标配置待发布' : failed ? '最新配置应用失败' : applied ? '目标配置已应用' : status && revisionKnown && serverKnown ? '等待设备应用' : current && !status ? '尚未发布配置' : '应用状态待确认'
  return <Modal title={`${server?.name ?? `服务器 #${serverId}`} · 节点部署`} onClose={onClose} wide busy={action.busy}>
    <div className="modal-body node-deployment">
      <ErrorNotice message={resource.error || action.error} retry={resource.reload} />
      {resource.error && <div className="notice"><Badge tone="neutral">应用状态待确认</Badge><span>部署状态读取失败，旧结果不能确认当前配置是否已应用。</span></div>}
      {!current && resource.loading ? <Loading /> : current && <>
        <div className="node-deployment-heading"><Badge tone={failed ? 'bad' : applied ? 'good' : 'warm'}>{title}</Badge><Refresh onClick={resource.reload} /></div>
        <dl className="node-deployment-facts"><div><dt>目标版本</dt><dd>{status?.target_rev ?? '—'}</dd></div><div><dt>已应用版本</dt><dd>{status?.applied_rev || '—'}</dd></div><div><dt>启用 / 有效用户授权节点</dt><dd>{current.enabled_nodes} / {current.authorized_nodes}</dd></div></dl>
        {!!status?.last_error && <div className="notice notice-error"><span>版本 {status.last_result_rev}：{status.last_error}</span></div>}
        <p>每台服务器统一发布完整配置。普通节点没有有效授权或已停用时，等待设备应用新配置后不再监听；链路出口可能凭内部连接凭据监听。设备离线时需等待重连，新配置失败时可能仍运行上一次健康配置。应用状态不表示已验证公网可达或链路连通。</p>
        {current.authorized_nodes === 0 && <p>当前有效用户授权节点数为 0。普通节点需先到<a href="#/plugins/sing-box/users" onClick={onClose}>代理用户</a>分配权限与套餐；仅承担链路出口的服务器仍可能使用内部连接凭据，不需要为出口单独授权用户。</p>}
      </>}
      <div className="node-deployment-heading"><h3>基础安装条件检查</h3><button className="button button-secondary" disabled={action.busy || Boolean(resourceWriteError(resource))} onClick={() => { if (resourceWriteError(resource)) return; setCheck(null); void action.run(() => api<Readiness>(`${path}/check`, 'POST'), setCheck) }}>{action.busy ? '正在检查…' : '检查基础安装条件'}</button></div>
      <p>检查设备接入、在线状态、插件能力和匹配的签名运行时。新增或修改有效普通节点须在下方查看配置差异、采集并确认完整部署预检；最终以 Agent 的应用与健康回报为准。</p>
      {check && <ul className="node-checks">{check.checks.map(item => <li key={item.name}><Badge tone={item.passed ? 'good' : 'warm'}>{item.name}</Badge><span>{item.detail}</span></li>)}</ul>}
      <RuntimeOperations serverId={serverId} status={status} deploymentError={() => resourceWriteError(resource)} getStatus={() => resource.getCurrent()?.status} />
      <div className="node-deployment-links"><a href={`#/servers/${serverId}`} onClick={onClose}>服务器接入与状态</a><a href="#/plugins/catalog" onClick={onClose}>运行时制品</a></div>
    </div><footer><button className="button button-secondary" onClick={onClose} disabled={action.busy}>关闭</button></footer>
  </Modal>
}
