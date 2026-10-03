import { useEffect, useState } from 'react'
import { api } from '../../api'
import { Badge, ErrorNotice, Field, Loading, Refresh } from '../../components'
import { bytes, time } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import OperationReview from './OperationReview'
import type { WorkflowOperation } from './OperationReview'

type Diagnosis = {
  account: { name: string; portal_created: boolean; keys: number; active_sessions: number; activation_expires_at: number | null }
  subscription: { status: string; message: string; granted_nodes: number; ready_managed_nodes: number; ready_external_nodes: number }
  permissions: { node_id: number; name: string; server_id: number; enabled: boolean; direct_grant: boolean; effective: boolean; policy_groups: { id: number; name: string; chain_id: number | null }[]; deployment: { target_revision: number | null; applied_revision: number | null; healthy: boolean | null; pending: boolean; last_error: string | null } }[]
  ledger: { server_id: number; epoch: string; sequence: string; node_id: number; period_start: number; period_end: number; uplink: string; downlink: string; in_current_cycle: boolean | null; received_at: number | null; replay_count: string; delivery_delay_seconds: number | null }[]
  rotations: { id: string; server_id: number; node_ids: number[]; state: string; requested_at: number; applied_revision: number | null; old_downloaded_credentials_revoked: boolean }[]
  events: { id: number; action: string; created_at: number; administrator_id: number | null }[]
  limitations: Record<string, { available: boolean; reason: string }>
}
type Template = { template: { revision: number; definition: unknown } | null; limitations: string; definition_redacted: boolean; credential_access_reason: string }
const auditNames: Record<string, string> = { subscription_fetch: '获取订阅', security_subscription_reset: '重置订阅地址', security_subscription_credentials_read: '再验证后读取连接配置', security_subscription_addresses_read: '再验证后读取订阅地址', security_node_credentials_read: '再验证后读取节点连接身份', security_client_template_read: '再验证后读取完整客户端模板', client_template_update: '修改客户端模板', security_portal_login: 'Passkey 登录', security_portal_login_failed: 'Passkey 验证失败', security_portal_logout: '主动退出会话', security_portal_key_register: '登记 Passkey', security_portal_key_remove: '移除 Passkey并撤销其他会话', security_portal_invitation: '生成自助入口邀请' }

export default function UserDiagnostics({ userId, userError, onChanged }: { userId: number; userError: () => string; onChanged: () => void }) {
  const resource = useResource<Diagnosis>(`/api/plugins/sing-box/users/${userId}/diagnosis`)
  const template = useResource<Template>(`/api/plugins/sing-box/users/${userId}/client-template`)
  const action = useAction()
  const [days, setDays] = useState('30')
  const [rotationNodes, setRotationNodes] = useState<number[]>([])
  const [operation, setOperation] = useState<WorkflowOperation | null>(null)
  const [definition, setDefinition] = useState('')
  const [draftDirty, setDraftDirty] = useState(false)
  const [revealedRevision, setRevealedRevision] = useState<number | null>(null)
  const [client, setClient] = useState('singbox')
  const [version, setVersion] = useState('1.14.2')
  const [compatibility, setCompatibility] = useState<{ available: boolean; reason: string; runtime_validation: boolean }>()
  const [notice, setNotice] = useState('')
  useEffect(() => { if (!draftDirty && template.data) setDefinition(JSON.stringify(template.data.template?.definition ?? { selection_groups: [], dns: null, route: null }, null, 2)) }, [template.data, draftDirty])
  const disabled = action.busy || Boolean(userError() || resourceWriteError(resource))
  const e = resource.data
  const changed = () => { setOperation(null); resource.reload(); onChanged(); setNotice('变更已保存，请按设备确认状态核对实际生效结果。') }
  const saveTemplate = () => {
    if (userError() || resourceWriteError(template) || (template.data?.definition_redacted && revealedRevision === null)) return
    void action.run(async () => {
      let parsed: unknown
      try { parsed = JSON.parse(definition) } catch { throw new Error('客户端模板 JSON 格式无效；草稿保留。') }
      return api(`/api/plugins/sing-box/users/${userId}/client-template`, 'PUT', { client: 'singbox', client_version: '1.14.2', expected_revision: revealedRevision ?? template.getCurrent()?.template?.revision ?? 0, definition: parsed })
    }, () => { setDraftDirty(false); setRevealedRevision(null); template.reload(); resource.reload(); setNotice('模板已保存，后续完整 JSON 订阅会使用模板。尚未在实际客户端验证。') })
  }
  return <section className="panel"><div className="panel-heading"><h2>用户诊断与安全操作</h2><Refresh onClick={() => { resource.reload(); template.reload() }} /></div><div className="panel-body">
    <ErrorNotice message={resource.error || template.error || action.error || userError()} retry={resource.reload} />{notice && <p className="notice notice-success" role="status">{notice}</p>}
    {!e ? <Loading /> : <>
      <p>{e.account.name} · {e.account.portal_created ? `独立自助账号已建立，Passkey ${e.account.keys} 把，当前有效会话 ${e.account.active_sessions} 个` : '独立自助账号尚未建立'}{e.account.activation_expires_at && <small>邀请到期 {time(e.account.activation_expires_at)}</small>}</p>
      <p><Badge tone={e.subscription.status === 'ready' ? 'good' : 'warm'}>{e.subscription.status === 'ready' ? '订阅可生成' : '订阅不可用'}</Badge> {e.subscription.message}</p>
      <p>授权 {e.subscription.granted_nodes} 项；当前可订阅受管节点 {e.subscription.ready_managed_nodes} 个，外部节点 {e.subscription.ready_external_nodes} 个。</p>
      <h3>每项有效权限的来源</h3><div className="table-wrap"><table><thead><tr><th>节点</th><th>授权来源</th><th>套餐与部署</th><th>轮换选择</th></tr></thead><tbody>{e.permissions.map(permission => <tr key={permission.node_id}><td>{permission.name}<small>服务器 #{permission.server_id}</small></td><td>{permission.direct_grant && <span>单独授权；</span>}{permission.policy_groups.map(group => <span key={`${group.id}-${group.chain_id}`}>{group.name}{group.chain_id ? `（链路 #${group.chain_id}）` : ''}；</span>)}</td><td>{permission.effective ? '套餐允许' : '套餐阻止'} · {permission.enabled ? '启用' : '停用'}<small>目标 {permission.deployment.target_revision ?? '—'} / 应用 {permission.deployment.applied_revision ?? '—'}；{permission.deployment.pending ? '待发布' : permission.deployment.healthy ? '健康' : '待确认'}</small>{permission.deployment.last_error && <small>{permission.deployment.last_error}</small>}</td><td><input type="checkbox" aria-label={`轮换 ${permission.name} 的连接凭据`} checked={rotationNodes.includes(permission.node_id)} disabled={disabled} onChange={event => setRotationNodes(values => event.target.checked ? [...values, permission.node_id] : values.filter(value => value !== permission.node_id))} /></td></tr>)}</tbody></table></div>
      <div className="runtime-operation-actions"><Field label="在原到期日后增加天数"><input type="number" min={1} max={36500} value={days} onChange={event => setDays(event.target.value)} /></Field><button className="button button-secondary" disabled={disabled || !Number.isInteger(Number(days)) || Number(days) < 1 || Number(days) > 36500} onClick={() => setOperation({ operation: 'extend_validity', user_id: userId, days: Number(days) })}>预览延期</button><button className="button button-secondary" disabled={disabled} onClick={() => setOperation({ operation: 'reset_quota', user_id: userId })}>预览重置本期额度</button><button className="button button-secondary" disabled={disabled || !rotationNodes.length || rotationNodes.some(id => !e.permissions.some(p => p.node_id === id))} onClick={() => setOperation({ operation: 'rotate_node_credentials', user_id: userId, node_ids: rotationNodes })}>预览轮换节点凭据</button></div>
      <p className="helper">延期只改到期日；额度重置采用明确补偿记录，历史用量与设备计量周期保留。订阅地址重置不会撤销已下载节点凭据。外部凭据需由提供方撤销。</p>
      {e.rotations.length > 0 && <div className="table-wrap"><table><thead><tr><th>轮换时间</th><th>设备与节点</th><th>设备确认</th></tr></thead><tbody>{e.rotations.map(rotation => <tr key={rotation.id}><td>{time(rotation.requested_at)}</td><td>服务器 #{rotation.server_id} · 节点 {rotation.node_ids.join('、')}</td><td>{rotation.state === 'device_confirmed' ? '设备已确认应用，旧下载凭据已从该版本移除' : rotation.state === 'superseded' ? '已被后续凭据变更替代' : rotation.state === 'confirmation_stale' ? '历史确认已过期，当前等待核对' : '等待设备确认'}<small>应用版本 {rotation.applied_revision ?? '—'}；现有连接是否已断开需实际检查</small></td></tr>)}</tbody></table></div>}
      <details><summary>计量批次与账期（最近 200 项）</summary><p>设备 epoch 与套餐账期分别显示；批次按服务器、epoch、序号去重。新批次显示首次接收与重放次数；延迟按设备窗口结束与面板接收时刻计算，需考虑时钟偏差。旧接收时间保持未知。</p><div className="table-wrap"><table><thead><tr><th>计量窗口</th><th>设备批次</th><th>节点</th><th>上传 / 下载</th><th>接收与重放</th><th>当前账期</th></tr></thead><tbody>{e.ledger.map((row, index) => <tr key={`${row.server_id}-${row.epoch}-${row.sequence}-${row.node_id}-${index}`}><td>{time(row.period_start)}<small>{time(row.period_end)}</small></td><td>#{row.server_id} / {row.sequence}<small>{row.epoch}</small></td><td>#{row.node_id}</td><td>{bytes(row.uplink)} / {bytes(row.downlink)}</td><td>{row.received_at ? time(row.received_at) : '旧批次时间未知'}<small>重放 {row.replay_count} 次；延迟 {row.delivery_delay_seconds === null ? '未知' : `${row.delivery_delay_seconds} 秒`}</small></td><td>{row.in_current_cycle === null ? '未设置账期' : row.in_current_cycle ? '是' : '历史账期'}</td></tr>)}</tbody></table></div></details>
      <details><summary>当前能力限制与审计记录</summary>{Object.entries(e.limitations).map(([key, limit]) => <p key={key}>{limit.reason}</p>)}{e.events.map(event => <p key={event.id}>{time(event.created_at)} · {event.administrator_id ? `管理员 #${event.administrator_id}` : event.action.startsWith('security_portal_') ? '用户自助入口' : '订阅客户端'} · {auditNames[event.action] ?? '已记录管理操作'}</p>)}</details>
    </>}
    <details><summary>客户端兼容与完整配置模板</summary><p>{template.data?.limitations}</p><Field label="客户端"><select value={client} onChange={event => { setClient(event.target.value); setCompatibility(undefined) }}><option value="singbox">sing-box</option><option value="other">其他客户端（当前未支持）</option></select></Field><Field label="版本"><input value={version} onChange={event => { setVersion(event.target.value); setCompatibility(undefined) }} /></Field><button className="button button-secondary" disabled={disabled} onClick={() => void action.run(() => api(`/api/plugins/sing-box/users/${userId}/compatibility`, 'POST', { client, version, format: 'singbox' }), value => setCompatibility(value as { available: boolean; reason: string; runtime_validation: boolean }))}>检查协议与字段兼容</button>{compatibility && <p className="notice">{compatibility.available ? '配置可生成' : '当前不可用'}：{compatibility.reason}</p>}
      {template.data?.definition_redacted && revealedRevision === null && <p className="helper">模板敏感字段已脱敏。{template.data.credential_access_reason} <button className="text-button" disabled={action.busy || Boolean(userError())} onClick={() => void action.run(() => api<Template>(`/api/plugins/sing-box/users/${userId}/client-template?reveal=true`), value => { setDefinition(JSON.stringify(value.template?.definition ?? {selection_groups: [], dns: null, route: null}, null, 2)); setRevealedRevision(value.template?.revision ?? 0); setDraftDirty(true) })}>再次验证并读取完整模板</button></p>}
      <Field label="sing-box 1.14.2 模板"><textarea rows={12} value={definition} disabled={Boolean(template.data?.definition_redacted && revealedRevision === null)} onChange={event => { setDraftDirty(true); setDefinition(event.target.value) }} spellCheck={false} /></Field><p className="helper">配置 selection_groups、dns 与 route。选择组成员使用授权出站标签，例如 node-节点编号；保存核对授权引用。订阅生成还会重新核对套餐、部署及当前可用节点，失败保留草稿与原字段。</p><button className="button button-secondary" disabled={action.busy || Boolean(userError() || resourceWriteError(template)) || Boolean(template.data?.definition_redacted && revealedRevision === null)} onClick={saveTemplate}>保存模板并核对授权引用</button>
    </details>
  </div>{operation && <OperationReview request={operation} onClose={() => setOperation(null)} onApplied={changed} />}</section>
}
