import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { ErrorNotice } from '../components'
import { resourceWriteError, useAction, useResource } from '../hooks'
import type { ActionRunner, CloudResource } from './types'
import { time } from './types'

type Actor = { admin_id: number; role: string; all_servers: boolean; capabilities: string[]; server_ids: number[] }
type Membership = { current_groups: string[]; managed_groups: string[]; protected_groups: string[]; server_ids: number[]; region: string; instance_id: string; resource_revision: number; account_revision: number }
type Fee = { status: string; reason: string }
type GroupOperation = {
  id: string; resource_id: string; requested_by: number; status: string; snapshot_digest: string; created_at: number; expires_at: number
  before: Membership; target_groups: string[]
  impact: { added: string[]; removed: string[]; baseline_retained: boolean; management_connectivity: string; rules_changed: boolean; fee: Fee }
  steps: { group_id: string; action: 'join' | 'leave'; state: string; request_id?: string | null; error_code?: string | null; observed_groups?: string[] }[]
  observed_at?: number | null; actual_groups?: string[]; error_code?: string | null; original_result?: string | null; reconciliation?: unknown
}
type Groups = Membership & { resource_id: string; observed_at: number; source: string; rules_edit_available: boolean; fee: Fee; operations: GroupOperation[] }
const statuses: Record<string, string> = { preview: '已冻结预览，待确认', running: '官方请求执行中或尚未核对结束', unknown: '官方请求结果未知，后续步骤已停止', succeeded: '官方读取已核对目标组关系', failed: '操作失败', reconciled: '已人工结束，原请求未知结果保留' }
const stepStates: Record<string, string> = { pending: '尚未提交', queued: '等待提交', running: '官方请求执行中', submitting: '官方请求提交中', verified: '官方读取已核对关系', unknown: '官方请求结果未知', succeeded: '官方回执已确认', failed: '官方回执失败', skipped: '未执行', not_submitted: '预检变化，未提交官方变更' }
const groupId = /^sg-[a-z0-9-]{1,77}$/
const evidenceBytes = (value: string) => new TextEncoder().encode(value.trim()).length
const allows = (actor: Actor | undefined, capability: string) => Boolean(actor && !(actor.role === 'viewer' && capability.endsWith(':write')) && (actor.role === 'owner' || actor.capabilities.includes(capability)))

function authorization(actor: Actor | undefined, serverIds: number[], write: boolean): string {
  if (!actor) return '当前管理员授权正在读取或刷新，请读取成功后再操作。'
  if (!actor.all_servers || !allows(actor, 'cloud:read')) return '安全组官方账号读取需要全局云读取授权。'
  if (write && !allows(actor, 'cloud:write')) return actor.role === 'viewer' ? '当前账号为只读角色，可查看官方证据，不能变更安全组。' : '当前账号未获云资源写入授权。'
  if (serverIds.some(id => !actor.all_servers && !actor.server_ids.includes(id))) return '当前账号未获本资源全部关联服务器授权。'
  return ''
}

export default function SecurityGroups({ resources, run, version }: { resources: CloudResource[]; run: ActionRunner; version: number }) {
  const actor = useResource<Actor>('/api/control-center/me')
  const [resourceId, setResourceId] = useState(''), [target, setTarget] = useState<string[]>([]), [extra, setExtra] = useState('')
  const [operationId, setOperationId] = useState(''), [stopped, setStopped] = useState(false), [evidence, setEvidence] = useState(''), [message, setMessage] = useState(''), [submitting, setSubmitting] = useState(false)
  const selected = resources.find(resource => resource.id === resourceId)
  const actorReadReason = authorization(actor.data, selected?.link?.server_id ? [selected.link.server_id] : [], false)
  const groups = useResource<Groups>(selected?.kind === 'ecs' && !actorReadReason ? `/api/operations/cloud/${selected.id}/security-groups` : null, 0)
  const receipt = useResource<GroupOperation>(operationId ? `/api/operations/cloud/security-group-operations/${operationId}` : null)
  const action = useAction()
  const initialResource = useRef('')
  useEffect(() => { if (groups.data && initialResource.current !== groups.data.resource_id) { initialResource.current = groups.data.resource_id; setTarget([...groups.data.current_groups]) } }, [groups.data])
  useEffect(() => { if (selected && !actorReadReason) groups.reload() }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
  const current = receipt.data
  const writeReason = authorization(actor.getCurrent(), groups.data?.server_ids ?? [], true)
  const unavailable = writeReason || resourceWriteError(actor, groups)
  const choices = [...new Set([...(groups.data?.current_groups ?? []), ...target])].sort()
  const protectedGroups = new Set(groups.data?.protected_groups ?? [])
  const targetsValid = target.length > 0 && target.length <= 16 && target.every(id => groupId.test(id)) && [...protectedGroups].every(id => target.includes(id))
  const change = (next: string[]) => { setTarget(next); setOperationId(''); setMessage('') }
  const setResult = (value: GroupOperation) => { setOperationId(value.id); setStopped(false); setEvidence(''); receipt.reload(); groups.reload() }
  const preview = () => void action.run(async () => {
    const snapshot = groups.getCurrent(), principal = actor.getCurrent()
    const denial = authorization(principal, snapshot?.server_ids ?? [], true)
    if (denial || !snapshot || !targetsValid) throw new Error(denial || '请先读取当前官方关系，并选择非空的有效目标；所有受保护基线组必须保留。')
    return api<GroupOperation>(`/api/operations/cloud/${snapshot.resource_id}/security-groups/preview`, 'POST', { target_groups: [...target].sort(), resource_revision: snapshot.resource_revision })
  }, value => { setOperationId(value.id); setMessage('已保存固定预览，尚未提交官方变更。请核对新增、移除、基线与影响后确认。') })
  const confirm = () => {
    const fixed = receipt.getCurrent()
    if (!fixed || unavailable || fixed.status !== 'preview' || fixed.expires_at <= Math.floor(Date.now() / 1000) || fixed.requested_by !== actor.getCurrent()?.admin_id) return
    run(async () => {
      const denial = authorization(actor.getCurrent(), fixed.before.server_ids, true)
      if (denial) throw new Error(denial)
      setSubmitting(true)
      try {
      const value = await api<GroupOperation>(`/api/operations/cloud/security-group-operations/${fixed.id}/confirm`, 'POST', { confirm: true, snapshot_digest: fixed.snapshot_digest })
      setResult(value); setMessage('已取得本次官方执行记录；逐步状态与实际读取结果分别显示。结果未知时不会重复提交。')
      } finally { setSubmitting(false) }
    }, true)
  }
  const reconcile = () => {
    const fixed = receipt.getCurrent(), conclusion = evidence.trim()
    if (!fixed || unavailable || !['unknown', 'running'].includes(fixed.status) || submitting || !stopped || evidenceBytes(conclusion) < 32 || evidenceBytes(conclusion) > 4096 || fixed.requested_by !== actor.getCurrent()?.admin_id) return
    run(async () => {
      const denial = authorization(actor.getCurrent(), fixed.before.server_ids, true)
      if (denial) throw new Error(denial)
      setSubmitting(true)
      try {
      const value = await api<GroupOperation>(`/api/operations/cloud/security-group-operations/${fixed.id}/reconcile`, 'POST', { process_stopped: true, evidence: conclusion })
      setResult(value); setMessage('已请求新的官方读取并记录人工结束结论；原始未知请求和未执行的后续步骤继续保留。')
      } finally { setSubmitting(false) }
    }, true)
  }
  const busy = action.busy || submitting || current?.status === 'running'
  return <section className="operations-card"><h3>阿里云 ECS 安全组成员变更</h3>
    <ErrorNotice message={actor.error || groups.error || receipt.error || action.error} />
    <p>保留原有基线组；只允许移除本流程确认加入且规则未被外部修改的附加组。这里变更实例与组的关联，组内规则编辑暂不可用；保留基线不能保证所有管理连接始终可用。</p>
    {actorReadReason && <p role="status">{actorReadReason}</p>}
    <label>明确选择 ECS 实例<select value={resourceId} disabled={busy} onChange={event => { setResourceId(event.target.value); initialResource.current = ''; setTarget([]); setExtra(''); setOperationId(''); setEvidence(''); setStopped(false); setMessage('') }}><option value="">选择受管云资源</option>{resources.map(resource => <option key={resource.id} value={resource.id} disabled={resource.kind !== 'ecs'}>{resource.name} · {resource.account_name} · {resource.region}{resource.kind !== 'ecs' ? ' · 此资源不支持 ECS 安全组' : ''}</option>)}</select></label>
    {selected && <p>{selected.cloud_id} · 关联服务器 {selected.link?.server_id ?? '独立云资源'}。<button className="ui-button" disabled={Boolean(authorization(actor.getCurrent(), [], false)) || action.busy || selected.kind !== 'ecs'} onClick={() => { if (!authorization(actor.getCurrent(), [], false)) groups.reload() }}>重新读取官方组关系</button></p>}
    {groups.data && <><p>官方证据 {time(groups.data.observed_at)} · {groups.data.source} · 资源版本 {groups.data.resource_revision} / 账号版本 {groups.data.account_revision}。</p><p>费用：{groups.data.fee.status === 'unknown' ? '未知' : groups.data.fee.status}。{groups.data.fee.reason}</p>
      {writeReason && <p role="status">{writeReason}</p>}
      {[...protectedGroups].some(id => !target.includes(id)) && <p role="status">官方基线关系已变化，当前草稿保留；请先明确采用当前组关系，再重新调整目标与预览。<button className="ui-button" disabled={Boolean(unavailable) || busy} onClick={() => { const snapshot = groups.getCurrent(); if (snapshot && !authorization(actor.getCurrent(), snapshot.server_ids, true)) change([...snapshot.current_groups]) }}>采用最新官方组关系作为目标</button></p>}
      <fieldset disabled={Boolean(unavailable) || busy}><legend>目标组关系（保留全部受保护基线）</legend>{choices.map(id => <label key={id}><input type="checkbox" checked={target.includes(id)} disabled={protectedGroups.has(id)} onChange={event => change(event.target.checked ? [...target, id] : target.filter(value => value !== id))} /><span>{id} · {protectedGroups.has(id) ? '受保护基线，必须保留' : groups.data?.managed_groups.includes(id) ? '本流程已确认加入，可预览移除' : '待新增组，官方确认前不视为已加入'}</span></label>)}<div className="operations-fields"><label>新增附加组 ID<input value={extra} onChange={event => setExtra(event.target.value)} placeholder="sg-…（必须为同地区可授权组）" maxLength={80} /></label><button className="ui-button" type="button" disabled={!groupId.test(extra.trim()) || target.includes(extra.trim()) || target.length >= 16} onClick={() => { if (authorization(actor.getCurrent(), groups.data?.server_ids ?? [], true)) return; change([...target, extra.trim()]); setExtra('') }}>加入待预览目标</button></div><button className="ui-button" disabled={!targetsValid || Boolean(unavailable)} onClick={preview}>读取官方条件并冻结变更预览</button></fieldset>
      <h4>原始操作、请求与核对历史</h4>{groups.data.operations.length ? groups.data.operations.map(operation => <p key={operation.id}>{time(operation.created_at)} · {statuses[operation.status] ?? operation.status} <button className="ui-button" disabled={action.busy} onClick={() => { setOperationId(operation.id); setStopped(false); setEvidence('') }}>查看固定预览与回执</button></p>) : <p>暂无安全组变更记录。</p>}
    </>}
    {submitting && <p role="status">确认请求已发送，等待官方流程返回；请勿重复提交。</p>}{message && <p role="status">{message}</p>}
    {current && <div className="operations-review"><h4>{statuses[current.status] ?? current.status}</h4><p>操作 {current.id} · 快照 <code>{current.snapshot_digest}</code> · 有效至 {time(current.expires_at)}。</p><p>实例 {current.before.instance_id} · {current.before.region} · 固定关联服务器 {current.before.server_ids.join('、') || '无'}。</p><p>新增：{current.impact.added.join('、') || '无'}；移除：{current.impact.removed.join('、') || '无'}；受保护基线：{current.before.protected_groups.join('、') || '无'}。</p><p>组内规则不修改。保留原基线，但管理连接仍须实际观测；费用{current.impact.fee.status === 'unknown' ? '未知' : current.impact.fee.status}：{current.impact.fee.reason}</p>
      <div className="operations-actions"><button className="ui-button" disabled={action.busy} onClick={receipt.reload}>读取已保存的官方回执</button>{current.status === 'preview' && <button className="ui-button" disabled={Boolean(unavailable) || busy || !receipt.fresh || current.expires_at <= Math.floor(Date.now() / 1000) || current.requested_by !== actor.getCurrent()?.admin_id} onClick={confirm}>验证身份并确认固定快照</button>}</div>
      {current.requested_by !== actor.data?.admin_id && <p>本记录由另一管理员创建；确认或人工结束需要原创建者。</p>}
      {current.error_code && <p role="alert">官方错误：{current.error_code}</p>}
      {current.steps.length > 0 && <div className="operations-table-wrap"><table><thead><tr><th>附加组</th><th>动作</th><th>真实阶段</th><th>官方请求证据</th></tr></thead><tbody>{current.steps.map((step, index) => <tr key={`${step.group_id}-${index}`}><td>{step.group_id}</td><td>{step.action === 'join' ? '加入' : '退出'}</td><td>{stepStates[step.state] ?? step.state}</td><td>{step.request_id || '尚无官方请求编号'}{step.error_code && <small>{step.error_code}</small>}{step.observed_groups && <small>官方观测 {step.observed_groups.join('、') || '无组'}</small>}</td></tr>)}</tbody></table></div>}
      {current.reconciliation != null && <details><summary>新的官方只读证据与人工结论（原请求结果仍未知）</summary><pre>{JSON.stringify(current.reconciliation, null, 2)}</pre></details>}
      {current.actual_groups && <p>最新实际组关系：{current.actual_groups.join('、') || '无'} · {time(current.observed_at)}。</p>}
      {['unknown', 'running'].includes(current.status) && <><p>禁止重复确认、自动重试与盲目回退。下面的核对会调用新的官方只读接口；人工结束保留原请求未知结果。</p><fieldset disabled={Boolean(unavailable) || action.busy || submitting || current.requested_by !== actor.getCurrent()?.admin_id}><label><input type="checkbox" checked={stopped} onChange={event => setStopped(event.target.checked)} />已人工确认原官方请求执行结束</label><label>核对步骤、证据来源及结论（32 至 4096 字节，不填凭据）<textarea value={evidence} maxLength={4096} onChange={event => setEvidence(event.target.value)} /></label><button className="ui-button" disabled={!stopped || evidenceBytes(evidence) < 32 || evidenceBytes(evidence) > 4096 || !receipt.fresh} onClick={reconcile}>验证身份并进行新的官方读取核对</button></fieldset></>}
    </div>}
  </section>
}
