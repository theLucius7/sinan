import { useEffect, useState } from 'react'
import { api, errorMessage } from '../../api'
import { ErrorNotice, Loading, Modal } from '../../components'
import { bytes, time } from '../../format'

export type WorkflowOperation = { operation: 'policy_batch'; user_ids: number[]; group_ids: number[] }
  | { operation: 'replace_package'; user_id: number; package_group_id: number }
  | { operation: 'extend_validity'; user_id: number; days: number }
  | { operation: 'reset_quota'; user_id: number }
  | { operation: 'rotate_node_credentials'; user_id: number; node_ids: number[] }
  | { operation: 'migrate_node'; source_node_id: number; candidate_node_id: number }
  | { operation: 'failover'; source_chain_id: number; alternate_chain_id: number; group_ids: number[]; reason: string }
type Summary = { effect: string; users?: { id: number; name: string }[]; affected_users?: ({ id: number; name: string } | number)[]; differences?: { user_id: number; added_nodes: number[]; removed_nodes: number[]; effective_nodes: number[] }[]; previous_expires_at?: number; new_expires_at?: number; credit_bytes?: string; plan?: { name: string; monthly_bytes: string | null; duration_days: number; timezone: string }; new_cycle?: { cycle_start: number; next_reset: number; used_bytes: string }; candidate_endpoint?: { host: string; port: number; sni: string }; source_server_id?: number; candidate_server_id?: number; affected_groups?: number[] }
type Preview = { id: string; expires_at: number; summary: Summary }
const titles: Record<WorkflowOperation['operation'], string> = { policy_batch: '策略组分配预览', replace_package: '套餐更换预览', extend_validity: '有效期延长预览', reset_quota: '本期额度重置预览', rotate_node_credentials: '节点凭据轮换预览', migrate_node: '节点迁移预览', failover: '备选链路切换预览' }

export default function OperationReview({ request, onClose, onApplied }: { request: WorkflowOperation; onClose: () => void; onApplied: () => void }) {
  const [preview, setPreview] = useState<Preview>()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [reload, setReload] = useState(0)
  const [confirmed, setConfirmed] = useState(false)
  const [now, setNow] = useState(Date.now() / 1000)
  useEffect(() => {
    const controller = new AbortController()
    let active = true
    setPreview(undefined); setConfirmed(false); setError('')
    void api<Preview>('/api/plugins/sing-box/operations/preview', 'POST', request, controller.signal).then(value => { if (active) setPreview(value) }).catch(error => { if (active && !controller.signal.aborted) setError(errorMessage(error)) })
    return () => { active = false; controller.abort() }
  }, [request, reload])
  useEffect(() => { const timer = window.setInterval(() => setNow(Date.now() / 1000), 1000); return () => window.clearInterval(timer) }, [])
  const expired = preview && preview.expires_at <= now
  const apply = async () => {
    if (!preview || !confirmed || expired || busy) return
    setBusy(true); setError('')
    try { await api(`/api/plugins/sing-box/operations/${preview.id}/apply`, 'POST', { confirm: true }); onApplied() }
    catch (error) { setError(errorMessage(error)) }
    finally { setBusy(false) }
  }
  const summary = preview?.summary
  return <Modal title={titles[request.operation]} onClose={onClose} busy={busy} wide>
    <div className="modal-body"><ErrorNotice message={error} retry={() => setReload(value => value + 1)} />
      {!preview && !error ? <Loading /> : summary && <>
        <p>{summary.effect}</p>
        {summary.users && <p>固定目标：{summary.users.map(user => `${user.name}（#${user.id}）`).join('、')}</p>}
        {summary.affected_users && <p>受影响用户：{summary.affected_users.map(user => typeof user === 'number' ? `#${user}` : `${user.name}（#${user.id}）`).join('、') || '暂无授权用户'}</p>}
        {summary.differences && <div className="table-wrap"><table><thead><tr><th>用户</th><th>新增节点</th><th>撤销节点</th><th>变更后节点数</th></tr></thead><tbody>{summary.differences.map(change => <tr key={change.user_id}><td>#{change.user_id}</td><td>{change.added_nodes.join('、') || '无'}</td><td>{change.removed_nodes.join('、') || '无'}</td><td>{change.effective_nodes.length}</td></tr>)}</tbody></table></div>}
        {summary.plan && <dl className="group-details"><div><dt>新套餐</dt><dd>{summary.plan.name}</dd></div><div><dt>月度额度</dt><dd>{summary.plan.monthly_bytes === null ? '不限量' : bytes(summary.plan.monthly_bytes)}</dd></div><div><dt>有效期</dt><dd>确认时起 {summary.plan.duration_days} 天</dd></div><div><dt>时区</dt><dd>{summary.plan.timezone}</dd></div>{summary.new_cycle && <><div><dt>新账期已用</dt><dd>{bytes(summary.new_cycle.used_bytes)}</dd></div><div><dt>下次重置</dt><dd>{time(summary.new_cycle.next_reset)}</dd></div></>}</dl>}
        {summary.new_expires_at && <p>原到期：{summary.previous_expires_at ? time(summary.previous_expires_at) : '未知'}；延长后：{time(summary.new_expires_at)}。</p>}
        {summary.credit_bytes !== undefined && <p>当前账期补偿：{bytes(summary.credit_bytes)}。之后到达的计量批次仍会计入。</p>}
        {summary.candidate_endpoint && <p>服务器 #{summary.source_server_id} → #{summary.candidate_server_id}；候选入口 {summary.candidate_endpoint.host}:{summary.candidate_endpoint.port}，证书域名 {summary.candidate_endpoint.sni || '未设置'}；影响策略组 {summary.affected_groups?.join('、') || '无'}。</p>}
        {request.operation === 'rotate_node_credentials' && <p>用户 #{request.user_id}，所选节点 {request.node_ids.join('、')}。订阅地址重置和节点凭据轮换是独立操作。</p>}
        {request.operation === 'failover' && <p>原链路 #{request.source_chain_id} → 明确备选 #{request.alternate_chain_id}；策略组 {request.group_ids.join('、')}。原因：{request.reason}。</p>}
        <p className="helper">预览有效至 {time(preview!.expires_at)}。对象、账期、用量或配置变化时需重新预览；确认不会自动扩大目标。</p>
        {expired ? <p className="notice" role="status">预览已过期，请重新预览。</p> : <label className="group-choice"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} disabled={busy} /><span>已核对目标与影响，确认执行</span></label>}
      </>}
    </div><footer><button className="button button-secondary" disabled={busy} onClick={onClose}>返回草稿</button><button className="button button-secondary" disabled={busy} onClick={() => setReload(value => value + 1)}>重新预览</button><button className="button button-primary" disabled={busy || !preview || !confirmed || Boolean(expired)} onClick={() => void apply()}>{busy ? '正在提交…' : '确认应用'}</button></footer>
  </Modal>
}
