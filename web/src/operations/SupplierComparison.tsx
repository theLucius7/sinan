import { useEffect, useState } from 'react'
import { api, errorMessage } from '../api'
import type { ActionRunner } from './types'
import { states, time } from './types'

type DiagnosticCondition = {
  plugin: string | null
  version: string | null
  artifact_sha256: string | null
  timeout_secs: number | null
  parameter_digest: string
  environment_digest: string
}
type Supplier = {
  provider: string
  server_ids: number[]
  server_count: number
  observations: { count: number; first_at: number | null; last_at: number | null; observed_hours: number; unknown_hours: number; evidence_state: 'observed' | 'insufficient'; availability_percent: null; permission_available: boolean }
  costs: { currency: string; amount_minor: string; record_count: number }[]
  diagnostics: { condition_digest: string; condition: DiagnosticCondition; records: { id: string; server_id: number; status: string; updated_at: number; report_available: boolean }[]; state: 'comparable' | 'insufficient' }[]
  diagnostics_permission_available: boolean
}
type Comparison = { from: number; until: number; suppliers: Supplier[]; limits: { server_limit: number; diagnostics_limit: number; server_limit_reached: boolean; diagnostics_limit_reached: boolean } }
type Actor = { role: string; capabilities: string[] }
const day = 86400
const localDate = (value: number) => {
  const date = new Date(value * 1000)
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16)
}

export default function SupplierComparison({ run, version }: { run: ActionRunner; version: number }) {
  const [from, setFrom] = useState(() => localDate(Math.floor(Date.now() / 1000) - 30 * day))
  const [until, setUntil] = useState(() => localDate(Math.floor(Date.now() / 1000)))
  const [comparison, setComparison] = useState<Comparison | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [canRead, setCanRead] = useState<boolean | null>(null)

  const refresh = async () => {
    setError('')
    setLoading(true)
    try {
      const actor = await api<Actor>('/api/control-center/me')
      const allowed = actor.role === 'owner' || actor.capabilities.includes('servers:read')
      setCanRead(allowed)
      if (!allowed) { setComparison(null); return }
      const first = Math.floor(new Date(from).getTime() / 1000)
      const last = Math.floor(new Date(until).getTime() / 1000)
      if (!Number.isFinite(first) || !Number.isFinite(last) || first < 0 || first >= last || last - first > 365 * day) throw new Error('请选择有效时间区间，结束时间须晚于开始时间，最长为 365 天。')
      setComparison(await api<Comparison>(`/api/operations/suppliers?from=${first}&until=${last}`))
    } catch (value) {
      setError(errorMessage(value))
      throw value
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { run(refresh) }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
  const chooseDays = (days: number) => { const now = Math.floor(Date.now() / 1000); setFrom(localDate(now - days * day)); setUntil(localDate(now)) }

  return <section className="operations-card" aria-busy={loading}>
    <h3>供应商长期观测对照</h3>
    <p>使用自己的服务器采样、采购成本和诊断记录。每台服务器每个 UTC 小时最多记一个有样本的小时槽；这不表示持续在线，无证据的小时也不表示离线。</p>
    <p>按当前资产登记的供应商归组；历史供应商变更未冻结，迁移前的历史证据不能自动归因当前供应商。</p>
    {canRead === false ? <p>当前账号缺少服务器读取授权，无法查看供应商的服务器观测与成本对照。已有云资源仍可在上方查看。</p> : <><div className="operations-fields">
      <label>开始时间（本地时区）<input type="datetime-local" value={from} onChange={event => setFrom(event.target.value)} /></label>
      <label>结束时间（本地时区）<input type="datetime-local" value={until} onChange={event => setUntil(event.target.value)} /></label>
    </div>
    <div className="operations-actions">{[7, 30, 90, 365].map(days => <button className="ui-button" key={days} type="button" onClick={() => chooseDays(days)}>最近 {days} 天</button>)}<button className="ui-button" type="button" disabled={loading} onClick={() => run(refresh)}>读取所选区间</button></div></>}
    {error && <p className="operations-error" role="alert">{error}{comparison && '；下方保留上次读取结果。'}</p>}
    {loading && <p role="status">正在读取自己的观测记录。</p>}
    {comparison && <>
      <p>已读取区间：{time(comparison.from)} 至 {time(comparison.until)}。最多纳入 {comparison.limits.server_limit} 台已授权服务器与 {comparison.limits.diagnostics_limit} 条诊断记录。</p>
      {(comparison.limits.server_limit_reached || comparison.limits.diagnostics_limit_reached) && <p role="status">结果达到读取上限，仅展示有界记录；请缩短区间或按报告进一步核对。</p>}
      {!comparison.suppliers.length && <p>所选区间内没有可读取的供应商记录。</p>}
      <div className="operations-table-wrap"><table><thead><tr><th>供应商／服务器</th><th>采样证据</th><th>成本原始记录</th><th>同条件诊断</th></tr></thead><tbody>{comparison.suppliers.map(supplier => <tr key={supplier.provider}>
        <td>{supplier.provider || '未登记供应商'}<small>{supplier.server_count} 台服务器</small><small>服务器编号：{supplier.server_ids.join('、') || '无'}</small></td>
        <td>{supplier.observations.permission_available ? <>有样本的服务器小时：{supplier.observations.observed_hours}<small>无证据的服务器小时：{supplier.observations.unknown_hours}</small><small>完整聚合桶内至少 {supplier.observations.count} 个样本；区间边界未补算样本。</small><small>首个样本 {time(supplier.observations.first_at)}</small><small>最后样本 {time(supplier.observations.last_at)}</small><small>{supplier.observations.evidence_state === 'observed' ? '已有真实采样证据' : '采样证据不足'}</small></> : '未授权读取监控证据'}</td>
        <td>{supplier.costs.length ? supplier.costs.map(cost => <p key={cost.currency}>{cost.amount_minor} 最小币单位（{cost.currency}）<small>{cost.record_count} 条成本记录</small></p>) : '暂无成本记录'}<small>保留原最小币单位与币种，不作汇率换算。</small></td>
        <td>{!supplier.diagnostics_permission_available ? <p>未授权读取诊断证据。</p> : !supplier.diagnostics.length && <p>暂无同条件诊断记录。</p>}{supplier.diagnostics.map(group => <details key={group.condition_digest}>
          <summary>{group.state === 'comparable' ? '已有至少两台服务器的同条件成功结果' : '同条件成功结果不足'} · {group.records.length} 条记录</summary>
          <p>工具：{group.condition.plugin ?? '未记录'}；版本：{group.condition.version ?? '未记录'}；时长上限：{group.condition.timeout_secs === null ? '未记录' : `${group.condition.timeout_secs} 秒`}。</p>
          <p>制品摘要：<code>{group.condition.artifact_sha256 ?? '未记录'}</code><small>条件摘要：{group.condition_digest}</small><small>参数摘要：{group.condition.parameter_digest}</small><small>环境摘要：{group.condition.environment_digest}</small></p>
          <ul>{group.records.map(record => <li key={record.id}>服务器 {record.server_id} · {states[record.status] ?? '其他执行状态'} · {time(record.updated_at)}<small>报告编号：{record.id} · {record.report_available ? '已有报告可核对' : '报告不可用'}</small></li>)}</ul>
        </details>)}</td>
      </tr>)}</tbody></table></div>
      <p>诊断按工具版本、制品、参数和环境摘要分组。仅核对同条件原始报告，不生成统一分数、供应商排名或超售结论。</p>
    </>}
  </section>
}
