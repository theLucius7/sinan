import { useEffect, useState } from 'react'
import { api } from '../api'
import { Field } from '../components'
import { resourceWriteError, useResource } from '../hooks'
import { time } from './types'

type Plan = { tool_version: string; credential_id: string; email: string; staging: boolean; terms_accepted: boolean; license_accepted: boolean; automatic_renewal: boolean; renew_before_days: number }
type Current = { plan: { config: Plan; revision: number; status: string; next_run_at: number } | null }
type Job = { id: string; status: string; created_at: number; result: { issued?: boolean | string; saved?: boolean; deployed?: boolean; handshake_verified?: boolean; error_code?: string; cleanup_required?: boolean; tool_version?: string } | null }

export default function AcmePlan({ certificateId, run }: { certificateId: string; run: (work: () => Promise<unknown>) => Promise<void> }) {
  const current = useResource<Current>(`/api/network-configuration/certificates/${certificateId}/acme-plan`)
  const jobs = useResource<Job[]>(`/api/network-configuration/certificates/${certificateId}/issuance`)
  const [plan, setPlan] = useState<Plan>({ tool_version: '', credential_id: '', email: '', staging: true, terms_accepted: false, license_accepted: false, automatic_renewal: false, renew_before_days: 30 })
  const [confirmed, setConfirmed] = useState(false), [reconciled, setReconciled] = useState(false)
  const [dirty, setDirty] = useState(false), [editingRevision, setEditingRevision] = useState<number | null>(null)
  useEffect(() => { if (!dirty) { if (current.data?.plan) setPlan(current.data.plan.config); setEditingRevision(current.data?.plan?.revision ?? null) } }, [current.data, dirty])
  const change = (part: Partial<Plan>) => { setDirty(true); setPlan(value => ({ ...value, ...part })) }
  return <section className="panel network-details"><h3>DNS-01 自动签发与续期</h3><p className="helper">使用已签名制品库存里的固定版 lego，向 Cloudflare 与 Let's Encrypt 发起真实请求。账户材料与私钥以加密凭据保存；不会自动部署到目标服务。默认使用预发布签发环境。</p>
    {current.error && <p role="alert">{current.error}</p>}
    <Field label="已签名 lego 固定版本"><input value={plan.tool_version} onChange={event => change({ tool_version: event.target.value })} placeholder="填写已导入签名库存的精确版本，不能使用 latest" /></Field>
    <Field label="Cloudflare DNS 凭据中心标识"><input value={plan.credential_id} onChange={event => change({ credential_id: event.target.value })} placeholder="受限 DNS 账号凭据的标识" /></Field>
    <Field label="签发联系邮箱"><input type="email" value={plan.email} onChange={event => change({ email: event.target.value })} /></Field>
    <Field label="自动续期提前天数"><input type="number" min={7} max={60} value={plan.renew_before_days} onChange={event => change({ renew_before_days: Number(event.target.value) })} /></Field>
    <label><input type="checkbox" checked={plan.staging} onChange={event => change({ staging: event.target.checked })} />使用 Let's Encrypt 预发布环境；该证书不受普通客户端信任</label>
    <label><input type="checkbox" checked={plan.terms_accepted} onChange={event => change({ terms_accepted: event.target.checked })} />已确认所选签发服务的条款</label>
    <label><input type="checkbox" checked={plan.license_accepted} onChange={event => change({ license_accepted: event.target.checked })} />已确认 lego 的 MIT 许可及所使用 DNS 服务条款</label>
    <label><input type="checkbox" checked={plan.automatic_renewal} onChange={event => change({ automatic_renewal: event.target.checked })} />授权自动首次签发，并在证书进入续期窗口时签发新版本</label>
    {dirty && current.data?.plan?.revision !== editingRevision && <p role="alert">签发计划已被并发修改，当前草稿保留；请重新核对远端配置后保存。</p>}
    <button className="button button-secondary" disabled={!current.fresh || !plan.tool_version || !plan.credential_id || !plan.email || !plan.license_accepted || !plan.terms_accepted} onClick={() => void run(async () => { const error = resourceWriteError(current); if (error) throw new Error(error); await api(`/api/network-configuration/certificates/${certificateId}/acme-plan`, 'PUT', { config: plan, revision: editingRevision }); current.reload(); jobs.reload(); setDirty(false) })}>保存签发与续期计划</button>
    <label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />确认本次真实签发及 DNS TXT 创建与清理</label>
    {jobs.data?.some(job => job.status === 'unknown') && <label><input type="checkbox" checked={reconciled} onChange={event => setReconciled(event.target.checked)} />已在签发方与 DNS 提供方人工核对未知请求，并处理遗留 TXT 后允许重新下单</label>}
    <div className="network-actions"><button className="button button-primary" disabled={!confirmed || !current.fresh || !jobs.fresh || !current.data?.plan || (jobs.data?.some(job => job.status === 'unknown') && !reconciled)} onClick={() => void run(async () => { const error = resourceWriteError(current, jobs); if (error) throw new Error(error); await api(`/api/network-configuration/certificates/${certificateId}/issue`, 'POST', { confirmed, remote_reconciled: reconciled }); jobs.reload(); return { status: '签发已排队，等待后台执行器结果' } })}>单独发起签发</button><button className="button button-secondary" onClick={() => { current.reload(); jobs.reload() }}>刷新签发阶段</button></div>
    {jobs.error && <p role="alert">{jobs.error}</p>}
    {jobs.data?.map(job => <article key={job.id}><strong>{({ queued: '已排队', running: '正在签发', succeeded: '已签发并保存', failed: '执行前失败，尚未签发', unknown: '执行结果未知，需核对', reconciled: '已人工核对' } as Record<string, string>)[job.status] ?? '状态未知'}</strong><span> · {time(job.created_at)}</span><p>签发 {job.result?.issued === true ? '已完成' : job.result?.issued === 'unknown' ? '未知' : '待完成'} · 保存 {job.result?.saved ? '已完成' : '待完成'} · 部署 {job.result?.deployed ? '已完成' : '维护方待执行'} · 握手 {job.result?.handshake_verified ? '已验证' : '待验证'}</p>{job.result?.error_code && <code>{job.result.error_code}</code>}{job.result?.cleanup_required && <p role="alert">需要在提供方核对遗留的验证记录；系统不会自动重放未知请求。</p>}</article>)}
  </section>
}
