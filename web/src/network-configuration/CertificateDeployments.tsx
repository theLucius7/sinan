import { useState } from 'react'
import { api } from '../api'
import { Field } from '../components'
import { resourceWriteError, useResource } from '../hooks'
import type { Document, Target, Version } from './types'
import { time } from './types'

type Preview = { id: string; version_id: string; fingerprint: string; targets: Target[]; adopt_existing: boolean; expires_at: number }
type Deployment = { id: string; version_id: string; target: Target; status: string; created_at: number; receipt: unknown }
export default function CertificateDeployments({ document, run }: { document: Document; run: (work: () => Promise<unknown>) => Promise<void> }) {
  const versions = useResource<Version[]>(`/api/network-configuration/certificates/${document.id}/versions`)
  const deployments = useResource<Deployment[]>(`/api/network-configuration/certificates/${document.id}/deployments`)
  const [version, setVersion] = useState(document.active_version ?? ''), [keyReference, setKeyReference] = useState('')
  const [selected, setSelected] = useState<number[]>([]), [adopt, setAdopt] = useState(false), [confirmed, setConfirmed] = useState(false)
  const [preview, setPreview] = useState<Preview | null>(null)
  const targets = document.config.targets as Target[]
  const edit = (change: () => void) => { change(); setPreview(null); setConfirmed(false) }
  const statuses: Record<string, string> = { awaiting_queue: '等待入队', queued: '已排队', dispatched: '已派发', succeeded: '执行完成，握手另验', failed: '执行失败，请查看回执', cancelled: '已取消', queue_rejected: '能力、权限或生命周期拒绝', unknown: '结果未知，先核对远端' }
  return <section className="panel network-details"><h3>明确目标的批量证书部署</h3><p className="helper">预览固定证书版本、服务器、服务与文件路径，再逐台分发。Agent 只写入双侧授权目录，核对证书与私钥匹配，重载受管服务；失败尝试恢复原文件。实际 TLS 握手需单独核对。</p>
    <Field label="部署证书版本"><select value={version} onChange={event => edit(() => setVersion(event.target.value))}><option value="">请选择</option>{versions.data?.map(item => <option value={item.id} key={item.id}>版本 {item.revision} · 到期 {time(item.not_after)}</option>)}</select></Field>
    <Field label="加密私钥凭据引用（lego 签发可留空自动关联）"><input value={keyReference} onChange={event => edit(() => setKeyReference(event.target.value))} placeholder="仅填写凭据中心标识，不粘贴私钥" /></Field>
    {targets.map((target, index) => <label className="network-row" key={`${target.server_id}:${target.service}:${index}`}><span><input type="checkbox" disabled={!target.certificate_path || !target.private_key_path} checked={selected.includes(index)} onChange={event => edit(() => setSelected(previous => event.target.checked ? [...previous, index] : previous.filter(value => value !== index)))} />服务器 {target.server_id} · {target.service} · {target.domain}:{target.port}<br /><code>{target.certificate_path || '未配置受管证书路径'} · {target.private_key_path || '未配置受管私钥路径'}</code></span></label>)}
    <label><input type="checkbox" checked={adopt} onChange={event => edit(() => setAdopt(event.target.checked))} />明确接管目标现有文件；未接管时只更新已核对的司南受管证书</label>
    <button className="button button-secondary" disabled={!version || selected.length === 0 || !versions.fresh} onClick={() => void run(async () => { const error = resourceWriteError(versions); if (error) throw new Error(error); const result = await api<Preview>(`/api/network-configuration/certificates/${document.id}/deployment-preview`, 'POST', { version_id: version, key_credential_id: keyReference || null, target_indexes: selected, adopt_existing: adopt }); setPreview(result); return result })}>预览每台部署影响</button>
    {preview && <><p>预览有效期：{time(preview.expires_at)} · 私钥只通过目标 Agent 身份接口读取。</p><pre>{JSON.stringify(preview, null, 2)}</pre><label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />确认上述版本、目标文件与服务重载影响</label><button className="button button-primary" disabled={!confirmed || preview.expires_at * 1000 <= Date.now()} onClick={() => void run(async () => { const result = await api(`/api/network-configuration/deployment-previews/${preview.id}/apply`, 'POST', { confirmed }); setPreview(null); setConfirmed(false); deployments.reload(); return result })}>逐台排队部署</button></>}
    {versions.error && <p role="alert">{versions.error}</p>}{deployments.error && <p role="alert">{deployments.error}</p>}
    {deployments.data?.map(item => <article className="network-deployment" key={item.id}><strong>服务器 {item.target.server_id} · {item.target.service}</strong><span>{statuses[item.status] ?? '状态未知'} · {time(item.created_at)}</span><code>版本 {item.version_id}</code>{item.receipt !== null && <details><summary>脱敏执行回执</summary><pre>{JSON.stringify(item.receipt, null, 2)}</pre></details>}</article>)}
  </section>
}
