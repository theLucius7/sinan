import { useState } from 'react'
import { api } from '../api'
import { Field, ErrorNotice } from '../components'
import { resourceWriteError, useResource } from '../hooks'
import { labels, time } from './types'
import type { Draft, Kind, Server } from './types'

type Candidate = { id: string; kind: Kind; revision: number; before: Draft; suggested_config: Draft; identity: string }
type Candidates = { candidates: Candidate[]; truncated: boolean }
type Change = { document_id: string; destination_document_id: string; kind: Kind; revision: number; before: Draft; after: Draft; changes: unknown[]; notes: string[]; independent_identity: boolean }
type Preview = { id: string; snapshot_digest: string; expires_at: number; snapshot: { source: { id: number; name: string }; target: { id: number; name: string }; changes: Change[]; blockers: unknown[] } }
type Result = { id: string; source_server_id: number; target_server_id: number; applied_at: number; objects: { document_id: string; source_document_id: string; revision: number; independent_identity: boolean }[] }

export default function ServerMigrations({ servers, initialServerId, busy, run, changed }: { servers: Server[]; initialServerId?: number; busy: boolean; run: (work: () => Promise<unknown>) => Promise<void>; changed: () => void }) {
  const [source, setSource] = useState(initialServerId ?? 0), [target, setTarget] = useState(0)
  const candidates = useResource<Candidates>(source && target && source !== target ? `/api/network-configuration/server-migrations/candidates?source_server_id=${source}&target_server_id=${target}` : null)
  const [selected, setSelected] = useState<Record<string, string>>({}), [preview, setPreview] = useState<Preview | null>(null), [confirmed, setConfirmed] = useState(false), [result, setResult] = useState<Result | null>(null)
  const reset = () => { setSelected({}); setPreview(null); setConfirmed(false); setResult(null) }
  const invalidate = () => { setPreview(null); setConfirmed(false); setResult(null) }
  const selectedIds = Object.keys(selected)
  const create = () => run(async () => {
    const error = resourceWriteError(candidates); if (error) throw new Error(error)
    const selections = selectedIds.map(document_id => {
      let target_config: unknown
      try { target_config = JSON.parse(selected[document_id]) } catch { throw new Error('替换配置必须为有效 JSON；请修正所选对象。') }
      if (!target_config || typeof target_config !== 'object' || Array.isArray(target_config)) throw new Error('替换配置必须为对象。')
      return { document_id, target_config }
    })
    const response = await api<Preview>('/api/network-configuration/server-migrations/preview', 'POST', { source_server_id: source, target_server_id: target, selections })
    setPreview(response); setConfirmed(false); return undefined
  })
  const apply = () => preview && run(async () => {
    const response = await api<Result>(`/api/network-configuration/server-migrations/${preview.id}/apply`, 'POST', { confirmed, snapshot_digest: preview.snapshot_digest })
    setResult(response); setPreview(null); setConfirmed(false); changed(); candidates.reload(); return response
  })
  return <section className="panel network-details"><details><summary>服务器替换：迁移所选网络业务</summary>
    <p>选择原服务器、替换服务器与业务对象，逐项核对监听地址、公开入口、证书路径和授权。只保存业务目标配置，部署、实际握手与旧服务清理需要分别确认。</p>
    <div className="network-target"><Field label="原服务器"><select value={source} disabled={busy} onChange={event => { setSource(Number(event.target.value)); reset() }}><option value={0}>请选择</option>{servers.map(server => <option value={server.id} key={server.id}>{server.name}</option>)}</select></Field><Field label="替换服务器"><select value={target} disabled={busy} onChange={event => { setTarget(Number(event.target.value)); reset() }}><option value={0}>请选择</option>{servers.filter(server => server.id !== source).map(server => <option value={server.id} key={server.id}>{server.name}</option>)}</select></Field></div>
    <ErrorNotice message={candidates.error} retry={candidates.reload} />
    {candidates.data?.truncated && <p role="alert">候选查询达到受限范围，部分对象可能未列出；请先减少原服务器关联配置。</p>}
    {candidates.data?.candidates.map(candidate => <article className="network-deployment" key={candidate.id}><label><input type="checkbox" checked={Object.hasOwn(selected, candidate.id)} disabled={busy || (!Object.hasOwn(selected, candidate.id) && selectedIds.length >= 64)} onChange={event => { if (event.target.checked) setSelected(value => ({ ...value, [candidate.id]: JSON.stringify(candidate.suggested_config, null, 2) })); else setSelected(value => { const next = { ...value }; delete next[candidate.id]; return next }); invalidate() }} />{String(candidate.before.name)} · {labels[candidate.kind]} · 版本 {candidate.revision}</label>
      {candidate.identity === 'new_document_and_new_local_key' && <p>创建独立候选并保留源对象；新设备生成新的本机密钥，对端需要明确授权新公钥。</p>}
      {Object.hasOwn(selected, candidate.id) && <><details><summary>原配置</summary><pre>{JSON.stringify(candidate.before, null, 2)}</pre></details><Field label="替换配置：核对新服务器地址、端口与证书服务路径"><textarea rows={12} disabled={busy} value={selected[candidate.id]} onChange={event => { setSelected(value => ({ ...value, [candidate.id]: event.target.value })); invalidate() }} /></Field></>}
    </article>)}
    {source > 0 && target > 0 && candidates.fresh && candidates.data?.candidates.length === 0 && <p>当前授权范围内没有可迁移的网络业务对象。</p>}
    <div className="network-actions"><button className="button button-secondary" disabled={busy || !candidates.fresh || selectedIds.length === 0} onClick={() => void create()}>预览 {selectedIds.length} 个所选对象的替换影响</button><a href="#/plugins/ddns">另外预览 DDNS 规则迁移</a></div>
    {preview && <section><h3>{preview.snapshot.source.name} → {preview.snapshot.target.name}</h3><p>预览有效至 {time(preview.expires_at)}。原 Agent 身份保留，目标 Agent 身份独立。</p>{preview.snapshot.changes.map(change => <article className="network-deployment" key={change.document_id}><strong>{String(change.before.name)} · {labels[change.kind]}</strong><p>原服务器 {source} → 替换服务器 {target} · {change.independent_identity ? '新标识候选，原对象保留' : '保留业务标识与版本历史'}</p><details open><summary>字段与关系变化</summary><pre>{JSON.stringify(change.changes, null, 2)}</pre></details>{change.notes.map(note => <p key={note}>{note}</p>)}</article>)}
      {preview.snapshot.blockers.length > 0 && <div role="alert"><p>能力、授权、地址、证书或冲突检查存在阻断项，当前不能确认迁移。</p><pre>{JSON.stringify(preview.snapshot.blockers, null, 2)}</pre></div>}
      <details><summary>服务器能力、范围、证书与凭据引用核对</summary><pre>{JSON.stringify(preview.snapshot, null, 2)}</pre></details><label><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />确认所选对象及新目标，之后另行部署、验证并清理旧服务</label><div className="network-actions"><button className="button button-primary" disabled={busy || !confirmed || preview.snapshot.blockers.length > 0 || preview.expires_at * 1000 <= Date.now()} onClick={() => void apply()}>确认保存替换目标配置</button></div>
    </section>}
    {result && <section><h3>替换目标配置已保存</h3><p>{time(result.applied_at)} · 新目标待部署、待实际验证；原服务器服务未自动停止。</p>{result.objects.map(object => <p key={object.document_id}>对象 <code>{object.document_id}</code> · 版本 {object.revision} · {object.independent_identity ? '独立身份候选' : '保留业务标识'} · <a href={`#/servers/${result.target_server_id}/network-configuration`}>进入新服务器部署与验证</a>{object.independent_identity && <> · 原对象 <code>{object.source_document_id}</code></>}</p>)}<a href={`#/servers/${result.source_server_id}/fleet`}>在原服务器核对运行服务与清理结果</a></section>}
  </details></section>
}
