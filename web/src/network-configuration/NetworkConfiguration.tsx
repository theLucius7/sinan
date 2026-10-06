import { useRef, useState } from 'react'
import { api, errorMessage } from '../api'
import { ErrorNotice, Field, PageHeader, Refresh } from '../components'
import { resourceWriteError, useResource } from '../hooks'
import Certificates from './Certificates'
import Editor from './Editor'
import Relationships from './Relationships'
import ServerMigrations from './ServerMigrations'
import { labels, template, time } from './types'
import type { Document, Draft, Kind, Server } from './types'
import './network-configuration.css'

export default function NetworkConfiguration({ serverId }: { serverId?: number }) {
  const documents = useResource<Document[]>('/api/network-configuration/documents')
  const servers = useResource<Server[]>('/api/servers')
  const [kind, setKind] = useState<Kind>('domain'), [selectedId, setSelectedId] = useState<string | null>(null)
  const [draft, setDraft] = useState<Draft>(template('domain', serverId)), [dirty, setDirty] = useState(false)
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [preview, setPreview] = useState<unknown>(null)
  const [evidence, setEvidence] = useState<unknown>(null), [confirmed, setConfirmed] = useState(false), [snapshot, setSnapshot] = useState(''), [operation, setOperation] = useState('')
  const [baseRevision, setBaseRevision] = useState<number | null>(null)
  const locked = useRef(false)
  const selected = documents.data?.find(item => item.id === selectedId)
  const refresh = () => { documents.reload(); servers.reload() }
  const run = async (work: () => Promise<unknown>) => { if (locked.current) return; locked.current = true; setBusy(true); setError(''); try { const value = await work(); if (value !== undefined) setEvidence(value) } catch (cause) { setError(errorMessage(cause)) } finally { locked.current = false; setBusy(false) } }
  const change = (part: Record<string, unknown>) => { setDraft(value => ({ ...value, ...part })); setDirty(true); setPreview(null) }
  const pick = (next: Document | null, nextKind = kind) => { if (dirty && !window.confirm('当前表单有未保存草稿，确认离开？')) return; setSelectedId(next?.id ?? null); setBaseRevision(next?.revision ?? null); setKind(next?.kind ?? nextKind); setDraft(next?.config ?? template(nextKind, serverId)); setDirty(false); setPreview(null); setEvidence(null); setConfirmed(false); setSnapshot(''); setOperation('') }
  const loadEvidence = () => selected && run(async () => { setEvidence(await api(`/api/network-configuration/documents/${selected.id}/observations`)) })
  const execute = (action: string) => selected && run(async () => { const error = resourceWriteError(documents, servers); if (error) throw new Error(error); const result = await api<{ operation_id: string; request: { snapshot_id?: string } }>(`/api/network-configuration/documents/${selected.id}/execute`, 'POST', { action, revision: baseRevision, snapshot_id: snapshot || null, confirmed }); setOperation(result.operation_id); if (result.request.snapshot_id) setSnapshot(result.request.snapshot_id); return result })
  const readOnly = (action: string) => ['status', 'tunnel_status', 'mesh_status', 'firewall_status'].includes(action)
  const actions: Partial<Record<Kind, string[][]>> = { forwarding: [['start', '启动临时转发'], ['stop', '停止转发'], ['status', '核对服务状态']], tuning: [['temporary', '临时应用并安排恢复'], ['confirm', '确认结果并解除恢复'], ['persist', '保存长期配置'], ['restore', '恢复原始参数']], tunnel: [['tunnel_key', '生成或读取独立隧道公钥'], ['tunnel_start', '启动反向隧道'], ['tunnel_stop', '停止反向隧道'], ['tunnel_status', '查看隧道服务状态']], mesh: [['mesh_apply', '应用私有组网'], ['mesh_status', '读取握手及传输观测'], ['mesh_stop', '停止接口'], ['mesh_restore', '回退前一配置'], ['mesh_persist', '启用开机组网']], firewall: [['firewall_temporary', '临时应用并安排恢复'], ['firewall_confirm', '确认结果并解除恢复'], ['firewall_persist', '持久化受管防火墙'], ['firewall_restore', '恢复前一受管表'], ['firewall_status', '核对实际规则']] }
  const scope = servers.data?.filter(server => !serverId || server.id === serverId) ?? []
  return <div className="network-configuration"><PageHeader eyebrow="服务器网络" title="DNS、证书与网络配置" description="维护域名、证书、端点和系统网络参数；明确区分配置、任务执行与实际观测。"><Refresh onClick={refresh} /></PageHeader>
    <ErrorNotice message={error || documents.error || servers.error} retry={refresh} />
    <ServerMigrations servers={servers.data ?? []} initialServerId={serverId} busy={busy} run={run} changed={refresh} />
    <nav className="network-tabs ui-tab-list" aria-label="网络配置分类">{(Object.keys(labels) as Kind[]).map(value => <button type="button" key={value} aria-pressed={kind === value} onClick={() => pick(null, value)}>{labels[value]}</button>)}<a href="#/plugins/ddns">DNS 与 DDNS 插件</a></nav>
    <div className="network-layout"><aside className="panel"><button className="button button-secondary" disabled={busy} onClick={() => pick(null)}>新增{labels[kind]}</button>{documents.data?.filter(item => item.kind === kind).map(item => <button className="network-card" aria-current={selectedId === item.id ? 'true' : undefined} key={item.id} onClick={() => pick(item)}><strong>{String(item.config.name)}</strong><span>版本 {item.revision} · {time(item.updated_at)}</span></button>)}</aside>
      <section className="panel network-editor">{selected && baseRevision !== selected.revision && <p role="alert">台账已被并发修改，当前草稿保留；请重新选择并核对最新配置。</p>}<form onSubmit={event => { event.preventDefault(); void run(async () => { const error = resourceWriteError(documents, servers); if (error) throw new Error(error); const saved = await api<Document>(selected ? `/api/network-configuration/documents/${selected.id}` : '/api/network-configuration/documents', selected ? 'PUT' : 'POST', { config: draft, revision: baseRevision }); setSelectedId(saved.id); setBaseRevision(saved.revision); setDraft(saved.config); setDirty(false); setPreview(null); documents.reload(); return { status: '已保存配置台账，执行需单独确认', revision: saved.revision } }) }}><fieldset disabled={busy}><Editor key={`${selectedId ?? 'new'}:${kind}`} draft={draft} change={change} servers={scope} documents={documents.data ?? []} /><div className="network-actions"><button type="button" className="button button-secondary" disabled={!documents.fresh || !servers.fresh} onClick={() => void run(async () => { const error = resourceWriteError(documents, servers); if (error) throw new Error(error); setPreview(await api('/api/network-configuration/documents/preview', 'POST', { config: draft, revision: baseRevision })) })}>预览关联与影响</button><button className="button button-primary" disabled={!preview || !documents.fresh || !servers.fresh || (selected !== undefined && baseRevision !== selected.revision)}>确认预览并保存台账</button></div></fieldset></form>
        {preview !== null && <details open><summary>待保存配置与影响</summary><pre>{JSON.stringify(preview, null, 2)}</pre></details>}
      </section>
    </div>
    {selected && <><Relationships document={selected} documents={documents.data ?? []} select={pick} /><section className="panel network-details"><h3>独立执行与实际观测</h3><p className="helper">保存配置不会执行网络变更。任务排队、进程运行、端到端可达性和握手验证是不同状态；缺失结果保留为未知。</p><div className="network-actions"><button className="button button-secondary" disabled={busy} onClick={() => void loadEvidence()}>读取结果与观测</button><button className="button button-secondary" disabled={busy} onClick={() => void run(async () => setEvidence(await api(`/api/network-configuration/documents/${selected.id}/history`)))}>查看台账历史</button></div>
      {actions[kind] && <><label><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} />确认目标服务器、资源影响与本机授权</label>
        <div className="network-actions">{actions[kind]?.map(([action, label]) => <button className="button button-secondary" key={action} disabled={busy || dirty || !documents.fresh || !servers.fresh || (!readOnly(action) && !confirmed) || (['confirm', 'persist', 'restore', 'firewall_confirm', 'firewall_persist', 'firewall_restore', 'firewall_status'].includes(action) && !snapshot)} onClick={() => void execute(action)}>{label}</button>)}</div>
        {(kind === 'tuning' || kind === 'firewall') && <Field label="当前临时快照标识"><input value={snapshot} onChange={event => setSnapshot(event.target.value)} placeholder="临时应用后自动填入；也可选择历史快照" /></Field>}
        {operation && <div className="network-row"><span>任务 {operation}</span><button className="button button-secondary" disabled={busy} onClick={() => void run(async () => setEvidence(await api(`/api/fleet/operations/${operation}`)))}>查询此任务实际结果</button></div>}
      </>}
    </section>{kind === 'certificate' && <Certificates key={selected.id} document={selected} run={run} changed={() => { documents.reload(); void loadEvidence() }} />}</>}
    {kind === 'tuning' && <section className="panel network-details"><h3>只读网络参数盘点</h3>{scope.map(server => <button className="button button-secondary" disabled={busy} key={server.id} onClick={() => void run(async () => { const result = await api<{ operation_id: string }>(`/api/network-configuration/servers/${server.id}/inventory`, 'POST'); setOperation(result.operation_id); return result })}>读取 {server.name} 参数与能力</button>)}{!selected && operation && <button className="button button-secondary" disabled={busy} onClick={() => void run(async () => setEvidence(await api(`/api/fleet/operations/${operation}`)))}>查询盘点任务结果</button>}</section>}
    {evidence !== null && <section className="panel network-details"><details open><summary>结构化执行证据</summary><pre>{JSON.stringify(evidence, null, 2)}</pre></details></section>}
  </div>
}
