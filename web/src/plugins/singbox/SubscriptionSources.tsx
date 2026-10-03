import { useEffect, useRef, useState } from 'react'
import { api, errorMessage } from '../../api'
import { Badge, Confirm, Empty, ErrorNotice, Field, FormDialog, Icon, Loading, Refresh } from '../../components'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import { hopReference, sourceReason, sourceStatus, validSubscriptionSources, validExternalNodePreviews, knownSourceAmount, sourceReportedTotal, sourceAdoptionError } from './sourceTypes'
import type { ExternalNodePreview, SubscriptionHopReference, SubscriptionSource, SubscriptionSourceJob } from './sourceTypes'
import SourceImport from './SourceImport'
import { validatedSnapshot } from './groupTypes'
import { bytes } from '../../format'
import './sources.css'

const root = '/api/plugins/sing-box'
const time = (timestamp: number | null) => timestamp ? new Date(timestamp * 1000).toLocaleString('zh-CN', { hour12: false }) : '尚无记录'

export default function SubscriptionSources({ onSelect, onChange }: { onSelect?: (reference: SubscriptionHopReference, node: ExternalNodePreview) => void; onChange?: () => void }) {
  const sourcesQuery = useResource<unknown>(`${root}/subscription-sources`)
  const sourceHistory = useRef<SubscriptionSource[] | undefined>(undefined)
  const sourceView = validatedSnapshot(sourcesQuery, validSubscriptionSources, sourceHistory.current)
  if (sourceView.fresh) sourceHistory.current = sourceView.data
  const sources = { ...sourcesQuery, ...sourceView, data: sourceView.data, getCurrent: () => sourceView.getCurrent?.(), isCurrent: () => sourceView.isCurrent?.() === true }
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const selectedIdRef = useRef(selectedId); selectedIdRef.current = selectedId
  const chooseSource = (id: number) => { selectedIdRef.current = id; setSelectedId(id) }
  const [editor, setEditor] = useState<{ source?: SubscriptionSource } | null>(null)
  const [deleting, setDeleting] = useState<SubscriptionSource | null>(null)
  const [mode, setMode] = useState<SubscriptionHopReference['update_mode']>('follow_node')
  const action = useAction()
  const selected = sources.data?.find(source => source.id === selectedId)
  const nodesQuery = useResource<unknown>(selectedId ? `${root}/subscription-sources/${selectedId}/nodes` : null)
  const nodeHistory = useRef<{ id: number | null; data?: ExternalNodePreview[] }>({ id: selectedId })
  if (nodeHistory.current.id !== selectedId) nodeHistory.current = { id: selectedId }
  const nodeView = validatedSnapshot(nodesQuery, validExternalNodePreviews, nodeHistory.current.data)
  if (nodeView.fresh) nodeHistory.current.data = nodeView.data
  const nodes = { ...nodesQuery, ...nodeView, data: nodeView.data, getCurrent: () => nodeView.getCurrent?.(), isCurrent: () => nodeView.isCurrent?.() === true }
  const job = useResource<SubscriptionSourceJob>(selected?.active_job_id ? `${root}/subscription-source-jobs/${selected.active_job_id}` : null, 1500)
  const previous = useRef<string | null>(null)
  const change = useRef(onChange); change.current = onChange
  useEffect(() => {
    if (!sources.data) return
    const revisions = sources.data.map(source => `${source.id}:${source.current_revision_id}:${source.settings_revision}`).join(',')
    // The first snapshot is the baseline; reloading the whole page for it only repeats the initial reads.
    if (previous.current === null) { previous.current = revisions; return }
    if (revisions !== previous.current) { previous.current = revisions; nodes.reload(); change.current?.() }
  }, [sources.data, nodes.reload])
  const reload = () => { sources.reload(); nodes.reload(); job.reload() }
  const writeError = (source?: SubscriptionSource) => {
    const stale = resourceWriteError(sources)
    if (stale) return stale
    const current = source && sources.getCurrent?.()?.find(value => value.id === source.id)
    return source && (!current || current.settings_revision !== source.settings_revision || current.identity_epoch !== source.identity_epoch || current.current_revision_id !== source.current_revision_id || current.archived !== source.archived || current.active_job_id !== source.active_job_id) ? '此来源已不存在或设置已改变，请重新确认；当前草稿已保留。' : ''
  }
  const selectionError = () => selectedIdRef.current !== selected?.id ? '来源选择已改变，请重新确认；当前选择已保留。' : writeError(selected) || resourceWriteError(nodes)
  const open = (source?: SubscriptionSource) => { if (writeError(source)) return; action.clearError(); setEditor({ source }) }
  const archive = (source: SubscriptionSource) => { if (writeError(source)) return; void action.run(() => api(`${root}/subscription-sources/${source.id}`, 'PATCH', { settings_revision: source.settings_revision, archived: !source.archived }), reload) }
  const refreshSource = (source: SubscriptionSource) => {
    if (writeError(source)) return
    const current = sources.getCurrent?.()?.find(value => value.id === source.id)
    if (!current || current.archived || current.active_job_id) return
    void action.run(() => api<SubscriptionSourceJob>(`${root}/subscription-sources/${source.id}/refresh`, 'POST', {}), () => { chooseSource(source.id); reload() })
  }
  const adopt = (node: ExternalNodePreview) => {
    if (!selected || selectionError() || !node.id) return
    const currentSource = sources.getCurrent?.()?.find(source => source.id === selected.id)
    if (!currentSource || currentSource.identity_epoch !== node.identity_epoch || currentSource.archived && !node.adopted) return
    const current = nodes.getCurrent?.()?.find(value => value.id === node.id && value.source_id === selected.id && value.node_version_id === node.node_version_id && value.identity_epoch === node.identity_epoch)
    if (sourceAdoptionError(node, current) || !current) return
    void action.run(() => api(`${root}/subscription-sources/${selected.id}/nodes/${node.id}`, 'PATCH', { adopted: !current.adopted, settings_revision: selected.settings_revision, identity_epoch: current.identity_epoch, node_version_id: current.node_version_id, metadata_revision: current.metadata_revision }), () => { reload(); onChange?.() })
  }
  const cancelJob = () => {
    if (selectedIdRef.current !== selected?.id || writeError(selected) || resourceWriteError(job)) return
    const current = job.getCurrent()
    const source = sources.getCurrent?.()?.find(value => value.id === selectedId)
    if (!current || !source || current.id !== source.active_job_id || current.source_id !== source.id || current.settings_revision !== source.settings_revision || current.identity_epoch !== source.identity_epoch || !['queued', 'running'].includes(current.state)) return
    void action.run(() => api(`${root}/subscription-source-jobs/${current.id}/cancel`, 'POST', {}), reload)
  }
  return <section className="panel subscription-sources" aria-labelledby="subscription-sources-title">
    <div className="panel-heading"><div><h2 id="subscription-sources-title">订阅来源</h2><p className="helper">导入、更新来源，将选定节点加入节点库或用于链路。</p></div><div className="row-actions"><Refresh onClick={reload} /><button className="button button-primary button-small" disabled={Boolean(writeError())} onClick={() => open()}><Icon name="plus" size={16} />添加来源</button></div></div>
    <div className="panel-body"><ErrorNotice message={sources.error || (!editor && !deleting ? action.error : '')} retry={reload} /></div>
    {sources.loading && !sources.data ? <Loading /> : !sources.data?.length ? <Empty icon="nodes" title="添加第一个订阅来源" description="支持订阅地址、分享链接、sing-box 配置和 Clash 节点配置。导入只保留代理节点。"><button className="button button-secondary" disabled={Boolean(writeError())} onClick={() => open()}>添加来源</button></Empty> : <div className="source-list">{sources.data.map(source => <article key={source.id} className={`source-card ${source.id === selectedId ? 'source-card-selected' : ''}`}>
      <div className="source-card-main"><button className="text-button source-title" onClick={() => chooseSource(source.id)} aria-expanded={source.id === selectedId}>{source.name}</button><Badge tone={source.archived ? 'neutral' : source.last_error ? 'warm' : source.supported_count ? 'good' : 'neutral'}>{sourceStatus(source)}</Badge></div>
      <div className="source-meta"><span>{source.kind === 'url' ? source.source_host : '粘贴或上传配置'}</span><span>最近解析：支持 {source.supported_count} · 不支持或身份待确认 {source.unsupported_count}</span><span>最后成功：{time(source.last_success_at)}</span></div>
      {source.changes && <div className="source-meta"><span>新增 {source.changes.added} · 更新 {source.changes.updated} · 缺失 {source.changes.missing}</span>{source.kind === 'url' && <span>{source.auto_refresh === false ? '自动更新已关闭' : `每 ${source.refresh_interval_seconds / 60} 分钟更新`}</span>}</div>}
      {source.traffic && (source.traffic.upload !== undefined || source.traffic.download !== undefined || source.traffic.total !== undefined || source.traffic.expire !== undefined) && <div className="source-traffic"><span>来源用量：{sourceReportedTotal(source.traffic.upload, source.traffic.download) !== undefined ? bytes(sourceReportedTotal(source.traffic.upload, source.traffic.download)!) : '未知'} / {knownSourceAmount(source.traffic.total) !== undefined ? bytes(source.traffic.total!) : '未知额度'}</span>{source.traffic.expire !== undefined && <span>到期：{knownSourceAmount(source.traffic.expire) !== undefined && source.traffic.expire > 0 ? time(source.traffic.expire) : '未知'}</span>}<small>提供方上报 · {time(source.traffic.updated_at ?? null)}{(source.stale || !sourceView.fresh) && ' · 上次成功数据'}</small></div>}
      {source.last_error && <p className="source-warning">{sourceReason(source.last_error)}</p>}
      {!!source.dependency_ids.length && <p className="helper">被 {source.dependency_ids.length} 条链路引用（编号 {source.dependency_ids.join('、')}）</p>}
      <div className="row-actions"><button className="text-button" onClick={() => chooseSource(source.id)}>查看节点</button><button className="text-button" disabled={Boolean(writeError(source))} onClick={() => open(source)}>设置与更新</button>{source.kind === 'url' && <button className="text-button" disabled={source.archived || !!source.active_job_id || action.busy || Boolean(writeError(source))} onClick={() => refreshSource(source)}>立即更新</button>}<button className="text-button" disabled={action.busy || Boolean(writeError(source))} onClick={() => archive(source)}>{source.archived ? '恢复来源' : '归档'}</button><button className="text-button danger-text" disabled={Boolean(writeError(source))} onClick={() => { if (writeError(source)) return; action.clearError(); setDeleting(source) }}>删除</button></div>
    </article>)}</div>}
    {selected && <div className="source-preview">
      <div className="source-preview-heading"><h3>{selected.name} · 节点预览</h3><span className="subtle">来源代次 {selected.identity_epoch} · 成功批次 {selected.current_revision_id ?? '尚无'}</span></div>
      {job.data && ['queued', 'running'].includes(job.data.state) && <div className="source-job" role="status"><span className="spinner" />{job.data.phase === 'downloading' ? '正在获取订阅…' : job.data.phase === 'parsing' ? '正在解析节点…' : '等待刷新…'}<button className="text-button" disabled={action.busy || Boolean(writeError(selected) || resourceWriteError(job))} onClick={cancelJob}>取消刷新</button></div>}
      <ErrorNotice message={nodes.error || job.error} retry={nodes.reload} />
      {onSelect && <Field label="选中节点后的更新方式"><select value={mode} onChange={event => { if (['follow_node', 'pinned'].includes(event.target.value)) setMode(event.target.value as SubscriptionHopReference['update_mode']) }}><option value="follow_node">跟随所选节点更新</option><option value="pinned">固定当前版本</option></select></Field>}
      {nodes.loading && !nodes.data ? <Loading /> : !nodes.data?.length ? <p className="helper">尚无解析结果。完成导入后会在此显示支持项与拒绝原因。</p> : <div className="table-wrap"><table><thead><tr><th>节点</th><th>协议与端点</th><th>版本与用途</th><th>状态</th><th>节点库</th>{onSelect && <th>选择</th>}</tr></thead><tbody>{nodes.data.map((node, index) => <tr key={`${node.id ?? 'rejected'}-${index}`}><td><strong>{node.name}</strong>{node.id !== null && <small>节点 #{node.id}</small>}</td><td>{node.protocol ? <>{node.protocol}<small className="source-endpoint">{node.server?.includes(':') ? `[${node.server}]` : node.server}:{node.port}</small><small>传输：{node.transport}</small></> : '无法转换'}</td><td>{node.node_version_id ? <>版本 #{node.node_version_id}<small>{node.tcp ? '支持 TCP' : '不支持 TCP'} · {node.udp ? '支持 UDP' : '仅 TCP'}</small></> : '无可用版本'}</td><td>{node.selectable ? <Badge tone="good">可选</Badge> : <span className="source-warning">{sourceReason(node.reason)}</span>}</td><td>{node.id !== null && <button className="text-button" disabled={action.busy || Boolean(selectionError() || sourceAdoptionError(node, node))} onClick={() => adopt(node)}>{node.adopted ? '移出节点库' : '加入节点库'}</button>}</td>{onSelect && <td><button className="button button-secondary button-small" disabled={!node.selectable || Boolean(selectionError())} onClick={() => { if (selectionError() || !['follow_node', 'pinned'].includes(mode)) return; const current = nodes.getCurrent?.()?.find(value => value.id === node.id && value.node_version_id === node.node_version_id && value.source_id === node.source_id && value.identity_epoch === node.identity_epoch); const reference = current?.selectable && hopReference(current, mode); if (reference && current) onSelect(reference, current) }}>加入此段</button></td>}</tr>)}</tbody></table></div>}
      <p className="helper">“可选”表示参数可用于链路配置。放置位置还需校验整条路径的承载能力；解析成功不代表机场账户有效或链路连通。节点缺失或更新失败时，已有链路保留已应用版本。</p>
    </div>}
    {editor && !editor.source && <SourceImport writeError={() => writeError()} onClose={() => setEditor(null)} onSaved={source => { setEditor(null); chooseSource(source.id); reload(); onChange?.() }} />}
    {editor?.source && <SourceEditor source={editor.source} writeError={() => writeError(editor.source)} onClose={() => setEditor(null)} onSaved={source => { setEditor(null); chooseSource(source.id); reload(); onChange?.() }} />}
    {deleting && <Confirm title={`删除「${deleting.name}」？`} busy={action.busy} confirmDisabled={Boolean(writeError(deleting))} error={writeError(deleting) || action.error} onClose={() => setDeleting(null)} onConfirm={() => { if (writeError(deleting)) return; void action.run(() => api(`${root}/subscription-sources/${deleting.id}`, 'DELETE'), () => { if (selectedIdRef.current === deleting.id) { selectedIdRef.current = null; setSelectedId(null) } setDeleting(null); reload(); onChange?.() }) }}>仍被链路或代理用户引用的来源不能删除。归档可以停止刷新和新引用，已有链路继续使用保存的版本；历史版本和发布记录会保留。</Confirm>}
  </section>
}

function SourceEditor({ source, writeError, onClose, onSaved }: { source?: SubscriptionSource; writeError: () => string; onClose: () => void; onSaved: (source: SubscriptionSource) => void }) {
  const action = useAction()
  const [kind, setKind] = useState(source?.kind ?? 'url')
  const [url, setUrl] = useState('')
  const [authorization, setAuthorization] = useState('')
  const [content, setContent] = useState('')
  const [clearAuthorization, setClearAuthorization] = useState(false)
  const [replaceSource, setReplaceSource] = useState(false)
  const [fileError, setFileError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(source?.auto_refresh !== false)
  const upload = async (file?: File) => {
    if (!file) return
    if (file.size > 2 * 1024 * 1024) { setFileError('配置文件不能超过 2 MiB。'); return }
    try { setContent(await file.text()); setFileError('') } catch (error) { setFileError(errorMessage(error)) }
  }
  const submit = (form: FormData) => void action.run(async () => {
    const stale = writeError(); if (stale) throw new Error(stale)
    if (new TextEncoder().encode(content).length > 2 * 1024 * 1024) throw new Error('配置内容不能超过 2 MiB。')
    const body: Record<string, unknown> = { name: String(form.get('name') ?? '').trim() }
    if (source) body.settings_revision = source.settings_revision
    else body.kind = kind
    if (kind === 'url') {
      body.refresh_interval_seconds = Number(form.get('refresh_minutes')) * 60; body.auto_refresh = autoRefresh; body.user_agent = String(form.get('user_agent') ?? 'Sinan-subscription-import/1')
      if (url.trim()) body.url = url.trim()
      if (authorization) body.authorization = authorization
      if (clearAuthorization) body.clear_authorization = true
    } else if (content) { body.content = content; if (source) body.replace_source = replaceSource }
    return api<SubscriptionSource>(`${root}/subscription-sources${source ? `/${source.id}` : ''}`, source ? 'PATCH' : 'POST', body)
  }, saved => { setUrl(''); setAuthorization(''); setContent(''); onSaved(saved) })
  return <FormDialog title={source ? `设置「${source.name}」` : '添加订阅来源'} wide onClose={onClose} onSubmit={submit} busy={action.busy} submitDisabled={Boolean(writeError())} error={writeError() || action.error || fileError} submitLabel={source ? '保存并解析更新' : '保存并解析'}>
    <Field label="来源名称"><input name="name" maxLength={128} required defaultValue={source?.name ?? ''} autoComplete="off" /></Field>
    {!source && <Field label="来源类型"><select value={kind} onChange={event => { setKind(event.target.value as 'url' | 'inline'); setUrl(''); setAuthorization(''); setContent('') }}><option value="url">HTTPS 订阅地址</option><option value="inline">粘贴或上传配置</option></select></Field>}
    {kind === 'url' ? <>
      <Field label={source ? '替换订阅地址' : 'HTTPS 订阅地址'} hint={source ? '已配置的完整地址不会回显。留空保留；更换地址会建立新来源身份，原链路不会自动换机场。' : '仅接受公网 HTTPS 地址。地址中的路径和查询可能包含令牌。'}><input type="password" name="subscription_url" autoComplete="new-password" spellCheck={false} required={!source} maxLength={8192} placeholder={source?.url_configured ? '已配置，留空保留' : 'https://…'} value={url} onChange={event => setUrl(event.target.value)} /></Field>
      <Field label="获取认证（可选）" hint="需要时填写完整 Authorization 值。留空保留已配置的认证。"><input type="password" autoComplete="new-password" spellCheck={false} maxLength={8192} disabled={clearAuthorization} placeholder={source?.authorization_configured ? '已配置，留空保留' : '按来源要求填写'} value={authorization} onChange={event => setAuthorization(event.target.value)} /></Field>
      {source?.authorization_configured && <label className="source-checkbox"><input type="checkbox" checked={clearAuthorization} onChange={event => { setClearAuthorization(event.target.checked); if (event.target.checked) setAuthorization('') }} />清除已配置的获取认证</label>}
      <Field label="请求标识"><input name="user_agent" required maxLength={256} defaultValue={source?.user_agent ?? 'Sinan-subscription-import/1'} /></Field>
      <label className="source-checkbox"><input type="checkbox" checked={autoRefresh} onChange={event => setAutoRefresh(event.target.checked)} />自动更新来源</label>
      <Field label="自动刷新间隔（分钟）" hint="默认每天一次；允许 5 分钟至 30 天。"><input name="refresh_minutes" type="number" min={5} max={43200} step={1} required defaultValue={source ? source.refresh_interval_seconds / 60 : 1440} /></Field>
    </> : <>
      <Field label="上传配置文件" hint="支持文本、JSON、YAML，最大 2 MiB。"><input type="file" accept=".txt,.json,.yaml,.yml,text/plain,application/json" onChange={event => void upload(event.target.files?.[0])} /></Field>
      <Field label={source ? '更新配置内容' : '配置内容'} hint={source ? '留空保留当前内容；原内容不会回显。' : '粘贴分享链接、Base64 订阅、sing-box JSON 或 Clash / Mihomo 节点配置。'}><textarea name="source_content" rows={9} required={!source} autoComplete="off" spellCheck={false} value={content} onChange={event => setContent(event.target.value)} /></Field>
      {source && <Field label="内容更新方式"><select value={replaceSource ? 'replace' : 'same'} onChange={event => setReplaceSource(event.target.value === 'replace')}><option value="same">同一来源更新内容，按明确节点身份匹配</option><option value="replace">更换来源，原链路保留旧版本并需要重新选点</option></select></Field>}
    </>}
    <p className="helper">保存后只显示来源主机和节点公开预览。敏感内容仅在当前表单内存中保留，保存成功即清空。归档来源停止刷新；恢复后可再次提交更新。</p>
  </FormDialog>
}
