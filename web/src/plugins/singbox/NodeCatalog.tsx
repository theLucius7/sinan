import { useEffect, useRef, useState } from 'react'
import { api } from '../../api'
import { Badge, Confirm, Empty, ErrorNotice, Field, FormDialog, Loading, Modal } from '../../components'
import { bytes, totalBytes } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import type { Node, PluginServer, Usage } from '../../types'
import type { ProxyResource, ResourceKey } from './resourceTypes'
import { endpoint, resourceLink, roleNames, stageName } from './resourceTypes'
import { protocolNames } from './ProtocolFields'
import { sourceReason } from './sourceTypes'
import { catalogKey, catalogRef, catalogMutationError, filterCatalog, parsedTags, renamed, tagsError, validCatalog } from './catalog'
import type { CatalogNode } from './catalog'
import { validatedSnapshot } from './groupTypes'
import './catalog.css'

const root = '/api/plugins/sing-box'
const kinds = { direct: '直连节点', chain: '链路', external: '外部节点' }
type Props = { nodes: Node[]; servers: PluginServer[]; getServers: () => PluginServer[] | undefined; usage?: Usage; server: string; getServer: () => string; onServer: (id: string) => void; excludedKeys: string[]; metadataTarget: ResourceKey | null; onMetadataOpened: () => void; kind: string; onKind: (kind: string) => void; initialServerRole?: 'any' | 'entry' | 'middle' | 'exit'; refreshRevision: number; onChanged: () => void; managedWriteError: () => string; onEdit: (node: Node) => void; onDelete: (node: ProxyResource) => void; onDeployment: (id: number) => void }

export default function NodeCatalog(props: Props) {
  const query = useResource<unknown>(`${root}/node-catalog`)
  const history = useRef<CatalogNode[] | undefined>(undefined)
  const view = validatedSnapshot(query, validCatalog, history.current)
  if (view.fresh) history.current = view.data
  const catalog = { ...query, ...view, data: view.data, getCurrent: () => view.getCurrent?.(), isCurrent: () => view.isCurrent?.() === true }
  const [filter, setFilter] = useState({ search: '', kind: props.kind, protocol: '', tag: '', status: '', source: '', role: '' })
  const filterRef = useRef(filter)
  filterRef.current = filter
  useEffect(() => { filterRef.current = { ...filterRef.current, kind: props.kind }; setFilter(filterRef.current); setPage(1) }, [props.kind])
  const [page, setPage] = useState(1), [size, setSize] = useState(20), [sort, setSort] = useState('custom')
  const [selection, setSelection] = useState<string[]>([])
  const [batch, setBatch] = useState<{ mode: string; nodes: CatalogNode[]; scope: string } | null>(null)
  const [details, setDetails] = useState<CatalogNode | null>(null)
  const [clone, setClone] = useState<{ node: CatalogNode; scope: string } | null>(null)
  const action = useAction()
  // The catalog already loads on mount; only later parent refreshes need another read.
  const refreshRevision = useRef(props.refreshRevision)
  useEffect(() => { if (refreshRevision.current === props.refreshRevision) return; refreshRevision.current = props.refreshRevision; catalog.reload() }, [props.refreshRevision, catalog.reload])
  const all = catalog.data ?? []
  const visible = filterCatalog(all.filter(node => !props.excludedKeys.includes(catalogKey(node))), { ...filter, server: props.server, serverRole: props.initialServerRole }).sort((a, b) => sort === 'name' ? a.name.localeCompare(b.name, 'zh-CN') || catalogKey(a).localeCompare(catalogKey(b)) : sort === 'protocol' ? (a.protocol ?? '').localeCompare(b.protocol ?? '') || a.name.localeCompare(b.name) : a.sort_order - b.sort_order || a.kind.localeCompare(b.kind) || a.id - b.id)
  const pages = Math.max(1, Math.ceil(visible.length / size)), currentPage = Math.min(page, pages)
  const rows = visible.slice((currentPage - 1) * size, currentPage * size)
  const selected = all.filter(node => selection.includes(catalogKey(node)))
  const scope = () => JSON.stringify({ ...filterRef.current, server: props.getServer(), serverRole: props.initialServerRole ?? 'any' })
  const stale = () => resourceWriteError(catalog) || props.managedWriteError()
  const mutationError = (nodes: CatalogNode[]) => stale() || catalogMutationError(catalog.getCurrent?.(), nodes, props.getServer(), props.initialServerRole)
  const refresh = () => { catalog.reload(); props.onChanged() }
  const change = (key: keyof typeof filter, value: string) => { filterRef.current = { ...filterRef.current, [key]: value }; setFilter(filterRef.current); if (key === 'kind') props.onKind(value); setPage(1) }
  const toggle = (node: CatalogNode) => setSelection(value => value.includes(catalogKey(node)) ? value.filter(key => key !== catalogKey(node)) : value.length < 200 ? [...value, catalogKey(node)] : value)
  const openBatch = (mode: string, nodes = selected) => { if (mutationError(nodes)) return; action.clearError(); setBatch({ mode, nodes, scope: scope() }) }
  useEffect(() => { if (!props.metadataTarget) return; const node = catalog.getCurrent?.()?.find(node => catalogKey(node) === catalogKey(props.metadataTarget!)); if (node) openBatch('metadata', [node]); props.onMetadataOpened() }, [props.metadataTarget])
  const apply = (items: object[]) => api(`${root}/node-catalog/batch`, 'POST', { items })
  const move = (node: CatalogNode, offset: number) => {
    if (mutationError([node])) return
    const current = catalog.getCurrent?.(); if (!current) return
    const ordered = [...current].sort((a, b) => a.sort_order - b.sort_order || a.kind.localeCompare(b.kind) || a.id - b.id)
    const currentVisible = filterCatalog(current, { ...filterRef.current, server: props.getServer(), serverRole: props.initialServerRole }).sort((a, b) => a.sort_order - b.sort_order || a.kind.localeCompare(b.kind) || a.id - b.id)
    const neighbor = currentVisible[currentVisible.findIndex(value => catalogKey(value) === catalogKey(node)) + offset]
    if (!neighbor || mutationError([node, neighbor])) return
    const index = ordered.findIndex(value => catalogKey(value) === catalogKey(node)), other = ordered.findIndex(value => catalogKey(value) === catalogKey(neighbor))
    // Normalize a small catalog to distinct ranks so tied defaults cannot jump other rows.
    if (ordered.length > 200) { openBatch('order', [node]); return }
    ;[ordered[index], ordered[other]] = [ordered[other], ordered[index]]
    void action.run(() => apply(ordered.map((value, position) => ({ ...catalogRef(value), sort_order: position }))), refresh)
  }
  const actions = (node: CatalogNode) => {
    const managed = node.kind !== 'external' ? props.nodes.find(value => value.id === (node.entry_node_id ?? node.id)) : undefined
    return <div className="row-actions catalog-actions">{node.kind === 'external' ? <button className="text-button" onClick={() => setDetails(node)}>详情</button> : <><a className="text-button" href={resourceLink(node as ProxyResource)}>详情</a><button className="text-button" onClick={() => props.onDeployment(node.server_id!)}>部署</button>{node.kind === 'direct' && <button className="text-button" disabled={!managed} onClick={() => managed && props.onEdit(managed)}>编辑</button>}</>}
      <button className="text-button" disabled={Boolean(stale())} onClick={() => openBatch('metadata', [node])}>整理</button>
      {node.kind === 'direct' && <button className="text-button" disabled={Boolean(stale())} onClick={() => { if (!mutationError([node])) setClone({ node, scope: scope() }) }}>复制</button>}
      <button className="text-button danger-text" disabled={Boolean(stale())} onClick={() => { if (mutationError([node])) return; if (node.kind === 'external') openBatch('delete', [node]); else props.onDelete(node as ProxyResource) }}>删除</button>
      {sort === 'custom' && <><button className="text-button" aria-label={`上移 ${node.name}`} disabled={action.busy || Boolean(stale()) || catalogKey(node) === catalogKey(visible[0])} onClick={() => move(node, -1)}>↑</button><button className="text-button" aria-label={`下移 ${node.name}`} disabled={action.busy || Boolean(stale()) || catalogKey(node) === catalogKey(visible.at(-1)!)} onClick={() => move(node, 1)}>↓</button></>}
    </div>
  }
  const publicEndpoint = (node: CatalogNode) => node.public_host && node.port !== null ? endpoint(node.public_host, props.nodes.find(value => node.kind !== 'external' && value.id === (node.entry_node_id ?? node.id))?.settings?.public_port ?? node.port) : '未知端点'
  const title = (node: CatalogNode) => <div><strong>{node.name}</strong><small>{kinds[node.kind]} · {(node.protocol && protocolNames[node.protocol]) ?? node.protocol ?? '未知协议'}</small><div className="catalog-tags">{node.tags.map(tag => <button key={tag} onClick={() => change('tag', tag)} className="catalog-tag">{tag}</button>)}</div>{node.note && <small className="catalog-note" title={node.note}>{node.note}</small>}</div>
  const status = (node: CatalogNode) => <><Badge tone={stale() ? 'neutral' : !node.enabled ? 'neutral' : node.available ? 'good' : 'warm'}>{stale() ? '资源状态待确认' : !node.enabled ? '已停用' : node.kind === 'external' ? node.available ? '可分配' : '不可分配' : node.available ? '可用' : '待就绪'}</Badge><small>{node.kind === 'external' ? node.last_error ? sourceReason(node.last_error) : '由来源提供服务' : `${roleNames[node.role as ProxyResource['role']]} · ${stageName(node.stage)}`}</small></>
  const traffic = (node: CatalogNode) => { const record = props.usage?.by_node.find(value => value.node_id === (node.entry_node_id ?? node.id)); return node.kind === 'external' ? '提供方计量' : record ? bytes(totalBytes(record.uplink, record.downlink)) : props.usage ? '0 B' : '暂无数据' }
  return <section className="panel node-catalog" aria-label="节点库">
    <div className="panel-heading"><h2>节点库 <span className="count">{all.length}</span></h2><span className="subtle">受管 {all.filter(node => node.kind !== 'external').length} · 外部 {all.filter(node => node.kind === 'external').length}</span></div>
    <div className="catalog-filters"><input aria-label="搜索代理资源" placeholder="搜索名称、地址、标签或备注" value={filter.search} onChange={event => change('search', event.target.value)} />
      <select aria-label="按类型筛选" value={filter.kind} onChange={event => change('kind', event.target.value)}><option value="">全部类型</option>{Object.entries(kinds).map(([value, name]) => <option key={value} value={value}>{name}</option>)}</select>
      <select aria-label="按协议筛选" value={filter.protocol} onChange={event => change('protocol', event.target.value)}><option value="">全部协议</option>{[...new Set(all.flatMap(node => node.protocol ? [node.protocol] : []))].sort().map(value => <option key={value}>{value}</option>)}</select>
      <select aria-label="按标签筛选" value={filter.tag} onChange={event => change('tag', event.target.value)}><option value="">全部标签</option>{[...new Set(all.flatMap(node => node.tags))].sort().map(value => <option key={value}>{value}</option>)}</select>
      <select aria-label="按状态筛选" value={filter.status} onChange={event => change('status', event.target.value)}><option value="">全部状态</option><option value="available">可用 / 可分配</option><option value="unavailable">待就绪 / 不可分配</option><option value="disabled">已停用</option></select>
      <select aria-label="按服务器筛选" value={props.server} onChange={event => { props.onServer(event.target.value); setPage(1) }}><option value="">全部服务器</option>{props.server && !props.servers.some(server => String(server.id) === props.server) && <option value={props.server}>指定服务器尚未启用或不存在</option>}{props.servers.map(server => <option key={server.id} value={server.id}>{server.name}</option>)}</select>
      <select aria-label="按来源筛选" value={filter.source} onChange={event => change('source', event.target.value)}><option value="">全部来源</option>{[...new Map(all.filter(node => node.source_id).map(node => [node.source_id, node.source_name])).entries()].map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select>
      <select aria-label="按角色筛选" value={filter.role} onChange={event => change('role', event.target.value)}><option value="">全部角色</option>{Object.entries(roleNames).map(([key, value]) => <option key={key} value={key}>{value}</option>)}<option value="external">外部节点</option></select>
      <select aria-label="节点排序" value={sort} onChange={event => { setSort(event.target.value); setPage(1) }}><option value="custom">自定义顺序</option><option value="name">名称</option><option value="protocol">协议</option></select>
    </div>
    <div className="catalog-selection"><label><input type="checkbox" aria-label="选择本页节点" checked={!!rows.length && rows.every(node => selection.includes(catalogKey(node)))} onChange={event => setSelection(event.target.checked ? [...new Set([...selection, ...rows.map(catalogKey)])].slice(0, 200) : selection.filter(key => !rows.some(node => catalogKey(node) === key)))} /> 本页</label><span>已选 {selected.length} 项</span><button className="text-button" disabled={!visible.length || visible.length > 200} onClick={() => setSelection(visible.map(catalogKey))}>选择筛选结果（{visible.length}）</button><button className="text-button" onClick={() => setSelection([])} disabled={!selection.length}>清空</button>
      {selected.length > 0 && <div className="row-actions"><button className="text-button" disabled={Boolean(stale())} onClick={() => openBatch('rename')}>批量改名</button><button className="text-button" disabled={Boolean(stale())} onClick={() => openBatch('tags')}>批量标签</button><button className="text-button" disabled={Boolean(stale())} onClick={() => openBatch('enable')}>启用</button><button className="text-button" disabled={Boolean(stale())} onClick={() => openBatch('disable')}>停用</button><button className="text-button danger-text" disabled={Boolean(stale())} onClick={() => openBatch('delete')}>批量删除</button></div>}
    </div>
    <ErrorNotice message={catalog.error || (!batch ? action.error : '')} retry={catalog.reload} />
    {catalog.loading && !catalog.data ? <Loading /> : !rows.length ? <Empty icon="nodes" title="没有符合条件的节点" description="创建受管节点，或从下方订阅来源导入外部节点。" /> : <>
      <div className="table-wrap catalog-table"><table><thead><tr><th>选择</th><th>节点 / 链路</th><th>服务器 / 来源</th><th>公开地址</th><th>状态</th><th>累计流量</th><th>操作</th></tr></thead><tbody>{rows.map(node => <tr key={catalogKey(node)} data-resource-key={catalogKey(node)}><td><input type="checkbox" aria-label={`选择 ${node.name}`} checked={selection.includes(catalogKey(node))} onChange={() => toggle(node)} /></td><td>{title(node)}</td><td>{node.kind === 'external' ? node.source_name : <a href={`#/servers/${node.server_id}`}>{node.server_name}</a>}</td><td><code>{publicEndpoint(node)}</code><small>{node.udp ? 'TCP / UDP' : '仅 TCP'}</small></td><td>{status(node)}</td><td>{traffic(node)}</td><td>{actions(node)}</td></tr>)}</tbody></table></div>
      <div className="catalog-cards">{rows.map(node => <article key={catalogKey(node)} className="catalog-card" data-resource-key={catalogKey(node)}><div className="catalog-card-heading"><input type="checkbox" aria-label={`选择 ${node.name}`} checked={selection.includes(catalogKey(node))} onChange={() => toggle(node)} />{title(node)}</div><div className="catalog-card-meta"><span>{node.server_name ?? node.source_name}</span><code>{publicEndpoint(node)}</code>{status(node)}<span>{traffic(node)}</span></div>{actions(node)}</article>)}</div>
    </>}
    <div className="catalog-pagination"><span>共 {visible.length} 项 · 第 {currentPage} / {pages} 页</span><div className="row-actions"><select aria-label="每页节点数" value={size} onChange={event => { setSize(Number(event.target.value)); setPage(1) }}>{[20, 50, 100, 200].map(value => <option key={value} value={value}>{value} 项 / 页</option>)}</select><button className="button button-secondary button-small" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>上一页</button><button className="button button-secondary button-small" disabled={currentPage === pages} onClick={() => setPage(currentPage + 1)}>下一页</button></div></div>
    {batch && <CatalogBatch mode={batch.mode} nodes={batch.nodes} current={() => catalog.getCurrent?.()} stale={() => stale() || (scope() !== batch.scope ? '筛选范围已改变；请重新确认，当前草稿已保留。' : '')} server={() => props.getServer()} serverRole={props.initialServerRole} onClose={() => setBatch(null)} onSaved={() => { setBatch(null); setSelection([]); refresh() }} />}
    {details && <Modal title={details.name} onClose={() => setDetails(null)}><div className="modal-body"><dl className="catalog-detail"><dt>来源</dt><dd>{details.source_name}</dd><dt>原始名称</dt><dd>{details.original_name}</dd><dt>节点端点</dt><dd>{details.protocol} · {details.public_host && details.port !== null ? endpoint(details.public_host, details.port) : '未知端点'}</dd><dt>当前版本</dt><dd>{details.version_id ? `#${details.version_id}` : '未知版本'} · 来源代次 {details.identity_epoch}</dd><dt>备注</dt><dd>{details.note || '—'}</dd></dl><p className="helper">从代理用户页面分配此节点。连接凭据仅在授权订阅中提供，运行状态与用量由来源管理。</p><a className="button button-primary" href="#/plugins/sing-box/users" onClick={() => setDetails(null)}>分配给代理用户</a></div></Modal>}
    {clone && <CloneNode node={clone.node} servers={props.servers} getServers={props.getServers} stale={() => mutationError([clone.node]) || (scope() !== clone.scope ? '筛选范围已改变；请重新确认，当前草稿已保留。' : '')} onClose={() => setClone(null)} onSaved={() => { setClone(null); refresh() }} />}
  </section>
}

function CatalogBatch({ mode, nodes, current, stale, server, serverRole, onClose, onSaved }: { mode: string; nodes: CatalogNode[]; current: () => CatalogNode[] | undefined; stale: () => string; server: () => string; serverRole?: 'any' | 'entry' | 'middle' | 'exit'; onClose: () => void; onSaved: () => void }) {
  const action = useAction()
  const [renameMode, setRenameMode] = useState('prefix'), [value, setValue] = useState(''), [replacement, setReplacement] = useState('')
  const [tagMode, setTagMode] = useState('append'), [tags, setTags] = useState(mode === 'metadata' ? nodes[0].tags.join(', ') : '')
  const [name, setName] = useState(nodes[0].name), [note, setNote] = useState(nodes[0].note), [order, setOrder] = useState(String(nodes[0].sort_order))
  const writeError = () => stale() || catalogMutationError(current(), nodes, server(), serverRole)
  const error = writeError()
  const submit = () => void action.run(async () => {
    const currentError = writeError(); if (currentError) throw new Error(currentError)
    const parsed = parsedTags(tags)
    if (['tags', 'metadata'].includes(mode) && tagsError(parsed)) throw new Error(tagsError(parsed))
    const items = nodes.map(node => {
      const fields: Record<string, unknown> = { ...catalogRef(node) }
      if (mode === 'rename') fields.name = renamed(node.name, renameMode, value, replacement)
      if (mode === 'tags') fields.tags = tagMode === 'replace' ? parsed : tagMode === 'remove' ? node.tags.filter(tag => !parsed.includes(tag)) : [...new Set([...node.tags, ...parsed])]
      if (mode === 'enable' || mode === 'disable') fields.enabled = mode === 'enable'
      if (mode === 'metadata') { if (name.trim() !== nodes[0].name) fields.name = name.trim(); fields.tags = parsed; fields.note = note; fields.sort_order = Number(order) }
      if (mode === 'order') fields.sort_order = Number(order)
      if (fields.name !== undefined && (!fields.name || Array.from(String(fields.name)).length > 128)) throw new Error('节点名称不能为空，且不能超过 128 个字符。')
      if (fields.tags && tagsError(fields.tags as string[])) throw new Error(tagsError(fields.tags as string[]))
      if (fields.sort_order !== undefined && !Number.isSafeInteger(fields.sort_order)) throw new Error('排序值须为安全范围内的整数。')
      return fields
    })
    return api(`${root}/node-catalog/batch`, mode === 'delete' ? 'DELETE' : 'POST', { items })
  }, onSaved)
  const titles: Record<string, string> = { rename: '批量改名', tags: '批量标签', enable: '启用节点', disable: '停用节点', delete: '删除节点', metadata: '整理节点', order: '调整顺序' }
  if (['delete', 'enable', 'disable'].includes(mode)) return <Confirm title={`${titles[mode]}（${nodes.length} 项）`} busy={action.busy} error={error || action.error} confirmDisabled={Boolean(error)} confirmLabel={`确认${titles[mode]}`} busyLabel="正在提交…" onClose={onClose} onConfirm={submit}><span>{nodes.map(node => node.name).join('、')}</span><br />{mode === 'delete' ? '操作会先核对全部引用，任一节点无法删除则整批不变。历史流量与版本保留。' : '受管节点等待设备应用后生效；外部节点只改变后续订阅分发，已下载凭据及现有链路不因此失效。'}</Confirm>
  return <FormDialog title={`${titles[mode]}（${nodes.length} 项）`} wide onClose={onClose} onSubmit={submit} busy={action.busy} error={error || action.error} submitDisabled={Boolean(error)} submitLabel="确认保存">
    {mode === 'rename' && <><Field label="改名方式"><select value={renameMode} onChange={event => setRenameMode(event.target.value)}><option value="prefix">添加前缀</option><option value="suffix">添加后缀</option><option value="replace">替换文本</option></select></Field><Field label={renameMode === 'replace' ? '查找文本' : '添加文本'}><input required value={value} onChange={event => setValue(event.target.value)} maxLength={128} /></Field>{renameMode === 'replace' && <Field label="替换为"><input value={replacement} onChange={event => setReplacement(event.target.value)} maxLength={128} /></Field>}<div className="table-wrap"><table><thead><tr><th>原名称</th><th>预览</th></tr></thead><tbody>{nodes.map(node => <tr key={catalogKey(node)}><td>{node.name}</td><td>{renamed(node.name, renameMode, value, replacement)}</td></tr>)}</tbody></table></div></>}
    {mode === 'tags' && <Field label="标签操作"><select value={tagMode} onChange={event => setTagMode(event.target.value)}><option value="append">追加标签</option><option value="replace">替换全部标签</option><option value="remove">移除指定标签</option></select></Field>}
    {mode === 'metadata' && <Field label="显示名称"><input required maxLength={128} value={name} onChange={event => setName(event.target.value)} /></Field>}
    {['tags', 'metadata'].includes(mode) && <Field label="标签" hint="逗号分隔，最多 16 个。"><input value={tags} onChange={event => setTags(event.target.value)} /></Field>}
    {mode === 'metadata' && <Field label="备注"><textarea rows={3} value={note} maxLength={1024} onChange={event => setNote(event.target.value)} /></Field>}
    {['metadata', 'order'].includes(mode) && <Field label="排序值" hint="数值越小越靠前。"><input type="number" step={1} required value={order} onChange={event => setOrder(event.target.value)} /></Field>}
  </FormDialog>
}

function CloneNode({ node, servers, getServers, stale, onClose, onSaved }: { node: CatalogNode; servers: PluginServer[]; getServers: () => PluginServer[] | undefined; stale: () => string; onClose: () => void; onSaved: () => void }) {
  const action = useAction()
  const [serverId, setServerId] = useState(String(node.server_id ?? ''))
  const selectedServer = useRef(serverId); selectedServer.current = serverId
  const targetError = () => getServers()?.some(server => server.enabled === true && Number.isSafeInteger(server.id) && server.id > 0 && String(server.id) === selectedServer.current) ? '' : '目标服务器已不存在或未启用，请明确重新选择；当前草稿已保留。'
  const writeError = () => stale() || targetError()
  return <FormDialog title={`复制「${node.name}」`} onClose={onClose} busy={action.busy} error={writeError() || action.error} submitDisabled={Boolean(writeError())} submitLabel="创建副本" onSubmit={form => void action.run(() => { if (writeError()) throw new Error(writeError()); return api(`${root}/nodes/${node.id}/clone`, 'POST', { revision: node.revision, name: String(form.get('name')).trim(), server_id: Number(selectedServer.current), public_host: String(form.get('public_host')).trim(), ...(form.get('port') ? { port: Number(form.get('port')) } : {}) }) }, onSaved)}>
    <Field label="副本名称"><input name="name" required maxLength={128} defaultValue={`${node.name} 副本`} /></Field><Field label="目标服务器"><select name="server_id" required value={serverId} onChange={event => { selectedServer.current = event.target.value; setServerId(event.target.value) }}>{serverId && !servers.some(server => server.enabled && String(server.id) === serverId) && <option value={serverId}>已选服务器已不存在或未启用（原选择保留）</option>}{servers.filter(server => server.enabled).map(server => <option key={server.id} value={server.id}>{server.name}</option>)}</select></Field><Field label="公开地址"><input name="public_host" required defaultValue={node.public_host ?? ''} /></Field><Field label="监听端口" hint="留空自动分配。"><input name="port" type="number" min={1} max={65535} /></Field><p className="helper">复制协议设置并重新生成连接身份，不复制代理用户授权。使用证书的节点请确认目标服务器和域名的证书设置。</p>
  </FormDialog>
}
