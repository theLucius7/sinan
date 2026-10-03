import { useEffect, useRef, useState } from 'react'
import { api } from '../../api'
import { Confirm, ErrorNotice, Field, FormDialog, Icon, PageHeader, Refresh, Stat } from '../../components'
import { bytes } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import type { Node, PluginServer, Usage } from '../../types'
import ProtocolFields, { protocolRequest } from './ProtocolFields'
import { ConnectionFields, nodeSettingsRequest } from './NodeSettingsFields'
import NodeDeployment from './NodeDeployment'
import SubscriptionSources from './SubscriptionSources'
import ChainEditor from './ChainEditor'
import ProxyResourceDetail from './ProxyResourceDetail'
import NodeCatalog from './NodeCatalog'
import type { ProxyResource, ResourceKey } from './resourceTypes'
import { resourceLink } from './resourceTypes'
import OrderedResources from './OrderedResources'
import type { ProxyResourceFilter, ProxyResourceServerRole, ProxyResource as OrderedResource } from './groupTypes'
import { validatedSnapshot, validProxyResources } from './groupTypes'
import './nodes.css'

export default function Nodes({ serverId, chainsOnly = false, selected, initialKind, initialServerRole }: { serverId?: number; chainsOnly?: boolean; selected?: ResourceKey; initialKind?: ProxyResourceFilter; initialServerRole?: ProxyResourceServerRole }) {
  const nodes = useResource<Node[]>('/api/plugins/sing-box/nodes')
  const resources = useResource<ProxyResource[]>('/api/plugins/sing-box/proxy-resources')
  const orderedQuery = useResource<unknown>('/api/plugins/sing-box/ordered-proxy-resources')
  const orderedHistory = useRef<OrderedResource[] | undefined>(undefined)
  const ordered = validatedSnapshot(orderedQuery, validProxyResources, orderedHistory.current)
  if (ordered.fresh) orderedHistory.current = ordered.data
  const selectedOrdered = selected?.kind === 'chain' ? ordered.data?.find(resource => resource.kind === selected.kind && resource.id === selected.id) : undefined
  const showFlatDetail = selected && !selectedOrdered && (resources.data?.some(resource => resource.kind === selected.kind && resource.id === selected.id) || ordered.fresh)
  const servers = useResource<PluginServer[]>('/api/plugins/sing-box/servers')
  const usage = useResource<Usage>('/api/plugins/sing-box/usage')
  const action = useAction()
  const [editor, setEditor] = useState<Node | 'new' | null>(null)
  const [draftServer, setDraftServer] = useState('')
  const [deleting, setDeleting] = useState<ProxyResource | null>(null)
  const [filter, setFilter] = useState(serverId === undefined ? '' : String(serverId))
  const currentFilter = useRef(filter)
  useEffect(() => { const value = serverId === undefined ? '' : String(serverId); currentFilter.current = value; setFilter(value) }, [serverId])
  const [kind, setKind] = useState(initialKind === 'direct' ? 'direct' : chainsOnly ? 'chain' : '')
  const [catalogRevision, setCatalogRevision] = useState(0)
  const [catalogMetadata, setCatalogMetadata] = useState<ResourceKey | null>(null)
  useEffect(() => { setKind(initialKind === 'direct' ? 'direct' : chainsOnly ? 'chain' : '') }, [initialKind, chainsOnly])
  const [creatingChain, setCreatingChain] = useState(false)
  const [createdChains, setCreatedChains] = useState<number[]>([])
  const [deployment, setDeployment] = useState<number | null>(null)
  const [saved, setSaved] = useState<number | null>(null)
  const enabledServers = servers.data?.filter(server => server.enabled) ?? []
  const canCreate = !resourceWriteError(nodes, resources, servers) && enabledServers.length > 0 && (!filter || enabledServers.some(server => server.id === Number(filter)))
  const all = resources.data ?? []
  const inventoryCount = all.length + (ordered.data?.filter(resource => resource.kind === 'chain' && resource.path_kind === 'ordered' && !all.some(flat => flat.kind === resource.kind && flat.id === resource.id)).length ?? 0)
  const canCreateChain = canCreate && Boolean(nodes.data && resources.data && !nodes.error && !resources.error)
  const refresh = () => { nodes.reload(); resources.reload(); orderedQuery.reload(); servers.reload(); usage.reload(); setCatalogRevision(value => value + 1) }
  const creationError = () => resourceWriteError(nodes, resources, servers) || (!servers.getCurrent()?.some(server => server.enabled && (!currentFilter.current || server.id === Number(currentFilter.current))) ? '当前筛选中没有可用的入口服务器，请明确选择后再创建。' : '')
  const writeError = (value?: { kind: 'direct' | 'chain'; id: number }) => {
    const stale = resourceWriteError(nodes, resources, servers)
    if (stale) return stale
    return value && !resources.getCurrent()?.some(item => item.kind === value.kind && item.id === value.id) ? '此代理资源已不存在，请重新选择；当前草稿已保留。' : ''
  }
  const nodeDraftError = () => editor && editor !== 'new' && JSON.stringify(nodes.getCurrent()?.find(value => value.id === editor.id)) !== JSON.stringify(editor) ? '节点配置已变化，请重新打开编辑；当前草稿已保留。' : ''
  const nodeServerError = () => editor && !servers.getCurrent()?.some(server => server.id === (editor === 'new' ? Number(draftServer) : editor.server_id) && server.enabled) ? '已选节点所属服务器已不存在或未启用；当前草稿已保留。' : ''
  const editorError = editor ? writeError(editor === 'new' ? undefined : { kind: 'direct', id: editor.id }) || nodeDraftError() || nodeServerError() || (editor === 'new' && !servers.getCurrent()?.some(server => String(server.id) === draftServer && server.enabled) ? '已选服务器已不存在或未启用，请明确重新选择；当前草稿已保留。' : '') : ''
  const currentEditor = editor && editor !== 'new' ? nodes.data?.find(node => node.id === editor.id) : null
  const connectionLocked = Boolean(currentEditor?.configuration_locked || (editor && editor !== 'new' && editor.configuration_locked))
  const deletingError = deleting ? writeError(deleting) : ''
  const edit = (node: Node | 'new') => { if (writeError(node === 'new' ? undefined : { kind: 'direct', id: node.id }) || (node === 'new' && creationError())) return; action.clearError(); setDraftServer(currentFilter.current || String(servers.getCurrent()?.find(server => server.enabled)?.id ?? '')); setEditor(node) }
  const submit = (form: FormData) => {
    if (!editor || writeError(editor === 'new' ? undefined : { kind: 'direct', id: editor.id }) || nodeDraftError() || nodeServerError() || (editor === 'new' && !servers.getCurrent()?.some(server => String(server.id) === draftServer && server.enabled))) return
    const fields = { name: String(form.get('name')).trim(), public_host: String(form.get('public_host')).trim(), sni: String(form.get('sni') ?? '').trim(), protocol_config: protocolRequest(form), enabled: form.get('enabled') === 'on', settings: nodeSettingsRequest(form) }
    const port = String(form.get('port') ?? '').trim()
    const selectedPort = port ? { port: Number(port) } : {}
    const locked = connectionLocked || (editor !== 'new' && nodes.getCurrent()?.find(node => node.id === editor.id)?.configuration_locked)
    const request = editor === 'new' ? { ...fields, ...selectedPort, server_id: Number(draftServer) } : locked ? { name: fields.name, enabled: fields.enabled } : { ...fields, ...selectedPort }
    const serverId = editor === 'new' ? Number(draftServer) : editor!.server_id
    void action.run(() => api(editor === 'new' ? '/api/plugins/sing-box/nodes' : `/api/plugins/sing-box/nodes/${editor?.id}`, editor === 'new' ? 'POST' : 'PATCH', request), () => { setEditor(null); setSaved(serverId); refresh() })
  }
  return <div className="nodes-page" onInvalidCapture={event => { if (event.target instanceof HTMLElement) { const details = event.target.closest('details'); if (details) details.open = true } }}>
    <PageHeader eyebrow="sing-box 插件" title="代理节点" description="统一管理受管节点、有序链路与外部节点，整理来源并分配订阅。"><Refresh onClick={refresh} /><button className="button button-primary" disabled={!canCreate} onClick={() => edit('new')}><Icon name="plus" size={18} />创建节点</button><button className="button button-secondary" disabled={!canCreateChain || creatingChain} onClick={() => { if (creationError()) return; action.clearError(); setCreatingChain(true); setCreatedChains([]) }}>创建链路</button></PageHeader>
    <div className="stats-grid"><Stat icon="nodes" label="代理资源" value={resources.data && ordered.data ? inventoryCount : '—'} note="直连节点与独立链路入口" /><Stat icon="server" label="所在服务器" value={resources.data ? new Set(all.map(node => node.server_id)).size : '—'} note="每台服务器运行一份完整配置" /><Stat icon="nodes" label="物理监听数" value={nodes.data ? nodes.data.length : '—'} note="受管节点监听，不重复计算链路引用" /><Stat icon="activity" label="累计代理流量" value={usage.data ? bytes(usage.data.total) : '—'} note="含已删除节点的历史用量" /></div>
    <ErrorNotice message={resources.error || nodes.error || servers.error || usage.error} retry={refresh} />
    {saved !== null && <div className="notice" role="status"><span>目标已保存；新增有效监听或部署配置变化须完整预检确认，实际应用等待设备回执。</span><button className="text-button" onClick={() => setDeployment(saved)}>查看差异、完整预检与发布状态</button></div>}
    {!!createdChains.length && <div className="notice" role="status"><span>已保存 {createdChains.length} 条链路，正在等待依赖与路径验证。</span><a href={resourceLink({ kind: 'chain', id: createdChains[0] })}>查看链路详情</a></div>}
    {creatingChain && <ChainEditor writeError={() => writeError()} getCurrent={() => ({ nodes: nodes.getCurrent() ?? [], resources: resources.getCurrent() ?? [], servers: servers.getCurrent()?.filter(server => server.enabled) ?? [], entryServerIds: servers.getCurrent()?.filter(server => server.enabled && (!currentFilter.current || server.id === Number(currentFilter.current))).map(server => server.id) ?? [] })} nodes={nodes.data ?? []} resources={all} servers={enabledServers.filter(server => !filter || server.id === Number(filter))} availableServers={enabledServers} onClose={() => setCreatingChain(false)} onSaved={receipt => { setCreatingChain(false); setCreatedChains(receipt.chain_ids); refresh() }} />}
    <NodeCatalog nodes={nodes.data ?? []} servers={enabledServers} getServers={() => servers.getCurrent()} usage={usage.data ?? undefined} server={filter} getServer={() => currentFilter.current} onServer={value => { currentFilter.current = value; setFilter(value) }} kind={kind} onKind={setKind} excludedKeys={(ordered.data ?? []).filter(resource => resource.kind === 'chain' && resource.path_kind === 'legacy').map(resource => `${resource.kind}:${resource.id}`)} metadataTarget={catalogMetadata} onMetadataOpened={() => setCatalogMetadata(null)} initialServerRole={initialServerRole} refreshRevision={catalogRevision} onChanged={refresh} managedWriteError={() => writeError() || resourceWriteError(ordered)} onEdit={edit} onDelete={resource => { if (writeError(resource)) return; action.clearError(); setDeleting(resource) }} onDeployment={setDeployment} />
    <div className="notice quiet-notice"><Icon name="check" size={18} /><div><strong>目标配置与发布</strong><p>保存后等待 5 秒合并处理。新增有效监听或协议、TLS、服务设置变化须先在部署进度内查看差异、采集并确认完整预检；原监听内凭据更新、撤销和停用继续自动处理。未授权给任何用户的节点不会监听端口；订阅只包含设备已成功应用的配置。</p></div></div>
    <div hidden={kind === 'external'}><OrderedResources resourcesQuery={orderedQuery} nodesQuery={nodes} serversQuery={servers} usage={usage} hideFlatRows onOrganize={resource => setCatalogMetadata({ kind: resource.kind, id: resource.id })} flatKeys={all.map(resource => `${resource.kind}:${resource.id}`)} selected={selectedOrdered} onCloseSelected={() => { window.location.hash = '/plugins/sing-box/nodes' }} filter={filter} kind={kind === 'chain' ? 'chains' : kind === 'direct' ? 'direct' : 'all'} initialServerRole={initialServerRole} getServerId={() => currentFilter.current ? Number(currentFilter.current) : undefined} onEdit={edit} onChanged={refresh} /></div>
    {!creatingChain && <SubscriptionSources onChange={refresh} />}
    {showFlatDetail && selected && <ProxyResourceDetail key={`${selected.kind}-${selected.id}`} selected={selected} onClose={() => { window.location.hash = '/plugins/sing-box/nodes' }} onChanged={refresh} onEdit={node => { window.location.hash = '/plugins/sing-box/nodes'; edit(node) }} onDelete={resource => { if (writeError(resource)) return; window.location.hash = '/plugins/sing-box/nodes'; action.clearError(); setDeleting(resource) }} onDeployment={id => { window.location.hash = '/plugins/sing-box/nodes'; setDeployment(id) }} />}
    {editor && <FormDialog wide className="node-editor" title={editor === 'new' ? '创建节点' : '编辑节点'} onClose={() => setEditor(null)} onSubmit={submit} busy={action.busy} submitDisabled={Boolean(editorError)} error={editorError || action.error} submitLabel={editor === 'new' ? '创建目标节点' : '保存目标配置'}>
      <h3>基本信息</h3><div className="node-fields-grid">
      <Field label="节点名称"><input name="name" required maxLength={128} defaultValue={editor === 'new' ? '' : editor.name} placeholder="例如：香港 · 直连" autoComplete="off" /></Field>
      {editor === 'new' && <Field label="所属服务器"><select name="server_id" required value={draftServer} onChange={event => setDraftServer(event.target.value)}>{draftServer && !enabledServers.some(server => String(server.id) === draftServer) && <option value={draftServer}>已选服务器已不存在或未启用（原选择保留）</option>}{enabledServers.map(server => <option key={server.id} value={server.id}>{server.name}{server.online ? ' · 在线' : ' · 离线'}</option>)}</select></Field>}
      <label className="node-switch"><input name="enabled" type="checkbox" defaultChecked={editor === 'new' || editor.enabled !== false} /><span>启用节点<small>停用保留授权与历史流量。</small></span></label>
      </div>
      {connectionLocked && <div className="node-lock-notice" role="status">此节点已被链路引用，当前可修改名称和启用状态。调整连接参数请先替换链路中的节点。<br />{(currentEditor?.referenced_chains ?? (editor === 'new' ? [] : editor.referenced_chains) ?? []).map(chain => <a key={chain.id} href={resourceLink({ kind: 'chain', id: chain.id })} onClick={() => setEditor(null)}>{chain.name}</a>)}</div>}
      <fieldset className="node-connection-fields" disabled={connectionLocked}><h3>连接地址</h3><div className="node-fields-grid">
      <Field label="监听端口" hint={editor === 'new' ? '可填写 443 等端口；留空时从 20000–29999 自动分配。18085 为保留端口。' : '修改后客户端需更新订阅；服务器上已有其他服务占用的端口不可使用。'}><input name="port" type="number" min={1} max={65535} step={1} required={editor !== 'new'} defaultValue={editor === 'new' ? '' : editor.port} placeholder="自动分配" /></Field>
      <Field label="公开地址" hint="填写客户端连接使用的域名或 IP，不含协议、端口和路径。"><input name="public_host" required defaultValue={editor === 'new' ? '' : editor.public_host} placeholder="node.example.com" autoComplete="off" spellCheck={false} /></Field>
      <ConnectionFields node={editor} />
      </div><h3>协议与安全</h3>
      <ProtocolFields key={editor === 'new' ? 'new' : editor.id} node={editor} />
      </fieldset>
    </FormDialog>}
    {deployment !== null && <NodeDeployment serverId={deployment} server={servers.data?.find(server => server.id === deployment)} onClose={() => setDeployment(null)} />}
    {deleting && <Confirm title={`删除「${deleting.name}」？`} busy={action.busy} confirmDisabled={Boolean(deletingError)} error={deletingError || action.error} onClose={() => setDeleting(null)} onConfirm={() => { if (writeError(deleting)) return; void action.run(() => api(deleting.kind === 'chain' ? `/api/plugins/sing-box/proxy-resources/chain/${deleting.id}` : `/api/plugins/sing-box/nodes/${deleting.id}`, 'DELETE'), () => { setDeleting(null); refresh() }) }}>{deleting.kind === 'chain' ? '请先从策略组移除此链路。删除会同时停用专用入口和内部连接，保留历史流量与版本证据；设备应用新配置后停止监听。' : '此节点及其授权将从订阅中移除，历史流量会保留。被链路引用的节点不能直接删除。设备应用新配置后，代理入口停止监听。'}</Confirm>}
  </div>
}
