import { useRef, useState } from 'react'
import { api } from '../../api'
import { Confirm, Empty, ErrorNotice, Field, FormDialog, Loading, PageHeader, Refresh } from '../../components'
import { bytes } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import { quotaBytes, scheduleText, validatedSnapshot, validProxyResources } from './groupTypes'
import type { ProxyResource, PackageGroup, PolicyGroup } from './groupTypes'
import { mergeResourceInventory, validFlatInventory } from './resourceInventory'
import type { ProxyResource as FlatResource } from './resourceTypes'

const root = '/api/plugins/sing-box'
type Tab = 'policy-groups' | 'package-groups'
type EditorInput = { kind: 'policy-groups'; value?: PolicyGroup } | { kind: 'package-groups'; value?: PackageGroup }
type Editor = { kind: 'policy-groups'; value?: PolicyGroup; nodeIds: number[]; chainIds: number[] } | { kind: 'package-groups'; value?: PackageGroup }
const labels: Record<Tab, string> = { 'policy-groups': '策略组', 'package-groups': '套餐组' }

export default function Groups({ initialTab = 'policy-groups' }: { initialTab?: Tab } = {}) {
  const policies = useResource<PolicyGroup[]>(`${root}/policy-groups`)
  const packages = useResource<PackageGroup[]>(`${root}/package-groups`)
  const resourceQuery = useResource<unknown>(`${root}/ordered-proxy-resources`)
  const flatQuery = useResource<unknown>(`${root}/proxy-resources`)
  const flatHistory = useRef<FlatResource[] | undefined>(undefined)
  const flat = validatedSnapshot(flatQuery, validFlatInventory, flatHistory.current)
  if (flat.fresh) flatHistory.current = flat.data
  const resourceHistory = useRef<ProxyResource[] | undefined>(undefined)
  const resources = validatedSnapshot(resourceQuery, validProxyResources, resourceHistory.current)
  if (resources.fresh) resourceHistory.current = resources.data
  const inventory = mergeResourceInventory(flat.data ?? [], resources.data ?? [])
  const nodes = inventory.filter(resource => resource.kind === 'direct')
  const chains = inventory.filter(resource => resource.kind === 'chain')
  const currentInventory = () => mergeResourceInventory(flat.getCurrent?.() ?? [], resources.getCurrent?.() ?? [])
  const action = useAction()
  const [tab, setTab] = useState<Tab>(initialTab)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [deleting, setDeleting] = useState<{ kind: Tab; id: number; name: string } | null>(null)
  const policyWriteError = resourceWriteError(policies, packages, flat, resources)
  const packageWriteError = resourceWriteError(policies, packages, flat, resources)
  const writeError = (kind: Tab, id?: number) => {
    const dependencyError = resourceWriteError(policies, packages, flat, resources)
    if (dependencyError) return dependencyError
    const data = kind === 'policy-groups' ? policies.getCurrent() : packages.getCurrent()
    return id !== undefined && !data?.some(value => value.id === id) ? '此资源已不可用，暂不能提交。草稿已保留，可关闭窗口后重新选择。' : ''
  }
  const invalidNodes = editor?.kind === 'policy-groups' ? editor.nodeIds.filter(id => !nodes.some(node => node.id === id && node.available)) : []
  const invalidChains = editor?.kind === 'policy-groups' ? editor.chainIds.filter(id => !chains.some(chain => chain.id === id && chain.available)) : []
  const currentSelectionError = () => editor?.kind === 'policy-groups' && [...editor.nodeIds.map(id => ({ kind: 'direct', id })), ...editor.chainIds.map(id => ({ kind: 'chain', id }))].some(selected => !currentInventory().some(value => value.kind === selected.kind && value.id === selected.id && value.available)) ? '已选资源已不可用或身份已变更，请取消这些选择后再保存；其余草稿已保留。' : ''
  const selectionError = invalidNodes.length || invalidChains.length ? '已选资源已不可用或身份已变更，请取消这些选择后再保存。其余草稿已保留。' : ''
  const refresh = () => { policies.reload(); packages.reload(); resourceQuery.reload(); flatQuery.reload() }
  const nodeName = (id: number) => nodes.find(n => n.id === id)?.name ?? `节点 #${id}（已不可用）`
  const open = (value: EditorInput) => {
    if (writeError(value.kind, value.value?.id)) return
    action.clearError()
    setEditor(value.kind === 'policy-groups' ? { ...value, nodeIds: [...(value.value?.node_ids ?? [])], chainIds: [...(value.value?.chain_ids ?? [])] } : value)
  }
  const choose = (kind: 'nodeIds' | 'chainIds', id: number, checked: boolean) => { if (resourceWriteError(policies, packages, flat, resources)) return; setEditor(previous => previous?.kind === 'policy-groups' ? { ...previous, [kind]: checked ? [...previous[kind], id] : previous[kind].filter(value => value !== id) } : previous) }
  const remove = (kind: Tab, value: { id: number; name: string }) => { if (writeError(kind, value.id)) return; action.clearError(); setDeleting({ kind, ...value }) }
  const submit = (form: FormData) => {
    if (!editor || writeError(editor.kind, editor.value?.id) || currentSelectionError()) return
    void action.run(async () => {
      const name = String(form.get('name') ?? '').trim()
      const value = 'value' in editor ? editor.value : undefined
      const body = editor.kind === 'policy-groups' ? { name, node_ids: editor.nodeIds, chain_ids: editor.chainIds }
        : { name, monthly_bytes: quotaBytes(String(form.get('amount') ?? ''), String(form.get('unit'))), reset_day: Number(form.get('reset_day')), reset_hour: Number(String(form.get('reset_time')).split(':')[0]), reset_minute: Number(String(form.get('reset_time')).split(':')[1]), timezone: String(form.get('timezone')), duration_days: Number(form.get('duration_days')) }
      return api(`${root}/${editor.kind}${value ? `/${value.id}` : ''}`, value ? 'PUT' : 'POST', body)
    }, () => { setEditor(null); refresh() })
  }
  return <>
    <PageHeader eyebrow="sing-box 插件" title="策略与套餐" description="把节点与链路整理成策略组，用套餐设定流量与有效期，在代理用户页面分别分配。"><Refresh onClick={refresh} /><a className="button button-secondary" href="#/plugins/sing-box/nodes">管理代理节点</a><a className="button button-secondary" href="#/plugins/sing-box/users">分配给代理用户</a></PageHeader>
    <div className="group-tabs ui-tab-list" role="group" aria-label="管理内容">{(Object.keys(labels) as Tab[]).map(key => <button type="button" key={key} aria-pressed={tab === key} onClick={() => setTab(key)}>{labels[key]}</button>)}</div>
    <ErrorNotice message={policies.error || packages.error || flat.error || resources.error} retry={refresh} />
    <section className="panel">
      {writeError(tab) && <p className="helper" role="status">{writeError(tab)}</p>}
      <div className="panel-heading"><h2>{labels[tab]}</h2><button className="button button-primary button-small" onClick={() => open({ kind: tab })} disabled={action.busy || Boolean(writeError(tab))}>创建{labels[tab]}</button></div>
      {tab === 'policy-groups' && (policies.loading && !policies.data ? <Loading /> : !policies.data?.length ? <Empty icon="nodes" title="把常用节点放进一个策略组" description="一个用户可分配多个策略组；重叠的节点只授权一次。修改组内节点后，所有已分配用户随之更新。" /> : <div className="table-wrap"><table><thead><tr><th>策略组</th><th>可用节点与链路</th><th>已分配用户</th><th>操作</th></tr></thead><tbody>{policies.data.map(p => <tr key={p.id}><td><strong>{p.name}</strong></td><td>{[...p.node_ids.map(nodeName), ...p.chain_ids.map(id => chains.find(c => c.id === id)?.name ?? `链路 #${id}`)].join('、') || '空组，不授予节点'}</td><td>{p.member_count}</td><td><div className="row-actions"><button className="text-button" disabled={action.busy || Boolean(policyWriteError)} onClick={() => open({ kind: 'policy-groups', value: p })}>编辑</button><button className="text-button danger-text" disabled={action.busy || Boolean(policyWriteError)} onClick={() => remove('policy-groups', p)}>删除</button></div></td></tr>)}</tbody></table></div>)}
      {tab === 'package-groups' && (packages.loading && !packages.data ? <Loading /> : !packages.data?.length ? <Empty icon="activity" title="为不同用量创建套餐" description="例如每月 500 GiB、每月 1 日零点重置、使用 365 天。每位用户的套餐独立计量，不共用总额度。" /> : <div className="table-wrap"><table><thead><tr><th>套餐组</th><th>每月流量</th><th>重置时间</th><th>有效期</th><th>操作</th></tr></thead><tbody>{packages.data.map(p => <tr key={p.id}><td><strong>{p.name}</strong></td><td>{p.monthly_bytes === null ? '不限量' : bytes(p.monthly_bytes)}</td><td>{scheduleText(p)}</td><td>分配后 {p.duration_days} 天</td><td><div className="row-actions"><button className="text-button" disabled={action.busy || Boolean(packageWriteError)} onClick={() => open({ kind: 'package-groups', value: p })}>编辑</button><button className="text-button danger-text" disabled={action.busy || Boolean(packageWriteError)} onClick={() => remove('package-groups', p)}>删除</button></div></td></tr>)}</tbody></table></div>)}
      <div className="panel-body"><p className="helper">{tab === 'policy-groups' ? '多个策略组与单独授权取并集。只取消一个来源，不会撤销其他来源仍授予的节点。' : '套餐修改仅影响之后的分配；已分配用户保留原有套餐快照。29 至 31 日在短月份按月末重置，下一月仍按原设定日期计算。'}</p><a className="text-button" href="#/plugins/sing-box/nodes?kind=chains">管理链路</a></div>
    </section>
    {editor && <FormDialog title={`${'value' in editor && editor.value ? '编辑' : '创建'}${labels[editor.kind]}`} onClose={() => setEditor(null)} onSubmit={submit} busy={action.busy} disabled={Boolean(writeError(editor.kind, editor.value?.id))} submitDisabled={Boolean(selectionError)} error={writeError(editor.kind, editor.value?.id) || selectionError || action.error} retry={writeError(editor.kind, editor.value?.id) ? refresh : undefined}>
      <Field label="名称"><input name="name" required maxLength={128} defaultValue={'value' in editor ? editor.value?.name ?? '' : ''} autoComplete="off" /></Field>
      {editor.kind === 'policy-groups' && <>
        <fieldset className="group-choices"><legend>直接连接的节点</legend>{nodes.map(n => <label className="group-choice" key={`direct:${n.id}`}><input name="node_ids" type="checkbox" value={n.id} checked={editor.nodeIds.includes(n.id)} disabled={!n.available && !editor.nodeIds.includes(n.id)} onChange={event => choose('nodeIds', n.id, event.target.checked)} /><span>{n.name}<small>{n.description}{!n.available && '（已不可用，请取消选择）'}</small></span></label>)}{invalidNodes.filter(id => !nodes.some(node => node.id === id)).map(id => <label className="group-choice" key={`unavailable-${id}`}><input name="node_ids" type="checkbox" value={id} checked onChange={event => choose('nodeIds', id, event.target.checked)} /><span>{nodeName(id)}<small>当前不能作为普通节点授权，请取消选择。</small></span></label>)}{!nodes.length && <p>请先创建代理节点。</p>}</fieldset>
        <fieldset className="group-choices"><legend>通过入口连接的链路</legend>{chains.map(c => <label className="group-choice" key={`chain:${c.id}`}><input name="chain_ids" type="checkbox" value={c.id} checked={editor.chainIds.includes(c.id)} onChange={event => choose('chainIds', c.id, event.target.checked)} disabled={!c.available && !editor.chainIds.includes(c.id)} /><span>{c.name}<small>{c.description}{!c.available && '（已不可用，请取消选择）'}</small></span></label>)}{invalidChains.filter(id => !chains.some(chain => chain.id === id)).map(id => <label className="group-choice" key={`unavailable-${id}`}><input name="chain_ids" type="checkbox" value={id} checked onChange={event => choose('chainIds', id, event.target.checked)} /><span>链路 #{id}<small>当前不可用，请取消选择。</small></span></label>)}{!chains.length && <p>尚未创建链路，可先只选择节点，或<a className="text-button" href="#/plugins/sing-box/nodes?kind=chains">创建链路</a>。</p>}</fieldset>
        {editor.value && <p className="helper">保存后会更新此组的 {editor.value.member_count} 位用户。新增授权等待设备应用，撤销授权同时移出订阅。</p>}
      </>}
      {editor.kind === 'package-groups' && <PackageFields value={editor.value} />}
    </FormDialog>}
    {deleting && <Confirm title={`删除「${deleting.name}」？`} busy={action.busy} disabled={Boolean(writeError(deleting.kind, deleting.id))} error={writeError(deleting.kind, deleting.id) || action.error} retry={writeError(deleting.kind, deleting.id) ? refresh : undefined} onClose={() => setDeleting(null)} onConfirm={() => { if (writeError(deleting.kind, deleting.id)) return; void action.run(() => api(`${root}/${deleting.kind}/${deleting.id}`, 'DELETE'), () => { setDeleting(null); refresh() }) }}>{deleting.kind === 'package-groups' ? '已分配用户的套餐与历史用量保持不变；此套餐不再提供新的分配。' : '已分配给用户的策略组不能直接删除，请先在用户页面取消分配。'}</Confirm>}
  </>
}

function PackageFields({ value }: { value?: PackageGroup }) {
  const gib = !value || (value.monthly_bytes !== null && BigInt(value.monthly_bytes) % 1073741824n === 0n)
  const amount = !value ? '500' : value.monthly_bytes === null ? '' : (BigInt(value.monthly_bytes) / (gib ? 1073741824n : 1n)).toString()
  return <>
    <div className="group-form-grid"><Field label="每月流量" hint="留空表示不限量；填写正整数。"><input name="amount" inputMode="numeric" pattern="[1-9][0-9]*" defaultValue={amount} /></Field><Field label="流量单位"><select name="unit" defaultValue={gib ? 'GiB' : 'B'}><option value="GiB">GiB（1024³ 字节）</option><option value="B">字节</option></select></Field></div>
    <div className="group-form-grid"><Field label="每月重置日" hint="短月份自动取月末。"><input name="reset_day" type="number" required min={1} max={31} step={1} defaultValue={value?.reset_day ?? 1} /></Field><Field label="重置时间"><input name="reset_time" type="time" required defaultValue={`${String(value?.reset_hour ?? 0).padStart(2, '0')}:${String(value?.reset_minute ?? 0).padStart(2, '0')}`} /></Field></div>
    <Field label="重置时区"><input name="timezone" required maxLength={128} list="group-timezones" defaultValue={value?.timezone ?? 'Asia/Taipei'} /><datalist id="group-timezones"><option value="Asia/Taipei" /><option value="Asia/Shanghai" /><option value="UTC" /><option value="America/New_York" /></datalist></Field>
    <Field label="可使用天数" hint="从分配时刻起计算，每天按 24 小时计。"><input name="duration_days" type="number" required min={1} max={36500} step={1} defaultValue={value?.duration_days ?? 365} /></Field>
    <p className="helper">每月流量按此用户所有节点的上传与下载合计。重新分配套餐不清空本期流水；编辑模板不会追溯修改已分配套餐。</p>
  </>
}
