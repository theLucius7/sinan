import { useState } from 'react'
import { api } from '../../api'
import { Badge, Confirm, ErrorNotice, Field, Modal } from '../../components'
import { useAction, useResource } from '../../hooks'
import type { DnsAccount } from './DnsAccounts'
import DnsResolver from './DnsResolver'

type Record = { id: string; name: string; type: string; content?: string; ttl: number; proxied?: boolean; priority?: number; data?: object; comment?: string; line?: string; provider_state?: string }
type History = { id: string; status: string; error_code: string | null; request: { operation: string }; previous: Record | null; observed: Record | null; occurred_at: number }
type Preview = { preview_id: string; previous: Record | null; desired: object | null; operation: string; expires_at: number }

export default function DnsRecords({ account, close }: { account: DnsAccount; close: () => void }) {
  const cloudflare = account.config.provider === 'cloudflare'
  const lineProvider = ['aliyun', 'tencent'].includes(account.config.provider)
  const recordTypes = ['A','AAAA','CNAME','TXT','MX','NS','SRV','CAA', ...(cloudflare ? ['PTR','HTTPS','SVCB'] : [])]
  const [line, setLine] = useState(account.config.provider === 'aliyun' ? 'default' : '0')
  const [zone, setZone] = useState(account.config.zone_ids[0] ?? '')
  const [page, setPage] = useState(1)
  const rows = useResource<{ records: Record[]; pagination: { total_pages: number }; checked_at: number }>(`/api/plugins/ddns/accounts/${account.id}/records?zone_id=${encodeURIComponent(zone)}&page=${page}`)
  const history = useResource<History[]>(`/api/plugins/ddns/accounts/${account.id}/records/history`)
  const action = useAction()
  const [record, setRecord] = useState<Record | null>(null)
  const [operation, setOperation] = useState('create')
  const [name, setName] = useState(''), [kind, setKind] = useState('A'), [content, setContent] = useState('')
  const [ttl, setTtl] = useState(300), [proxied, setProxied] = useState(false), [priority, setPriority] = useState(10)
  const [data, setData] = useState(''), [comment, setComment] = useState('')
  const [preview, setPreview] = useState<Preview | null>(null), [rollback, setRollback] = useState<History | null>(null)
  const [result, setResult] = useState('')
  const refresh = () => { rows.reload(); history.reload() }
  const edit = (value: Record | null, action: string) => { setRecord(value); setOperation(action); setName(value?.name ?? ''); setKind(value?.type ?? 'A'); setContent(value?.content ?? ''); setTtl(value?.ttl ?? 300); setProxied(value?.proxied ?? false); setLine(value?.line ?? (account.config.provider === 'aliyun' ? 'default' : '0')); setPriority(value?.priority ?? 10); setData(value?.data ? JSON.stringify(value.data, null, 2) : ''); setComment(value?.comment ?? ''); setPreview(null); setResult(''); actionClear() }
  const actionClear = action.clearError
  return <Modal title={`DNS 记录 · ${account.config.name}`} wide busy={action.busy} onClose={close}><div className="modal-body"><ErrorNotice message={rows.error || history.error || action.error} retry={refresh} />
    <Field label="授权区域"><select value={zone} disabled={action.busy} onChange={event => { setZone(event.target.value); setPage(1); setPreview(null); setRecord(null); setResult('') }}>{account.config.zone_ids.map(zone => <option key={zone}>{zone}</option>)}</select></Field>
    <div className="ddns-list">{rows.data?.records.map(value => <article className="ddns-rule" key={value.id}><strong>{value.name} · {value.type}</strong><p className="helper">{value.content ?? JSON.stringify(value.data)} · TTL {value.ttl === 1 ? '自动' : value.ttl} · {value.proxied ? '代理' : '仅 DNS'}{value.line ? ` · 线路 ${value.line}` : ''}{value.provider_state ? ` · ${value.provider_state === 'active' ? '提供方已生效' : '提供方未确认生效'}` : ''}</p><div className="ddns-actions"><button className="text-button" disabled={action.busy} onClick={() => edit(value, 'update')}>编辑并预览</button><button className="text-button danger-text" disabled={action.busy} onClick={() => edit(value, 'delete')}>预览删除</button></div></article>)}</div>
    <div className="ddns-actions"><button className="text-button" disabled={page <= 1 || action.busy} onClick={() => setPage(value => value - 1)}>上一页</button><span>第 {page} 页</span><button className="text-button" disabled={!rows.data || page >= rows.data.pagination.total_pages || action.busy} onClick={() => setPage(value => value + 1)}>下一页</button><button className="text-button" disabled={action.busy} onClick={() => edit(null, 'create')}>新建记录</button></div>
    <form onSubmit={event => { event.preventDefault(); void action.run(async () => {
      const fields = operation === 'delete' ? null : { name, type: kind, ttl, ...(!data.trim() || content ? { content } : {}), ...(cloudflare ? { proxied } : {}), ...(lineProvider ? { line } : {}), ...(kind === 'MX' && (cloudflare || !data.trim()) ? { priority } : {}), ...(data.trim() ? { data: JSON.parse(data) } : {}), ...(comment || record?.comment !== undefined ? { comment } : {}) }
      setPreview(await api(`/api/plugins/ddns/accounts/${account.id}/records/preview`, 'POST', { operation, zone_id: zone, record_id: record?.id ?? null, record: fields }))
    }) }}><h3>{operation === 'create' ? '新建记录' : operation === 'delete' ? '删除所选记录' : '修改所选记录'}</h3>
      {operation !== 'delete' && <div className="form-grid"><Field label="完整记录名称"><input required value={name} onChange={event => { setName(event.target.value); setPreview(null) }} /></Field><Field label="记录类型"><select value={kind} onChange={event => { setKind(event.target.value); setPreview(null) }}>{recordTypes.map(kind => <option key={kind}>{kind}</option>)}</select></Field><Field label="记录内容" hint={cloudflare ? undefined : account.config.provider === 'huawei' ? '使用官方记录文本；TXT 需要引号，SRV / CAA 使用对应文本格式，多值使用 records 数组。' : '使用所选提供方官方文本格式；复杂记录不会转换成 Cloudflare 结构字段。'}><textarea value={content} rows={3} onChange={event => { setContent(event.target.value); setPreview(null) }} /></Field><Field label="TTL"><input type="number" min={1} max={86400} value={ttl} onChange={event => { setTtl(Number(event.target.value)); setPreview(null) }} /></Field>{kind === 'MX' && <Field label="MX 优先级"><input type="number" min={0} max={65535} value={priority} onChange={event => { setPriority(Number(event.target.value)); setPreview(null) }} /></Field>}{lineProvider && <Field label="记录线路" hint={account.config.provider === 'aliyun' ? '阿里云线路代码，默认 default。' : '腾讯云 DNSPod 线路标识，默认 0，需填写账号可用线路。'}><input required value={line} onChange={event => { setLine(event.target.value); setPreview(null) }} /></Field>}{!lineProvider && <Field label="结构参数 JSON" hint={cloudflare ? '按 Cloudflare 官方 data 参数填写；未知字段会被拒绝。' : '华为云仅支持 records 字符串数组，如 {"records":["192.0.2.1","192.0.2.2"]}；填写数组时清空单条内容。'}><textarea rows={3} value={data} onChange={event => { setData(event.target.value); setPreview(null) }} /></Field>}<Field label="备注"><input value={comment} maxLength={256} onChange={event => { setComment(event.target.value); setPreview(null) }} /></Field>{cloudflare && <label className="ddns-toggle"><input type="checkbox" checked={proxied} onChange={event => { setProxied(event.target.checked); setPreview(null) }} /><span>Cloudflare 代理（仅支持的类型可启用）</span></label>}</div>}
      <button className="button button-secondary" disabled={action.busy || (operation === 'delete' && !record)}>读取远端并生成变更预览</button>
    </form>
    {preview && <div className="panel-body"><h3>应用前差异</h3><p className="helper">修改前</p><pre>{JSON.stringify(preview.previous, null, 2)}</pre><p className="helper">期望变更 · {preview.operation}</p><pre>{JSON.stringify(preview.desired, null, 2)}</pre><button className="button button-primary" disabled={action.busy || preview.expires_at * 1000 <= Date.now()} onClick={() => void action.run(async () => {
      const result = await api<{ status: string; error_code: string | null; reconcile_required: boolean }>(`/api/plugins/ddns/accounts/${account.id}/records/apply`, 'POST', { preview_id: preview.preview_id, confirmed: true })
      setResult(result.status === 'applied' ? '提供方已确认；解析器传播请另行检查。' : result.status === 'submitted' ? '提供方已接收但仍在处理中，请在历史中核对实际状态。' : result.reconcile_required ? '结果未知，请重新读取远端核对；不会自动重放操作。' : '远端或维护关系发生变化，变更已阻止，请重新预览。'); setPreview(null); refresh()
    })}>确认按预览应用（需管理员再次验证）</button></div>}
    {result && <p className="helper" role="status">{result}</p>}
    <DnsResolver account={account} zoneId={zone} initialName={name || record?.name || ''} />
    <h3>记录变更历史</h3>{history.data?.map(entry => <article className="ddns-rule" key={entry.id}><strong>{new Date(entry.occurred_at * 1000).toLocaleString('zh-CN')} · {entry.request.operation}</strong><Badge>{entry.status === 'applied' ? '提供方已确认' : entry.status === 'blocked' ? '条件变化，已阻止' : entry.status === 'submitted' ? '已提交，等待提供方生效' : entry.status === 'observed' ? '期望值已观测，归属未确认' : '结果未知'}</Badge><pre>{JSON.stringify({ previous: entry.previous, observed: entry.observed }, null, 2)}</pre>{['unknown', 'submitted', 'observed'].includes(entry.status) && <button className="text-button" disabled={action.busy} onClick={() => void action.run(async () => { const result = await api<{ status: string }>(`/api/plugins/ddns/accounts/${account.id}/records/${entry.id}/reconcile`, 'POST'); setResult(result.status === 'applied' ? '远端状态已核对，提供方已完成。' : result.status === 'observed' ? '远端符合期望，但新建记录的归属无法确认，禁止自动回退删除。' : '远端仍未确认期望状态；未重新提交任何修改。'); refresh() })}>只读核对远端结果</button>}{entry.status === 'applied' && <button className="text-button" disabled={action.busy} onClick={() => setRollback(entry)}>核对远端并回退此变更</button>}</article>)}
  </div><footer><button className="button button-secondary" disabled={action.busy} onClick={close}>关闭</button></footer>{rollback && <Confirm title="回退 DNS 记录变更" busy={action.busy} error={action.error} onClose={() => setRollback(null)} onConfirm={() => void action.run(async () => {
    const result = await api<{ status: string }>(`/api/plugins/ddns/accounts/${account.id}/records/${rollback.id}/rollback`, 'POST', { confirmed: true })
    setResult(result.status === 'applied' ? '回退已由提供方确认。' : '回退未完成，请重新读取远端核对，禁止自动重放。'); refresh()
  }, () => setRollback(null))}>修改记录恢复旧值；此前新建的记录将删除，此前删除的记录将重新建立。当前远端值必须与此条历史的结果相同，否则拒绝覆盖。此操作需要管理员再次验证。</Confirm>}</Modal>
}
