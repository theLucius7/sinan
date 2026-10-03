import { useState } from 'react'
import { api } from '../../api'
import { Badge, ErrorNotice, Field, Modal } from '../../components'
import { useAction, useResource } from '../../hooks'
import type { DdnsServer } from './guards'
import { providers } from './types'
import DnsRecords from './DnsRecords'

export type DnsAccount = { id: string; revision: number; config: { name: string; provider: keyof typeof providers; credential_id: string; zone_ids: string[]; server_ids: number[]; enabled: boolean }; record_management_available: boolean; unavailable_reason: string | null; checked_at: number | null; error_code: string | null }

function Editor({ account, servers, close, saved }: { account?: DnsAccount; servers: DdnsServer[]; close: () => void; saved: () => void }) {
  const action = useAction()
  const [config, setConfig] = useState(account?.config ?? { name: '', provider: 'cloudflare' as keyof typeof providers, credential_id: '', zone_ids: [] as string[], server_ids: [] as number[], enabled: true })
  const [zones, setZones] = useState(config.zone_ids.join('\n'))
  const change = (part: Partial<typeof config>) => setConfig(value => ({ ...value, ...part }))
  return <Modal title={account ? '编辑 DNS 账号' : '添加 DNS 账号'} busy={action.busy} onClose={close}><form onSubmit={event => { event.preventDefault(); void action.run(() => api(account ? `/api/plugins/ddns/accounts/${account.id}` : '/api/plugins/ddns/accounts', account ? 'PUT' : 'POST', { config: { ...config, zone_ids: zones.split(/[\s,]+/).filter(Boolean) }, revision: account?.revision }), saved) }}><div className="modal-body"><ErrorNotice message={action.error} />
    <Field label="账号名称"><input required value={config.name} maxLength={128} onChange={event => change({ name: event.target.value })} /></Field>
    <Field label="DNS 提供方"><select value={config.provider} onChange={event => change({ provider: event.target.value as typeof config.provider })}>{Object.entries(providers).map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></Field>
    <Field label="凭据中心 DNS 凭据标识" hint="仅保存加密凭据引用。四个提供方分别使用官方接口；区域、线路、结构参数和异步确认按实际提供方能力显示。"><input required value={config.credential_id} maxLength={36} onChange={event => change({ credential_id: event.target.value.trim() })} placeholder="DNS 凭据 UUID" /></Field>
    <Field label="明确授权的 DNS 区域" hint="每行一个区域。Cloudflare / 华为云填写 Zone ID，腾讯云 / 阿里云填写托管根域名，最多 32 个。"><textarea required rows={4} value={zones} onChange={event => setZones(event.target.value)} /></Field>
    <Field label="账号授权关联的服务器" hint="所有关联服务器均须在管理员授权范围内；未选择时需要全服务器授权。">{servers.map(server => <label className="ddns-toggle" key={server.id}><input type="checkbox" checked={config.server_ids.includes(server.id)} onChange={event => change({ server_ids: event.target.checked ? [...config.server_ids, server.id] : config.server_ids.filter(id => id !== server.id) })} /><span>{server.name}</span></label>)}</Field>
    <label className="ddns-toggle"><input type="checkbox" checked={config.enabled} onChange={event => change({ enabled: event.target.checked })} /><span>启用此账号；停用保留记录与操作历史。</span></label>
    <p className="helper">保存账号范围和凭据引用需要管理员再次验证；连接检查只查询提供方，不写入 DNS。</p>
  </div><footer><button type="button" className="button button-secondary" disabled={action.busy} onClick={close}>取消</button><button className="button button-primary" disabled={action.busy}>保存账号</button></footer></form></Modal>
}

export default function DnsAccounts({ servers }: { servers: DdnsServer[] }) {
  const accounts = useResource<DnsAccount[]>('/api/plugins/ddns/accounts')
  const action = useAction()
  const [editing, setEditing] = useState<DnsAccount | 'new' | null>(null)
  const [records, setRecords] = useState<DnsAccount | null>(null)
  const [check, setCheck] = useState<{ zones: { id: string; name: string | null; available: boolean; error_code: string | null }[]; error_code: string | null; checked_at: number } | null>(null)
  return <section className="panel"><div className="panel-heading"><h2>DNS 账号与普通记录</h2><button className="button button-secondary button-small" onClick={() => setEditing('new')}>添加账号</button></div><div className="panel-body"><ErrorNotice message={accounts.error || action.error} retry={accounts.reload} />
    <p className="helper">账号按提供方、凭据引用、区域与服务器权限关联管理。普通记录修改先预览再确认，并保存旧值；正在由 DDNS 自动维护的记录需先暂停对应规则。</p>
    {accounts.data?.map(account => <article className="ddns-rule" key={account.id}><div className="ddns-rule-heading"><strong>{account.config.name} · {providers[account.config.provider]}</strong><Badge>{account.config.enabled ? '已启用' : '已停用'}</Badge></div><p className="helper">账号标识 {account.id} · {account.config.zone_ids.length} 个授权区域 · {account.config.server_ids.length ? `${account.config.server_ids.length} 台服务器范围` : '全服务器权限范围'} · {account.record_management_available ? '官方记录管理已接入' : account.unavailable_reason}</p><div className="ddns-actions"><button className="text-button" disabled={action.busy || !account.config.enabled || !account.record_management_available} onClick={() => void action.run(async () => { setCheck(await api(`/api/plugins/ddns/accounts/${account.id}/check`, 'POST')); accounts.reload() })}>检查连接与区域</button><button className="text-button" disabled={!account.config.enabled || !account.record_management_available} onClick={() => setRecords(account)}>记录、传播观测与历史</button><button className="text-button" onClick={() => setEditing(account)}>编辑授权与启停</button></div></article>)}
    {!accounts.data?.length && !accounts.loading && <p className="helper">尚未登记 DNS 账号。</p>}
    {check && <p className="helper">{new Date(check.checked_at * 1000).toLocaleString('zh-CN')} · {check.zones.length ? check.zones.map(zone => `${zone.name ?? zone.id}：${zone.available ? '官方接口已确认' : `未确认（${zone.error_code ?? '未知'}）`}`).join('；') : '连接或授权未确认，请检查凭据与区域范围。'}</p>}
  </div>{editing && <Editor account={editing === 'new' ? undefined : editing} servers={servers} close={() => setEditing(null)} saved={() => { setEditing(null); accounts.reload() }} />}{records && <DnsRecords account={records} close={() => setRecords(null)} />}</section>
}
