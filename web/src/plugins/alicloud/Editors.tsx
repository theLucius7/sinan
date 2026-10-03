import { useState } from 'react'
import { api } from '../../api'
import { ErrorNotice, Field, FormDialog, Modal } from '../../components'
import { useAction } from '../../hooks'
import { accountWrite, charge, time } from './types'
import type { Account, Operation, Resource, Target } from './types'
import { accountError, checked, credentialError, operationError, registrationError, resourceError } from './guards'
import type { CurrentCloud } from './guards'
type Events = { close: () => void; saved: () => void; available: boolean; current: CurrentCloud; refresh: () => void }

export function AccountEditor({ account, close, saved, current }: Events & { account?: Account }) {
  const [draft, setDraft] = useState<Pick<Account, 'name' | 'site' | 'enabled' | 'auto_enabled' | 'limit_gb'>>(account ?? { name: '', site: 'china' as const, enabled: true, auto_enabled: false, limit_gb: 100 })
  const [key, setKey] = useState(''), [secret, setSecret] = useState(''), action = useAction()
  const [credentialId, setCredentialId] = useState(account?.credential_id ?? '')
  const [legacy, setLegacy] = useState(Boolean(account && !account.credential_id))
  const writeError = () => accountError(current, account) || (legacy ? credentialError(key, secret, !account || Boolean(account.credential_id)) : /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(credentialId.trim()) ? '' : '请填写集中云凭据的 UUID。')
  return <FormDialog title={account ? '编辑阿里云账号' : '添加阿里云账号'} busy={action.busy} error={action.error || accountError(current, account)} onClose={close} submitDisabled={Boolean(writeError())} onSubmit={() => void action.run(() => checked(writeError, () => api(account ? `/api/plugins/alicloud/accounts/${account.id}` : '/api/plugins/alicloud/accounts', account ? 'PATCH' : 'POST', accountWrite(draft, legacy ? key : '', legacy ? secret : '', account?.revision, legacy ? '' : credentialId, legacy))), () => { setKey(''); setSecret(''); saved() })}>
    <Field label="账号名称"><input required maxLength={128} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} /></Field>
    <Field label="阿里云账号站点" hint="用于选择中国站或国际站账单接口，与资源所在地域不同。"><select value={draft.site} onChange={e => setDraft({ ...draft, site: e.target.value as Account['site'] })}><option value="china">中国站</option><option value="international">国际站</option></select></Field>
    <Field label="凭据来源"><select value={legacy ? 'legacy' : 'center'} onChange={e => { setLegacy(e.target.value === 'legacy'); setKey(''); setSecret('') }}><option value="center">集中加密云凭据</option>{account && <option value="legacy">明确保留或替换旧兼容密钥</option>}</select></Field>
    {!legacy ? <Field label="云凭据标识" hint="在凭据中心创建用途为云资源的凭据，包含 provider=alicloud、access_key_id 和 access_key_secret。这里只保存引用；停用或缺少解密密钥会停止请求。"><input required maxLength={36} spellCheck={false} value={credentialId} onChange={e => setCredentialId(e.target.value.trim())} placeholder="集中云凭据的 UUID" /></Field> : <div className="form-grid"><Field label="旧兼容访问密钥 ID" hint="既有旧账号两项同时留空保留。建议迁入集中凭据；旧模式继续保留原有数据库存储。"><input type="password" autoComplete="new-password" minLength={8} maxLength={256} required={Boolean(account?.credential_id) || Boolean(secret)} value={key} onChange={e => setKey(e.target.value)} /></Field><Field label="旧兼容访问密钥 Secret"><input type="password" autoComplete="new-password" minLength={8} maxLength={256} required={Boolean(account?.credential_id) || Boolean(key)} value={secret} onChange={e => setSecret(e.target.value)} /></Field></div>}
    <label className="cloud-toggle"><input type="checkbox" checked={draft.enabled} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />启用账号查询与手动管理</label>
    <Field label="当月已出账 CDT 流量阈值（GB）" hint="账号全部 CDT 账单项目合计，不是某台服务器或剩余免费额度。仅完整的 GB 单位后付账单参与自动控制；退款、调账和缺少实例标识的数据只展示。"><input required type="number" min={1} max={1000000000} step={1} value={draft.limit_gb} onChange={e => setDraft({ ...draft, limit_gb: Number(e.target.value) })} /></Field>
    <label className="cloud-toggle"><input type="checkbox" checked={draft.auto_enabled} onChange={e => setDraft({ ...draft, auto_enabled: e.target.checked })} />达到阈值时，降低已勾选资源的带宽</label>
    <p className="helper">仅降低按流量计费资源的带宽，不自动切换计费或恢复。账单存在延迟，降速后仍产生流量和费用；请留足阈值余量。修改账号配置会取消未开始的操作并重新查询账单。</p>
  </FormDialog>
}
export function ResourceEditor({ resource, accounts, close, saved, current }: Events & { resource?: Resource; accounts: Account[] }) {
  const [draft, setDraft] = useState(resource ? { account_id: resource.account_id, name: resource.name, kind: resource.kind, region: resource.region, cloud_id: resource.cloud_id, cap_mbps: resource.cap_mbps, auto_enabled: resource.auto_enabled } : { account_id: accounts[0]?.id ?? '', name: '', kind: 'ecs' as Resource['kind'], region: '', cloud_id: '', cap_mbps: 1, auto_enabled: false })
  const [accountRevision, setAccountRevision] = useState(() => current()?.accounts.find(a => a.id === draft.account_id)?.revision)
  const action = useAction()
  const writeError = () => resource ? resourceError(current, resource, { accountRevision }) : registrationError(current, draft.account_id, accountRevision)
  return <FormDialog title={resource ? '编辑云资源策略' : '登记云资源'} busy={action.busy} error={action.error || writeError()} onClose={close} submitDisabled={Boolean(writeError())} onSubmit={() => void action.run(() => checked(writeError, () => api(resource ? `/api/plugins/alicloud/resources/${resource.id}` : '/api/plugins/alicloud/resources', resource ? 'PATCH' : 'POST', { ...draft, ...(resource ? { revision: resource.revision } : {}) })), saved)}>
    <Field label="资源名称"><input required maxLength={128} value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })} /></Field>
    <Field label="云账号"><select disabled={!!resource} required value={draft.account_id} onChange={e => { setDraft({ ...draft, account_id: e.target.value }); setAccountRevision(current()?.accounts.find(a => a.id === e.target.value)?.revision) }}>{!accounts.some(a => a.id === draft.account_id) && <option value={draft.account_id}>原云账号（不可用）</option>}{accounts.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}</select></Field>
    <div className="form-grid"><Field label="资源类型"><select disabled={!!resource} value={draft.kind} onChange={e => setDraft({ ...draft, kind: e.target.value as Resource['kind'], cloud_id: '' })}><option value="ecs">ECS 固定公网 IP</option><option value="eip">独立 EIP</option></select></Field><Field label="地域标识" hint="填写云控制台中的地域代码。"><input disabled={!!resource} required maxLength={80} pattern="[a-z0-9-]{3,80}" placeholder="例如 cn-hangzhou" value={draft.region} onChange={e => setDraft({ ...draft, region: e.target.value })} /></Field></div>
    <Field label={draft.kind === 'ecs' ? 'ECS 实例 ID' : 'EIP 分配 ID'}><input disabled={!!resource} required maxLength={80} pattern={draft.kind === 'ecs' ? 'i-[a-z0-9-]+' : 'eip-[a-z0-9-]+'} placeholder={draft.kind === 'ecs' ? 'i-…' : 'eip-…'} value={draft.cloud_id} onChange={e => setDraft({ ...draft, cloud_id: e.target.value })} /></Field>
    <Field label="自动降速目标（Mbps）"><input required type="number" min={1} max={100} step={1} value={draft.cap_mbps} onChange={e => setDraft({ ...draft, cap_mbps: Number(e.target.value) })} /></Field>
    <label className="cloud-toggle"><input type="checkbox" checked={draft.auto_enabled} onChange={e => setDraft({ ...draft, auto_enabled: e.target.checked })} />将此资源纳入该账号的自动降速策略</label>
    <p className="helper">登记不会创建、释放或绑定公网 IP。共享带宽包和包年包月 EIP 不支持。自动控制需要同时启用账号策略和资源策略；每组配置每月最多触发一次，失败后请核对并重新保存策略。</p>
  </FormDialog>
}
export function BandwidthEditor({ resource, close, saved, current, refresh }: Events & { resource: Resource }) {
  const [target, setTarget] = useState<Target>({ bandwidth_mbps: Math.max(1, Math.min(100, resource.snapshot?.bandwidth_mbps ?? 10)), charge_type: resource.snapshot?.charge_type ?? 'PayByTraffic' })
  const [preview, setPreview] = useState<Operation | null>(null), [confirmed, setConfirmed] = useState(false), action = useAction()
  const [accountRevision] = useState(() => current()?.accounts.find(a => a.id === resource.account_id)?.revision)
  const writeError = () => resourceError(current, resource, { managed: true, idle: true, accountRevision }) || (preview ? operationError(current, preview, false, ['preview'], true) : '')
  return <Modal title={`调整公网带宽 · ${resource.name}`} onClose={close} busy={action.busy}><form onSubmit={e => {
    e.preventDefault()
    if (preview) { if (confirmed) void action.run(() => checked(writeError, () => api(`/api/plugins/alicloud/operations/${preview.id}/confirm`, 'POST')), saved) }
    else void action.run(() => checked(writeError, () => api<Operation>(`/api/plugins/alicloud/resources/${resource.id}/preview`, 'POST', { target, revision: resource.revision })), value => { setPreview(value); setConfirmed(false); refresh() })
  }}><div className="modal-body"><ErrorNotice message={action.error || writeError()} />{preview ? <>
    <dl className="cloud-details"><div><dt>当前配置</dt><dd>{preview.before_state.bandwidth_mbps} Mbps · {charge(preview.before_state.charge_type)}</dd></div><div><dt>目标配置</dt><dd>{preview.target.bandwidth_mbps} Mbps · {charge(preview.target.charge_type)}</dd></div><div><dt>公网 IP</dt><dd>{preview.before_state.public_ip}</dd></div><div><dt>预览有效期</dt><dd>{time(preview.expires_at)}</dd></div></dl>
    <p className="helper">此次调整可能产生费用或扣款，具体金额以阿里云为准。执行前会再次核对资源状态；响应不确定时暂停后续变配，只核对结果。</p>
    <label className="cloud-toggle"><input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />确认此资源与目标配置，授权此次变配及可能产生的扣款</label>
  </> : <fieldset disabled={action.busy}><Field label="公网出带宽（Mbps）"><input required type="number" min={1} max={100} step={1} value={target.bandwidth_mbps} onChange={e => setTarget({ ...target, bandwidth_mbps: Number(e.target.value) })} /></Field>
    {resource.kind === 'ecs' ? <Field label="公网计费方式"><select value={target.charge_type} onChange={e => setTarget({ ...target, charge_type: e.target.value as Target['charge_type'] })}><option value="PayByTraffic">按流量计费</option><option value="PayByBandwidth">按带宽计费</option></select></Field> : <p className="helper">EIP 此处只调整带宽。计费转换请前往<a href="https://vpc.console.aliyun.com/" target="_blank" rel="noreferrer">阿里云 EIP 控制台</a>；请先刷新资源，确保计费状态最新。</p>}
    <p className="helper">下一步先读取云端配置并生成预览，确认后才提交调整。带宽降至 1 Mbps 仍有流量和费用。</p>
  </fieldset>}</div><footer><button className="button button-secondary" type="button" disabled={action.busy} onClick={preview ? () => { setPreview(null); setConfirmed(false) } : close}>{preview ? '重新预览' : '取消'}</button><button className="button button-primary" disabled={action.busy || Boolean(writeError()) || (!!preview && !confirmed)}>{action.busy ? '正在处理…' : preview ? '确认调整并授权扣款' : '预览变更'}</button></footer></form></Modal>
}
