import { useState } from 'react'
import { api } from '../../api'
import { ErrorNotice, Field, Modal } from '../../components'
import { useAction } from '../../hooks'
import { ddnsMessage, providers } from './types'
import type { DdnsRule } from './types'
import type { DdnsServer } from './guards'

type Preview = { preview_id: string; expires_at: number; items: { id: string; name: string; record_name: string; record_type: string; source_server_name: string; target_server_name: string; previous_ip: string | null; candidate_ip: string | null; source_status: string; enabled: boolean; previous_config: object; desired_config: object }[] }

export default function Migration({ rules, servers, close, saved }: { rules: DdnsRule[]; servers: DdnsServer[]; close: () => void; saved: () => void }) {
  const action = useAction()
  const [selected, setSelected] = useState(() => new Set(rules.map(rule => rule.id)))
  const [target, setTarget] = useState(servers.find(server => server.enabled)?.id ?? 0)
  const [provider, setProvider] = useState('')
  const [zoneId, setZoneId] = useState(''), [accountId, setAccountId] = useState('')
  const [oldSuffix, setOldSuffix] = useState(''), [newSuffix, setNewSuffix] = useState('')
  const [enabled, setEnabled] = useState('keep')
  const [preview, setPreview] = useState<Preview | null>(null)
  const [confirmed, setConfirmed] = useState(false)
  const invalidate = () => { setPreview(null); setConfirmed(false); action.clearError() }
  return <Modal title="DDNS 批量迁移与编辑" wide busy={action.busy} onClose={close}>
    <div className="modal-body"><ErrorNotice message={action.error} />
      <p className="helper">固定规则与版本，预览服务器、域名、提供方、账号与启停变化。更换 DNS 记录身份时清除旧记录关联，保留旧提供方解析；确认后按新规则对账，旧记录的停用与清理由管理员另行安排。</p>
      <Field label="目标服务器"><select disabled={action.busy} value={target} onChange={event => { setTarget(Number(event.target.value)); invalidate() }}>{servers.filter(server => server.enabled).map(server => <option key={server.id} value={server.id}>{server.name}{server.online ? '' : '（离线，将保留解析）'}</option>)}</select></Field>
      <div className="form-grid"><Field label="批量更换提供方"><select value={provider} onChange={event => { setProvider(event.target.value); invalidate() }}><option value="">保留每条原提供方</option>{Object.entries(providers).map(([id,name]) => <option key={id} value={id}>{name}</option>)}</select></Field><Field label="目标区域标识" hint="留空保留每条原区域；跨提供方时明确填写新 Zone ID 或根域名。"><input value={zoneId} onChange={event => { setZoneId(event.target.value.trim()); invalidate() }} /></Field><Field label="目标 DNS 账号" hint="填写凭据中心关联的账号 UUID；更换提供方时必须选择对应账号。留空保留原账号与凭据。"><input maxLength={36} value={accountId} onChange={event => { setAccountId(event.target.value.trim()); invalidate() }} /></Field><Field label="批量启停"><select value={enabled} onChange={event => { setEnabled(event.target.value); invalidate() }}><option value="keep">保持原状态</option><option value="enabled">全部启用</option><option value="paused">全部暂停</option></select></Field><Field label="待替换的域名后缀"><input value={oldSuffix} placeholder="example.com" onChange={event => { setOldSuffix(event.target.value.trim().replace(/\.$/, '')); invalidate() }} /></Field><Field label="新域名后缀" hint="只替换完整根域名或点分隔的后缀；逐条预览完整名称，不改变 A / AAAA 类型。"><input value={newSuffix} placeholder="example.net" onChange={event => { setNewSuffix(event.target.value.trim().replace(/\.$/, '')); invalidate() }} /></Field></div>
      <div className="ddns-list">{rules.map(rule => <label className="ddns-toggle" key={rule.id}><input type="checkbox" disabled={action.busy || rule.busy} checked={selected.has(rule.id)} onChange={event => { const checked = event.target.checked; setSelected(value => { const next = new Set(value); if (checked) next.add(rule.id); else next.delete(rule.id); return next }); invalidate() }} /><span><strong>{rule.config.name} · {rule.config.record_type}</strong><small>{rule.config.record_name} · {rule.server_name} · {rule.config.address_source === 'manual' ? '手工地址保持不变' : 'Agent 地址来源'}{rule.busy ? ' · 正在同步，请稍后重新预览' : ''}</small></span></label>)}</div>
      <button className="button button-secondary" disabled={action.busy || !target || !selected.size || rules.some(rule => selected.has(rule.id) && rule.busy)} onClick={() => void action.run(async () => {
        const result = await api<Preview>('/api/plugins/ddns/rules/migration-preview', 'POST', { target_server_id: target, rules: rules.filter(rule => selected.has(rule.id)).map(rule => {
          const config = { ...rule.config }
          if (provider) { config.provider = provider as typeof config.provider; config.line = provider === 'aliyun' ? 'default' : provider === 'tencent' ? '0' : ''; if (provider !== 'cloudflare') config.proxied = false }
          if (zoneId) config.zone_id = zoneId
          if (accountId) { config.account_id = accountId; config.credential_id = null }
          if (enabled !== 'keep') config.enabled = enabled === 'enabled'
          if (oldSuffix || newSuffix) {
            if (!oldSuffix || !newSuffix || (config.record_name !== oldSuffix && !config.record_name.endsWith(`.${oldSuffix}`))) throw new Error('所选域名必须匹配完整旧后缀，并填写新后缀。')
            config.record_name = config.record_name.slice(0, -oldSuffix.length) + newSuffix
          }
          return { id: rule.id, revision: rule.revision, config }
        }) })
        setPreview(result); setConfirmed(false)
      })}>预览 {selected.size} 条规则的影响</button>
      {preview && <div className="panel-body"><p className="helper">预览有效至 {new Date(preview.expires_at * 1000).toLocaleTimeString('zh-CN', { hour12: false })}。应用时再次核对所有规则版本与目标服务器状态；任一冲突时整批停止。</p>
        {preview.items.map(item => <article className="ddns-rule" key={item.id}><strong>{item.name} · {item.record_name} · {item.record_type}</strong><p>{item.source_server_name} → {item.target_server_name}</p><p className="helper">上次成功地址 {item.previous_ip ?? '暂无'}；目标候选地址 {item.candidate_ip ?? ddnsMessage(item.source_status)}；{item.enabled ? '确认后按新配置自动同步' : '保持暂停'}。</p><details><summary>配置差异</summary><p className="helper">此前配置</p><pre>{JSON.stringify(item.previous_config, null, 2)}</pre><p className="helper">目标配置</p><pre>{JSON.stringify(item.desired_config, null, 2)}</pre></details></article>)}
        <label className="ddns-toggle"><input type="checkbox" disabled={action.busy} checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /><span>已核对所有来源、目标和后续 DNS 影响，并完成管理员再次验证。</span></label>
      </div>}
    </div><footer><button className="button button-secondary" disabled={action.busy} onClick={close}>取消</button><button className="button button-primary" disabled={action.busy || !preview || !confirmed || preview.expires_at * 1000 <= Date.now()} onClick={() => void action.run(() => api('/api/plugins/ddns/rules/migrate', 'POST', { preview_id: preview!.preview_id, confirmed: true }), saved)}>{action.busy ? '正在迁移…' : '按预览应用整批变更'}</button></footer>
  </Modal>
}
