import { useState } from 'react'
import { api } from '../api'
import { ErrorNotice, Loading, PageHeader, Refresh } from '../components'
import { useAction, useResource } from '../hooks'
import { usePreference } from './preferences'
import SystemHealth from './SystemHealth'
import ToolSecurity from './ToolSecurity'
import './control-center.css'
type Actor = { admin_id: number; login_name: string; display_name: string; role: string; all_servers: boolean; capabilities: string[]; server_ids: number[] }
type Administrator = { id: number; login_name: string; display_name: string; role: string; enabled: boolean; all_servers: boolean; capabilities: string[]; server_ids: number[]; revision: number }
type Credential = { id: string; name: string; kind: string; version: number; key_id: string; enabled: boolean }
type ApiToken = { id: string; name: string; capabilities: string[]; server_ids: number[]; all_servers: boolean; expires_at: number; revoked_at: number | null; last_used_at: number | null }
type Session = { id: string; current: boolean; expires_at: number }
type Audit = { id: number; admin_id: number | null; action: string; object_path: string; occurred_at: number; request_diff: unknown; result: unknown }
const kindNames: Record<string, string> = { dns: 'DNS', cloud: '云账号', backup: '备份', 'external-api': '外部 API', certificate: '证书', monitoring: '监控', logs: '日志', ip: 'IP 查询', terminal: '终端', 'proxy-access': '代理访问', audit: '审计' }
const roleNames: Record<string, string> = { owner: '所有者', operator: '运维', viewer: '只读' }
const featureNames: Record<string, string> = { servers: '服务器', monitoring: '监控', terminal: '终端与命令', files: '文件', services: '系统服务', diagnostics: '检测验机', network: '网络配置', dns: 'DNS', proxy: '代理业务', operations: '批量运维', recovery: '备份恢复', cloud: '云资源', security: '系统安全' }
const time = (value: number | null) => value ? new Date(value * 1000).toLocaleString('zh-CN') : '暂无记录'
const ids = (value: string) => value.split(/[,，\s]+/).filter(Boolean).map(Number)
const emptyAdmin = { login_name: '', display_name: '', role: 'viewer', enabled: true, all_servers: false, capabilities: [] as string[], server_ids: [] as number[], password: '', expected_revision: 0 }

function Appearance() {
  const preference = usePreference<{ theme: string; density: string }>('appearance')
  const action = useAction()
  const value = preference.value ?? { theme: 'system', density: 'comfortable' }
  return <section className="panel"><div className="panel-heading"><h2>主题与密度</h2></div><div className="panel-body"><ErrorNotice message={action.error || preference.error} retry={preference.reload} /><div className="control-form-grid">
    <label className="field"><span>主题</span><select disabled={!preference.ready || action.busy} value={value.theme} onChange={event => void action.run(() => preference.save({ ...value, theme: event.target.value }))}><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></label>
    <label className="field"><span>密度</span><select disabled={!preference.ready || action.busy} value={value.density} onChange={event => void action.run(() => preference.save({ ...value, density: event.target.value }))}><option value="comfortable">舒适</option><option value="compact">紧凑</option></select></label>
  </div><p>偏好按管理员保存。搜索快捷键为 Ctrl / ⌘ + K，收藏与最近访问可在全局搜索中直接进入。</p></div></section>
}
function Administrators() {
  const resource = useResource<{ administrators: Administrator[]; features: string[] }>('/api/control-center/administrators')
  const action = useAction()
  const [editing, setEditing] = useState<number | null>(null)
  const [form, setForm] = useState(emptyAdmin)
  const [serverText, setServerText] = useState('')
  return <><ErrorNotice message={resource.error || action.error} retry={resource.reload} /><section className="panel"><div className="panel-heading"><h2>管理员与授权</h2><Refresh onClick={resource.reload} /></div>
    {resource.loading && !resource.data ? <Loading /> : <div className="table-wrap"><table><thead><tr><th>管理员</th><th>角色</th><th>服务器范围</th><th>状态</th><th>操作</th></tr></thead><tbody>{resource.data?.administrators.map(admin => <tr key={admin.id}><td>{admin.display_name}<small> · {admin.login_name}</small></td><td>{roleNames[admin.role]}</td><td>{admin.all_servers ? '所有服务器' : admin.server_ids.join('、') || '未授权服务器'}</td><td>{admin.enabled ? '启用' : '停用'}</td><td><button onClick={() => { setEditing(admin.id); setForm({ login_name: admin.login_name, display_name: admin.display_name, role: admin.role, enabled: admin.enabled, all_servers: admin.all_servers, capabilities: admin.capabilities, server_ids: admin.server_ids, password: '', expected_revision: admin.revision }); setServerText(admin.server_ids.join(',')) }}>编辑授权</button></td></tr>)}</tbody></table></div>}
  </section><section className="panel"><div className="panel-heading"><h2>{editing ? '编辑管理员' : '新增管理员'}</h2></div><form className="panel-body" onSubmit={event => {
    event.preventDefault(); void action.run(() => api(editing ? `/api/control-center/administrators/${editing}` : '/api/control-center/administrators', editing ? 'PUT' : 'POST', { ...form, password: form.password || null, server_ids: ids(serverText) }), () => { setEditing(null); setForm(emptyAdmin); setServerText(''); resource.reload() })
  }}><div className="control-form-grid"><label className="field"><span>登录名</span><input required pattern="[a-z0-9._-]+" value={form.login_name} onChange={event => setForm({ ...form, login_name: event.target.value })} /></label><label className="field"><span>显示名称</span><input required value={form.display_name} onChange={event => setForm({ ...form, display_name: event.target.value })} /></label><label className="field"><span>角色</span><select value={form.role} onChange={event => setForm({ ...form, role: event.target.value, capabilities: event.target.value === 'viewer' ? form.capabilities.filter(cap => cap.endsWith(':read')) : form.capabilities })}><option value="viewer">只读</option><option value="operator">运维</option><option value="owner">所有者</option></select></label><label className="field"><span>{editing ? '新密码（留空保留）' : '独立密码'}</span><input type="password" autoComplete="new-password" minLength={12} required={!editing} value={form.password} onChange={event => setForm({ ...form, password: event.target.value })} /></label></div>
    <label><input type="checkbox" checked={form.enabled} onChange={event => setForm({ ...form, enabled: event.target.checked })} />启用管理员</label> <label><input type="checkbox" checked={form.all_servers || form.role === 'owner'} disabled={form.role === 'owner'} onChange={event => setForm({ ...form, all_servers: event.target.checked })} />授权所有服务器</label>
    {!form.all_servers && form.role !== 'owner' && <label className="field"><span>授权服务器编号</span><input placeholder="多个编号以逗号分隔" value={serverText} onChange={event => setServerText(event.target.value)} /></label>}
    {form.role !== 'owner' && <fieldset className="control-capabilities"><legend>功能授权</legend>{(resource.data?.features ?? []).flatMap(feature => ['read', ...(form.role === 'viewer' ? [] : ['write'])].map(mode => {
      const cap = `${feature}:${mode}`
      return <label key={cap}><input type="checkbox" checked={form.capabilities.includes(cap)} onChange={event => setForm({ ...form, capabilities: event.target.checked ? [...form.capabilities, cap] : form.capabilities.filter(value => value !== cap) })} />{featureNames[feature]} · {mode === 'read' ? '读取' : '写入'}</label>
    }))}</fieldset>}
    <p>保存授权变更后会注销该管理员现有会话并撤销其 API 令牌。受限服务器账号从已授权服务器详情进入；跨服务器聚合需要全服务器授权。</p><div className="control-actions"><button className="button button-primary" disabled={action.busy || !resource.data}>确认保存</button><button type="button" onClick={() => { setEditing(null); setForm(emptyAdmin); setServerText('') }}>取消编辑</button></div>
  </form></section></>
}
function Sessions() {
  const resource = useResource<Session[]>('/api/control-center/sessions')
  const action = useAction()
  return <section className="panel"><div className="panel-heading"><h2>我的管理员会话</h2><Refresh onClick={resource.reload} /></div><div className="panel-body"><ErrorNotice message={resource.error || action.error} retry={resource.reload} />{resource.data?.map(session => <div className="control-row" key={session.id}><span>{session.current ? '当前会话' : '其他会话'} · 到期 {time(session.expires_at)}</span><button disabled={action.busy} onClick={() => void action.run(() => api(`/api/control-center/sessions/${session.id}`, 'DELETE'), resource.reload)}>注销此会话</button></div>)}</div></section>
}
function Credentials() {
  const resource = useResource<{ entries: Credential[]; encryption_ready: boolean }>('/api/control-center/credentials')
  const action = useAction()
  const [name, setName] = useState(''), [kind, setKind] = useState('dns'), [secret, setSecret] = useState('')
  const [rotation, setRotation] = useState<Credential | null>(null)
  return <section className="panel"><div className="panel-heading"><h2>凭据中心</h2><Refresh onClick={resource.reload} /></div><div className="panel-body"><ErrorNotice message={resource.error || action.error} retry={resource.reload} /><p>{resource.data?.encryption_ready ? '加密密钥已配置；列表只展示引用和版本。' : '加密密钥环尚未配置，不能保存或解密凭据。'}</p>
    {resource.data?.entries.map(entry => <div className="control-row" key={entry.id}><div><strong>{entry.name}</strong><p>{kindNames[entry.kind] ?? entry.kind} · 版本 {entry.version} · {entry.enabled ? '启用' : '停用'}</p><code>{entry.id}</code></div><div className="control-actions"><button disabled={action.busy || !entry.enabled || !resource.data?.encryption_ready} onClick={() => { setRotation(entry); setName(entry.name); setKind(entry.kind); setSecret('') }}>更换消费者凭据</button><button disabled={action.busy || !entry.enabled || !resource.data?.encryption_ready} onClick={() => void action.run(() => api(`/api/control-center/credentials/${entry.id}/rotate`, 'POST', { expected_version: entry.version, secret: null }), resource.reload)}>转用当前加密密钥</button><button disabled={action.busy || !entry.enabled} onClick={() => void action.run(() => api(`/api/control-center/credentials/${entry.id}`, 'DELETE'), resource.reload)}>停用引用</button></div></div>)}
    <form onSubmit={event => { event.preventDefault(); void action.run(() => { let parsed: unknown; try { parsed = JSON.parse(secret) } catch { throw new Error('凭据正文必须是合法的 JSON 对象。') }; if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || !Object.keys(parsed).length) throw new Error('凭据正文必须是非空的 JSON 对象。'); return rotation ? api(`/api/control-center/credentials/${rotation.id}/rotate`, 'POST', { expected_version: rotation.version, secret: parsed }) : api('/api/control-center/credentials', 'POST', { name, kind, secret: parsed }) }, () => { setSecret(''); setName(''); setRotation(null); resource.reload() }) }}><h3>{rotation ? `更换 ${rotation.name} 的凭据 · 当前版本 ${rotation.version}` : '新增独立凭据'}</h3><div className="control-form-grid"><label className="field"><span>名称</span><input required disabled={Boolean(rotation)} value={name} onChange={event => setName(event.target.value)} /></label><label className="field"><span>用途</span><select disabled={Boolean(rotation)} value={kind} onChange={event => setKind(event.target.value)}><option value="dns">DNS</option><option value="cloud">云账号</option><option value="backup">备份</option><option value="external-api">外部 API</option><option value="certificate">证书维护</option></select></label></div><label className="field"><span>凭据正文</span><textarea rows={4} required value={secret} onChange={event => setSecret(event.target.value)} autoComplete="off" placeholder={'{"token":"…"}'} /></label><button className="button button-primary" disabled={action.busy || !resource.data?.encryption_ready}>{rotation ? '确认替换并增加版本' : '加密保存并生成引用'}</button>{rotation && <button type="button" onClick={() => { setRotation(null); setSecret(''); setName('') }}>取消替换</button>}<p>替换保留引用并增加版本；消费者下次取用时读取新凭据。请先确认外部提供方已允许新凭据使用。</p></form>
  </div></section>
}
function Tokens() {
  const resource = useResource<ApiToken[]>('/api/control-center/tokens')
  const action = useAction()
  const [name, setName] = useState(''), [scope, setScope] = useState('servers:read'), [servers, setServers] = useState(''), [all, setAll] = useState(false), [days, setDays] = useState(7), [issued, setIssued] = useState('')
  return <section className="panel"><div className="panel-heading"><h2>管理 API 令牌</h2><Refresh onClick={resource.reload} /></div><div className="panel-body"><ErrorNotice message={resource.error || action.error} retry={resource.reload} />{issued && <div className="notice"><div><strong>令牌仅显示本次</strong><pre>{issued}</pre><button onClick={() => setIssued('')}>我已保存，隐藏令牌</button></div></div>}
    {resource.data?.map(token => <div className="control-row" key={token.id}><div><strong>{token.name}</strong><p>{token.capabilities.join('、')} · {token.all_servers ? '所有服务器' : token.server_ids.join('、') || '未授权服务器'}</p><small>到期 {time(token.expires_at)} · 最近使用 {time(token.last_used_at)} · {token.revoked_at ? '已撤销' : '有效'}</small></div><button disabled={action.busy || Boolean(token.revoked_at)} onClick={() => void action.run(() => api(`/api/control-center/tokens/${token.id}`, 'DELETE'), resource.reload)}>撤销</button></div>)}
    <form onSubmit={event => { event.preventDefault(); void action.run(() => api<{ token: string }>('/api/control-center/tokens', 'POST', { name, capabilities: scope.split(/[,，\s]+/).filter(Boolean), server_ids: ids(servers), all_servers: all, expires_at: Math.floor(Date.now() / 1000) + days * 86400 }), result => { setIssued(result.token); resource.reload() }) }}><h3>创建受限令牌</h3><div className="control-form-grid"><label className="field"><span>名称</span><input required value={name} onChange={event => setName(event.target.value)} /></label><label className="field"><span>有效天数</span><input type="number" min={1} max={365} value={days} onChange={event => setDays(Number(event.target.value))} /></label><label className="field"><span>能力</span><input required value={scope} onChange={event => setScope(event.target.value)} placeholder="servers:read, monitoring:read" /></label><label className="field"><span>服务器编号</span><input disabled={all} value={servers} onChange={event => setServers(event.target.value)} /></label></div><label><input type="checkbox" checked={all} onChange={event => setAll(event.target.checked)} />所有服务器</label><p>令牌权限与所属管理员当前权限取交集。高风险操作需要交互式管理员会话再次验证。</p><button className="button button-primary" disabled={action.busy}>创建令牌</button></form>
  </div></section>
}
function AuditLog() {
  const resource = useResource<Audit[]>('/api/control-center/audit')
  return <section className="panel"><div className="panel-heading"><h2>操作审计</h2><Refresh onClick={resource.reload} /></div><div className="panel-body"><ErrorNotice message={resource.error} retry={resource.reload} />{resource.data?.map(entry => <details key={entry.id}><summary>{time(entry.occurred_at)} · 管理员 {entry.admin_id ?? '后台执行器'} · {entry.action} · {entry.object_path}</summary><pre>{JSON.stringify({ requested: entry.request_diff, result: entry.result }, null, 2)}</pre></details>)}<p>凭据、密码、私钥、终端输入和文件正文已脱敏。返回成功只表示接口已接受或完成，具体执行结果请查看相应任务。</p></div></section>
}
export default function ControlCenter() {
  const actor = useResource<Actor>('/api/control-center/me')
  const [tab, setTab] = useState('workspace')
  const tabs = [{ id: 'workspace', name: '我的工作区' }, { id: 'sessions', name: '会话' }, ...(actor.data?.role === 'owner' ? [{ id: 'administrators', name: '管理员授权' }, { id: 'credentials', name: '凭据' }, { id: 'tokens', name: 'API 令牌' }, { id: 'audit', name: '审计' }, { id: 'health', name: '系统自检' }, { id: 'tool-security', name: '工具与依赖' }] : [])]
  return <><PageHeader eyebrow="系统" title="管理与安全" description="管理员权限、凭据引用、会话与可追溯的操作记录。" /><ErrorNotice message={actor.error} retry={actor.reload} />{actor.data && <p>{actor.data.display_name} · {roleNames[actor.data.role]} · {actor.data.all_servers ? '所有服务器' : `授权服务器 ${actor.data.server_ids.join('、') || '无'}`}</p>}<div className="control-tabs">{tabs.map(item => <button className={tab === item.id ? 'active' : ''} key={item.id} onClick={() => setTab(item.id)}>{item.name}</button>)}</div>{tab === 'workspace' && <Appearance />}{tab === 'sessions' && <Sessions />}{actor.data?.role === 'owner' && <>{tab === 'administrators' && <Administrators />}{tab === 'credentials' && <Credentials />}{tab === 'tokens' && <Tokens />}{tab === 'audit' && <AuditLog />}{tab === 'health' && <SystemHealth />}{tab === 'tool-security' && <ToolSecurity />}</>}</>
}
