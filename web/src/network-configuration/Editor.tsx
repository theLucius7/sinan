import { useState } from 'react'
import { Field } from '../components'
import { labels } from './types'
import type { Document, Draft, Renewal, Server, Target } from './types'

export default function Editor({ draft, change, servers, documents }: { draft: Draft; change: (part: Record<string, unknown>) => void; servers: Server[]; documents: Document[] }) {
  const str = (key: string) => String(draft[key] ?? '')
  const list = (key: string) => (draft[key] as string[] | undefined) ?? []
  const server = <Field label="执行服务器"><select value={Number(draft.server_id ?? 0)} onChange={event => change({ server_id: Number(event.target.value) || (draft.kind === 'endpoint' ? null : 0) })}><option value={0}>请选择；外部端点可不绑定</option>{servers.map(item => <option value={item.id} key={item.id}>{item.name}</option>)}</select></Field>
  const text = (key: string, label: string, required = false) => <Field label={label}><input required={required} value={str(key)} onChange={event => change({ [key]: key === 'public_address' ? event.target.value || null : event.target.value })} /></Field>
  const number = (key: string, label: string, max = 65535) => <Field label={label}><input type="number" min={1} max={max} value={Number(draft[key] ?? 0)} onChange={event => change({ [key]: Number(event.target.value) })} /></Field>
  const lines = (key: string, label: string) => <Field label={label}><textarea rows={3} value={list(key).join('\n')} placeholder="每行一个；未配置可留空" onChange={event => change({ [key]: event.target.value.split('\n').map(value => value.trim()).filter(Boolean) })} /></Field>
  const targets = (draft.targets as Target[] | undefined) ?? []
  const renewal = (draft.renewal as Renewal | undefined) ?? { mode: 'external', responsibility: '' }
  const targetChange = (index: number, part: Partial<Target>) => change({ targets: targets.map((target, at) => at === index ? { ...target, ...part } : target) })
  return <div className="network-form"><h3>{labels[draft.kind]}</h3>{text('name', draft.kind === 'domain' ? '完整域名' : '名称', true)}
    {draft.kind === 'domain' && <>
      {text('maintainer', '维护责任方', true)}
      <Field label="关联服务器"><div className="network-checks">{servers.map(item => <label key={item.id}><input type="checkbox" checked={(draft.server_ids as number[]).includes(item.id)} onChange={event => change({ server_ids: event.target.checked ? [...draft.server_ids as number[], item.id] : (draft.server_ids as number[]).filter(id => id !== item.id) })} />{item.name}</label>)}</div></Field>
      {lines('ddns_rule_ids', '关联 DDNS 规则标识')}{lines('applications', '关联应用')}{text('notes', '备注')}
    </>}
    {draft.kind === 'certificate' && <>
      {text('maintainer', '证书维护责任方', true)}{text('issuer', '签发方', true)}
      <Field label="覆盖域名"><div className="network-checks">{documents.filter(item => item.kind === 'domain').map(item => <label key={item.id}><input type="checkbox" checked={list('domain_ids').includes(item.id)} onChange={event => change({ domain_ids: event.target.checked ? [...list('domain_ids'), item.id] : list('domain_ids').filter(id => id !== item.id) })} />{String(item.config.name)}</label>)}</div></Field>
      <Field label="续期方式"><select value={renewal.mode} onChange={event => change({ renewal: { mode: event.target.value, responsibility: renewal.responsibility, ...(event.target.value === 'dns01' ? { ddns_rule_id: '' } : {}) } })}><option value="external">由维护方签发与续期</option><option value="dns01">DNS-01 验证辅助</option></select></Field>
      <Field label="签发维护责任方"><input required value={renewal.responsibility} onChange={event => change({ renewal: { ...renewal, responsibility: event.target.value } })} /></Field>
      {renewal.mode === 'dns01' && <Field label="DNS 凭据对应 DDNS 规则标识"><input required value={renewal.ddns_rule_id ?? ''} onChange={event => change({ renewal: { ...renewal, ddns_rule_id: event.target.value } })} /></Field>}
      <p className="helper">Cloudflare DNS-01 可配置签名库存里的固定版 lego 自动签发与续期；私钥保存到加密凭据中心。也可登记外部维护方挑战，仅创建、核对与清理专属 TXT。</p>
      {targets.map((target, index) => <div className="network-target" key={index}><Field label="部署服务器"><select value={target.server_id} onChange={event => targetChange(index, { server_id: Number(event.target.value) })}><option value={0}>请选择</option>{servers.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></Field><Field label="目标服务"><input value={target.service} onChange={event => targetChange(index, { service: event.target.value })} /></Field><Field label="握手域名"><input value={target.domain} onChange={event => targetChange(index, { domain: event.target.value })} /></Field><Field label="握手端口"><input type="number" min={1} max={65535} value={target.port} onChange={event => targetChange(index, { port: Number(event.target.value) })} /></Field><Field label="受管证书绝对路径（手工部署可留空）"><input value={target.certificate_path ?? ''} onChange={event => targetChange(index, { certificate_path: event.target.value || null })} placeholder="/srv/example-certificates/tls.crt" /></Field><Field label="受管私钥绝对路径（与证书路径一起配置）"><input value={target.private_key_path ?? ''} onChange={event => targetChange(index, { private_key_path: event.target.value || null })} placeholder="/srv/example-certificates/tls.key" /></Field><button type="button" className="text-button" onClick={() => change({ targets: targets.filter((_, at) => at !== index) })}>移除目标</button></div>)}
      <button type="button" className="button button-secondary" onClick={() => change({ targets: [...targets, { server_id: servers[0]?.id ?? 0, service: '', domain: '', port: 443 }] })}>添加部署目标</button>
    </>}
    {(draft.kind === 'endpoint' || draft.kind === 'forwarding') && <>{server}{text('listen_address', '本机监听地址', true)}{number(draft.kind === 'endpoint' ? 'port' : 'listen_port', '监听端口')}
      {draft.kind === 'endpoint' ? <>{text('public_address', '公开地址（可留空）')}{text('notes', '备注')}</> : <>{text('target_address', '实际目标地址', true)}{number('target_port', '目标端口')}{lines('dependency_ids', '依赖端点或转发标识')}<label><input type="checkbox" checked={Boolean(draft.enabled)} onChange={event => change({ enabled: event.target.checked })} />允许显式启动</label></>}
      <Field label="协议"><select value={str('protocol')} onChange={event => change({ protocol: event.target.value })}><option value="tcp">TCP</option><option value="udp">UDP</option></select></Field>
      <Field label="规则维护方"><select value={str('owner')} onChange={event => change({ owner: event.target.value })}><option value="sinan">司南受管</option><option value="external">外部提供</option></select></Field>
      <p className="helper">配置关系与实际观测分别保存。受管执行需要 Linux、systemd、socat、ss 和本机授权，支持 IPv4／IPv6 临时转发。反向隧道与私有组网使用各自独立配置和授权。</p>
    </>}
    {draft.kind === 'tuning' && <>{server}{text('purpose', '用途及对照测试说明', true)}{number('restore_after_secs', '本机自动恢复等待（60–900 秒）', 900)}
      <Parameters value={draft.parameters as Record<string, string>} change={(value, purpose) => change({ parameters: value, ...(purpose ? { purpose } : {}) })} />
      <p className="helper">先读取实际参数与支持算法；临时应用成功后确认结果，再单独持久化。应用前安排独立 systemd 恢复计时器。只修改列出的受管 sysctl。</p>
      {Number(draft.server_id) > 0 && <a href={`#/servers/${Number(draft.server_id)}/network-workbench`}>在当前服务器使用同目标、同参数与时长做网络对照测试</a>}
    </>}
    {draft.kind === 'tunnel' && <>{server}{text('relay_address', '中转服务器 IPv4', true)}{number('relay_port', '中转 SSH 端口')}{text('relay_account', '已授权中转执行账号', true)}{text('relay_host_key', '明确核对的中转 SSH 公钥', true)}{text('listen_address', '中转监听地址', true)}{number('listen_port', '中转发布端口')}{text('target_address', '本机侧服务地址', true)}{number('target_port', '本机侧服务端口')}<label><input type="checkbox" checked={Boolean(draft.enabled)} onChange={event => change({ enabled: event.target.checked })} />允许显式启动反向隧道</label><p className="helper">先生成本机独立 SSH 隧道公钥，由中转维护方明确授权后启动；不使用 Agent 身份。严格核对中转主机公钥，不接受自动信任。默认只监听中转回环地址；公网发布受中转 SSH 的 GatewayPorts 配置约束。服务状态不代表外部实际可达。</p></>}
    {draft.kind === 'mesh' && <>{server}{text('address', '本机私有地址及前缀', true)}{number('listen_port', 'WireGuard 监听端口')}<StructuredField value={draft.peers} label="组网成员（公钥、允许网段和端点）" change={peers => change({ peers })} hint='成员格式：{"public_key":"对端公钥","allowed_ips":["10.17.0.2/32"],"endpoint":null,"persistent_keepalive":25}；先以空成员应用，取得本机公钥后配置双方成员。' /><p className="helper">每台服务器生成独立受保护的 WireGuard 私钥，界面只返回公钥。仅允许私有网段，禁止默认路由；握手时间与传输量作为观测，不能替代真实双端连通性检测。应用、回退和开机启用分开执行。</p></>}
    {draft.kind === 'firewall' && <>{server}{number('restore_after_secs', '本机自动恢复等待（60–900 秒）', 900)}<StructuredField value={draft.management_ports} label="必须保留的管理 TCP 端口" change={management_ports => change({ management_ports })} hint="填写实际 SSH 或其他管理入口端口；例如 [22, 2222]。" /><StructuredField value={draft.rules} label="受管入站规则" change={rules => change({ rules })} hint='规则格式：{"source":"10.0.0.0/8","protocol":"tcp","port":443,"action":"accept"}；动作仅 accept/drop，协议仅 tcp/udp。' /><p className="helper">仅创建该配置独立的 nftables 入站表，不修改外部防火墙。保留本表中的已建立连接、回环与明确管理端口；外部防火墙仍可能拒绝管理连接。临时应用前做语法检查并安排本机恢复计时器，确认后才单独持久化。</p></>}
  </div>
}

function StructuredField({ value, label, change, hint }: { value: unknown; label: string; change: (value: unknown) => void; hint: string }) {
  const [raw, setRaw] = useState(JSON.stringify(value, null, 2)), [error, setError] = useState('')
  return <Field label={label} hint={hint}><textarea rows={6} value={raw} aria-invalid={Boolean(error)} onChange={event => { setRaw(event.target.value); try { const parsed: unknown = JSON.parse(event.target.value); if (!Array.isArray(parsed)) throw new Error(); change(parsed); setError('') } catch { change(null); setError('请输入有效数组；修正后才能预览和保存。') } }} />{error && <p role="alert">{error}</p>}</Field>
}

function Parameters({ value, change }: { value: Record<string, string>; change: (value: Record<string, string> | null, purpose?: string) => void }) {
  const [raw, setRaw] = useState(Object.entries(value).map(([key, item]) => `${key}=${item}`).join('\n'))
  const [error, setError] = useState('')
  const apply = (parameters: Record<string, string>, purpose: string) => { setRaw(Object.entries(parameters).map(([key, item]) => `${key}=${item}`).join('\n')); setError(''); change(parameters, purpose) }
  const descriptions: Record<string, string> = {
    'net.ipv4.tcp_congestion_control': 'TCP 拥塞算法；必须由目标实际支持，不能承诺吞吐提高。',
    'net.core.default_qdisc': '新队列默认算法；已有接口队列可能仍需另行核对。',
    'net.core.rmem_max': '单个接收缓冲区上限；增大可能提高内存占用。',
    'net.core.wmem_max': '单个发送缓冲区上限；增大可能提高内存占用。',
    'net.ipv4.tcp_rmem': 'TCP 接收最小、默认、最大预算；三项必须递增。',
    'net.ipv4.tcp_wmem': 'TCP 发送最小、默认、最大预算；三项必须递增。',
    'net.core.somaxconn': '监听队列上限，实际服务仍可能采用更小的队列。',
    'net.core.netdev_max_backlog': '网卡接收积压预算，积压过大可能增加延迟。',
    'net.netfilter.nf_conntrack_max': '连接跟踪条目上限；提高可能增加内存需求。',
    'net.ipv4.ip_local_port_range': '主动连接临时端口范围；需要核对现有监听与保留端口。',
  }
  return <><div className="network-actions"><button type="button" className="button button-secondary" onClick={() => apply({ 'net.ipv4.tcp_congestion_control': 'cubic', 'net.core.default_qdisc': 'fq_codel' }, '保守拥塞与公平队列对照；固定探测来源、目标、参数与时长，不改变缓冲区预算。')}>保守参数模板</button><button type="button" className="button button-secondary" onClick={() => apply({ 'net.ipv4.tcp_congestion_control': 'bbr', 'net.core.default_qdisc': 'fq' }, 'BBR 拥塞算法对照；仅目标实际支持时应用，比较相同来源和目标的吞吐与负载前后延迟。')}>BBR 对照候选模板</button></div><Field label="受管参数（每行 参数=值）"><textarea rows={7} value={raw} aria-invalid={Boolean(error)} onChange={event => { setRaw(event.target.value); try { const parameters: Record<string, string> = {}; for (const line of event.target.value.split('\n').filter(item => item.trim())) { const at = line.indexOf('='); const key = line.slice(0, at).trim(), item = line.slice(at + 1).trim(); if (at < 1 || !item || !Object.hasOwn(descriptions, key) || Object.hasOwn(parameters, key)) throw new Error(); parameters[key] = item } if (Object.keys(parameters).length === 0) throw new Error(); change(parameters); setError('') } catch { change(null); setError('参数须为不重复的白名单键=值；修正后才能预览和保存。') } }} />{error && <p role="alert">{error}</p>}</Field><details><summary>逐项用途与资源影响</summary>{Object.entries(descriptions).map(([key, description]) => <p key={key}><code>{key}</code>：{description}</p>)}</details></>
}
