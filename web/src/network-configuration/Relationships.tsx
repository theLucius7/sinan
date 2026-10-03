import type { Document } from './types'
import { labels } from './types'

type Relation = { from: string; to: string; label: string; document?: Document }
export default function Relationships({ document, documents, select }: { document: Document; documents: Document[]; select: (item: Document) => void }) {
  const config = document.config, name = String(config.name)
  const relations: Relation[] = []
  const references = [...(config.domain_ids as string[] ?? []), ...(config.dependency_ids as string[] ?? [])]
  for (const id of references) { const target = documents.find(item => item.id === id); relations.push({ from: name, to: target ? String(target.config.name) : id, label: target ? labels[target.kind] : '引用标识', document: target }) }
  for (const server of config.server_ids as number[] ?? (config.server_id ? [Number(config.server_id)] : [])) relations.push({ from: name, to: `服务器 ${server}`, label: '明确绑定服务器' })
  for (const target of config.targets as { server_id: number; service: string; domain: string; port: number }[] ?? []) relations.push({ from: name, to: `服务器 ${target.server_id} · ${target.service} · ${target.domain}:${target.port}`, label: '证书部署目标' })
  for (const rule of config.ddns_rule_ids as string[] ?? []) relations.push({ from: name, to: rule, label: 'DDNS 规则' })
  if (document.kind === 'forwarding') relations.push({ from: `${config.listen_address}:${config.listen_port}`, to: `${config.target_address}:${config.target_port}`, label: String(config.protocol).toUpperCase() + ' 转发配置' })
  if (document.kind === 'tunnel') relations.push({ from: `中转 ${config.relay_address}:${config.relay_port} · ${config.listen_address}:${config.listen_port}`, to: `${config.target_address}:${config.target_port}`, label: '授权 SSH 反向隧道' })
  if (document.kind === 'mesh') for (const peer of config.peers as { public_key: string; allowed_ips: string[] }[] ?? []) relations.push({ from: String(config.address), to: `${peer.public_key} · ${peer.allowed_ips.join('、')}`, label: '允许访问的组网成员' })
  return <section className="panel network-details"><h3>配置关系图</h3><p className="helper">箭头表示已保存的配置关系；实际连接与握手证据在独立观测中显示。当前没有可达性证据时保持“未验证”。</p>{relations.length === 0 ? <p>尚无明确关联。</p> : relations.map((relation, index) => <div className="network-relation" key={index}><span>{relation.from}</span><span aria-label="配置关联">→</span><span>{relation.document ? <button className="text-button" onClick={() => select(relation.document!)}>{relation.to}</button> : relation.to}</span><small>{relation.label} · 连通性未验证</small></div>)}</section>
}
