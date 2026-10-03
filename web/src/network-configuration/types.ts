export type Kind = 'domain' | 'certificate' | 'endpoint' | 'forwarding' | 'tuning' | 'tunnel' | 'mesh' | 'firewall'
export type Draft = Record<string, unknown> & { kind: Kind }
export type Document = { id: string; kind: Kind; revision: number; config: Draft; active_version: string | null; updated_at: number }
export type Server = { id: number; name: string }
export type Version = { id: string; fingerprint: string; not_before: number; not_after: number; revision: number }
export type Renewal = { mode: 'external' | 'dns01'; responsibility: string; ddns_rule_id?: string }
export type Target = { server_id: number; service: string; domain: string; port: number; certificate_path?: string | null; private_key_path?: string | null }
export const labels: Record<Kind, string> = { domain: '域名台账', certificate: '证书版本', endpoint: '端点台账', forwarding: '端口转发', tuning: '系统网络参数', tunnel: '反向隧道', mesh: '私有组网', firewall: '受管防火墙' }
export const time = (value: number) => new Date(value * 1000).toLocaleString('zh-CN', { hour12: false })
export function template(kind: Kind, server = 0): Draft {
  switch (kind) {
    case 'domain': return { kind, name: '', server_ids: server ? [server] : [], ddns_rule_ids: [], applications: [], maintainer: '', notes: '' }
    case 'certificate': return { kind, name: '', domain_ids: [], maintainer: '', issuer: '', targets: [], renewal: { mode: 'external', responsibility: '' } }
    case 'endpoint': return { kind, name: '', server_id: server || null, listen_address: '127.0.0.1', public_address: null, port: 443, protocol: 'tcp', owner: 'external', notes: '' }
    case 'forwarding': return { kind, name: '', server_id: server, listen_address: '127.0.0.1', listen_port: 8080, target_address: '127.0.0.1', target_port: 80, protocol: 'tcp', owner: 'sinan', enabled: false, dependency_ids: [] }
    case 'tuning': return { kind, name: '', server_id: server, parameters: { 'net.ipv4.tcp_congestion_control': 'cubic' }, restore_after_secs: 180, purpose: '' }
    case 'tunnel': return { kind, name: '', server_id: server, relay_address: '', relay_port: 22, relay_account: '', relay_host_key: '', listen_address: '127.0.0.1', listen_port: 8080, target_address: '127.0.0.1', target_port: 80, enabled: false }
    case 'mesh': return { kind, name: '', server_id: server, address: '10.17.0.1/24', listen_port: 51820, peers: [] }
    case 'firewall': return { kind, name: '', server_id: server, rules: [], management_ports: [22], restore_after_secs: 180 }
  }
}
