export type DdnsConfig = {
  provider?: 'cloudflare' | 'tencent' | 'aliyun' | 'huawei'; line?: string
  name: string; server_id: number; zone_id: string; record_name: string; record_type: 'A' | 'AAAA'
  address_source?: 'agent' | 'interface' | 'discovered' | 'manual'; manual_ip?: string | null; credential_id?: string | null; interface_name?: string | null; account_id?: string | null
  ttl: number; proxied: boolean; interval_secs: number; enabled: boolean; adopt_existing: boolean
}
export type DdnsRule = {
  id: string; config: DdnsConfig; revision: number; token_configured: boolean; busy: boolean; plugin_enabled: boolean
  server_name: string; candidate_ip: string | null; ip_status: string; ip_received_at: number | null
  last_ip: string | null; last_success_at: number | null; attempted_at: number | null; next_run_at: number
  status: string; error_code: string | null; failures: number
}
const messages: Record<string, string> = {
  source_unavailable: 'Agent 尚未提供所选网卡或公网发现来源，保留现有解析；请更新 Agent 或更换来源',
  credential_unavailable: '凭据中心引用不可用、密钥缺失或字段不匹配，请检查 DNS 凭据及其提供方配置',
  binding_changed: '来源绑定已迁移',
  rolled_back: '已回退，自动同步已暂停', rollback_running: '正在回退', remote_changed: '远端记录已经变化，已拒绝覆盖，请重新核对', lease_lost: '执行权限或租约已失效，未继续修改', checked: '已读取提供方记录',
  submitted: '已提交，等待提供方生效', provider_pending: '提供方正在处理，等待下轮核对', ttl_not_supported: 'TTL 低于当前域名套餐支持的最小值',
  plugin_disabled: '此服务器的 DDNS 插件未启用，保留现有解析',
  pending: '等待首次同步', running: '正在同步', updated: '已更新解析', unchanged: '解析一致', waiting: '等待有效地址', error: '同步失败',
  ready: '地址可用', no_public_ip: 'Agent 尚未上报此类型的公网地址', ip_stale: 'IP 报告已过期，等待 Agent 上报',
  server_offline: '服务器离线，保留现有解析', server_retired: '服务器已删除或退役，保留现有解析',
  authentication_failed: '凭据无效或权限不足，请检查访问凭据与域名的 DNS 编辑权限',
  zone_mismatch: '域名不属于指定 Zone', zone_inactive: 'Cloudflare Zone 尚未激活',
  record_conflict: 'DNS 记录存在冲突或重复，请先在 DNS 提供方整理', record_not_owned: '已有 DNS 记录，需勾选接管后才能更新',
  rate_limited: '云服务请求限流，等待自动重试', provider_rejected: '云服务拒绝请求，请检查记录配置与权限',
  resource_missing: 'Zone 或记录不存在，或 Token 无权访问', provider_unavailable: '云服务暂时不可用',
  network_error: '连接云服务 失败，等待重试', request_timeout: '请求超时，下轮将重新核对远端记录',
  invalid_response: '云服务返回了无法核对的响应', response_too_large: '云服务响应超过大小上限',
  redirect_refused: '云服务返回重定向，已停止请求', http_error: '云服务请求失败',
  storage_error: '读取服务器状态失败', client_error: '暂时无法初始化同步服务', invalid_configuration: '规则配置无效',
}
export function ddnsMessage(code: string | null | undefined) { return code ? Object.hasOwn(messages, code) ? messages[code] : '状态未知，请稍后刷新' : '' }
export const providers = { cloudflare: 'Cloudflare', tencent: '腾讯云 DNSPod', aliyun: '阿里云 DNS', huawei: '华为云 DNS' }
export function ddnsWrite(config: DdnsConfig, token: string, revision?: number, key = '', secret = '') {
  const cloudflare = !config.provider || config.provider === 'cloudflare'
  return { config: { ...config, ttl: config.proxied ? 1 : config.ttl }, ...(!config.credential_id && !config.account_id && cloudflare && token.trim() ? { api_token: token.trim() } : {}), ...(!config.credential_id && !config.account_id && !cloudflare && (key.trim() || secret.trim()) ? { access_key_id: key.trim(), access_key_secret: secret.trim() } : {}), ...(revision === undefined ? {} : { revision }) }
}
