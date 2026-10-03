export type Target = { bandwidth_mbps: number; charge_type: 'PayByTraffic' | 'PayByBandwidth' }
export type Snapshot = Target & { kind: string; cloud_id: string; region: string; public_ip: string; resource_charge_type: string; status: string }
export type Bill = { month: string; queried_at: number; usage_micro_gb: number | null; rows: { instance_id: string; region: string; product_type: string; billing_item: string; usage: string; unit: string; amount: string; currency: string }[] }
export type Account = { credential_id?: string | null; id: string; name: string; site: 'china' | 'international'; enabled: boolean; auto_enabled: boolean; limit_gb: number; revision: number; next_run_at: number; error_code: string | null; bill: Bill | null; traffic_error: string | null; traffic: { queried_at: number; mainland_bytes: string; overseas_bytes: string; regions: { region: string; bytes: string }[] } | null; balance?: { available: string; currency: string; queried_at: number } | null; balance_error?: string | null; balance_next_at?: number }
export type Resource = { id: string; account_id: string; name: string; kind: 'ecs' | 'eip'; region: string; cloud_id: string; auto_enabled: boolean; cap_mbps: number; revision: number; snapshot: Snapshot | null; checked_at: number | null; error_code: string | null; power_policy?: PowerPolicy; power_state?: PowerState | null; power_checked_at?: number | null; power_error?: string | null; manual_hold?: boolean; threshold_hold?: boolean; instance_bill?: { month: string; queried_at: number; rows: { item: string; amount: string; currency: string }[] } | null; bill_error?: string | null; bill_next_at?: number }
export type Operation = { id: string; resource_id: string; account_revision?: number; resource_revision?: number; before_state: Snapshot; target: Target; source: string; billing_cycle: string | null; status: string; created_at: number; updated_at: number; expires_at: number; error_code: string | null; request_id: string | null }
export type Overview = { accounts: Account[]; resources: Resource[]; operations: Operation[]; power_jobs?: PowerJob[]; events?: CloudEvent[] }
export type PowerPolicy = { enabled: boolean; stop_mode: 'KeepCharging' | 'StopCharging'; threshold_action: 'off' | 'notify' | 'stop'; limit_gb: number; threshold_percent: number; schedule_enabled: boolean; start_time: string; stop_time: string; utc_offset_minutes: number; keepalive: boolean }
export const defaultPowerPolicy: PowerPolicy = { enabled: false, stop_mode: 'KeepCharging', threshold_action: 'off', limit_gb: 100, threshold_percent: 95, schedule_enabled: false, start_time: '08:00', stop_time: '23:00', utc_offset_minutes: 480, keepalive: false }
export type PowerState = { cloud_id: string; region: string; status: string; stopped_mode: string | null; charge_type: string; network_type: string; spot_strategy: string; interruption_behavior: string | null; public_ips: string[]; locked: boolean }
export type PowerJob = { id: string; resource_id: string; account_revision?: number; resource_revision?: number; action: string; stop_mode: string; source: string; before_state: PowerState; status: string; created_at: number; expires_at: number; error_code: string | null; request_id: string | null }
export type CloudEvent = { id: number; resource_id: string; title: string; message: string; created_at: number; deliveries: { channel: string; status: string; attempts: number; last_error: string | null }[] }
export const stopMode = (mode: string) => mode === 'StopCharging' ? '节省停机' : mode === 'KeepCharging' ? '普通停机' : '停机模式未知'
const powerStates: Record<string, string> = { Running: '运行中', Stopped: '已停止', Starting: '启动中', Stopping: '停止中', Pending: '准备中' }
export const powerStatus = (value?: string) => value && Object.hasOwn(powerStates, value) ? powerStates[value] : '尚未查询'
const powerSources: Record<string, string> = { manual: '手动', threshold: '流量阈值', schedule: '每日计划', keepalive: '抢占式保活' }
export const powerSource = (value: string) => Object.hasOwn(powerSources, value) ? powerSources[value] : '未知来源'
export const utcOffset = (minutes: number) => `UTC${minutes < 0 ? '−' : '+'}${String(Math.floor(Math.abs(minutes) / 60)).padStart(2, '0')}:${String(Math.abs(minutes) % 60).padStart(2, '0')}`
export const charge = (value: string) => value === 'PayByTraffic' ? '按流量计费' : value === 'PayByBandwidth' ? '按带宽计费' : '未知计费方式'
export const time = (value: number | null) => value ? new Date(value * 1000).toLocaleString('zh-CN', { hour12: false }) : '尚未查询'
const states: Record<string, string> = { preview: '等待确认', queued: '等待执行', running: '执行中', uncertain: '结果待核对', succeeded: '已核对完成', failed: '未执行', cancelled: '已取消', dismissed: '已人工结束跟踪' }
const messages: Record<string, string> = {
  credential_unavailable: '集中云凭据停用、用途不符或解密密钥缺失', credential_invalid: '集中云凭据字段或提供方不符',
  authentication_failed: '访问密钥无效或缺少权限', rate_limited: '云服务限流，稍后重试', resource_not_found: '未找到指定地域和标识的资源',
  capacity_unavailable: '库存或抢占价格条件不足，保活冷却后再尝试', insufficient_balance: '账号余额不足或资源欠费，请在云端核对', resource_locked: '云端已锁定实例', request_rejected: '云端明确拒绝请求，请核对状态与权限',
  stop_mode_unsupported: '节省停机需要按量付费 VPC 实例', stop_mode_mismatch: '实例已停止，但停机模式与请求不符，请核对收费', stop_mode_unknown: '实例已停止，但无法核实实际停机模式',
  unsupported_resource: '仅支持 ECS 固定公网 IP 与按量付费的独立 EIP；不操作共享带宽包', resource_busy: '云资源正在变更或状态不支持调整',
  billing_incomplete: '账单数据不完整，自动控制暂停', state_changed: '云资源或本地配置已变化，请重新预览', policy_inactive: '策略已关闭或账单数据不可用于控制',
  request_timeout: '云接口超时，等待核对结果', network_error: '云接口连接失败', response_error: '云接口暂时不可用', invalid_response: '云接口响应与预期不符',
  provider_rejected: '云服务拒绝请求，请检查权限和资源限制', awaiting_confirmation: '尚未核对到目标状态，系统只读回结果，不重复提交',
}
export const status = (value: string) => Object.hasOwn(states, value) ? states[value] : '状态未知'
export const message = (value: string | null | undefined) => value ? Object.hasOwn(messages, value) ? messages[value] : '云接口暂时不可用' : ''
export function accountWrite(account: Pick<Account, 'name' | 'site' | 'enabled' | 'auto_enabled' | 'limit_gb'>, key: string, secret: string, revision?: number, credentialId = '', legacy = false) {
  return { name: account.name.trim(), site: account.site, enabled: account.enabled, auto_enabled: account.auto_enabled, limit_gb: account.limit_gb, ...(revision === undefined ? {} : { revision }), ...(credentialId.trim() ? { credential_id: credentialId.trim() } : legacy ? { legacy_credentials: true, ...(key.trim() || secret.trim() ? { access_key_id: key.trim(), access_key_secret: secret.trim() } : {}) } : {}) }
}
export function billUsable(account: Account, now = Date.now() / 1000) {
  const month = new Date((now + 8 * 3600) * 1000).toISOString().slice(0, 7), bill = account.bill
  return Boolean(account.enabled && !account.error_code && bill && bill.month === month && Number.isSafeInteger(bill.usage_micro_gb) && bill.usage_micro_gb! >= 0 && Number.isSafeInteger(bill.queried_at) && bill.queried_at > 0 && bill.queried_at <= now && bill.queried_at + 900 >= now)
}

export const exactUsage = (value: number | null | undefined) => Number.isSafeInteger(value) && value! >= 0 ? value! / 1e6 : null
