import type { DdnsConfig, DdnsRule } from './types'
export type DdnsServer = { id: number; name: string; online: boolean; enabled: boolean; interface_names?: string[]; public_discovery_available?: boolean }
export type DdnsCurrent = () => { rules: DdnsRule[]; servers: DdnsServer[] } | undefined
const stale = '规则或服务器正在刷新或刷新失败，请成功刷新后再提交；当前草稿已保留。'
const changed = '规则或服务器已变化，请重新核对；当前草稿已保留。'
export const sameRevision = (draft: number, current: number) => Number.isSafeInteger(draft) && draft > 0 && draft === current
export const ddnsCurrentError = (current: DdnsCurrent) => current() ? '' : stale

export function serverError(current: DdnsCurrent, draft: DdnsServer) {
  const data = current()
  if (!data) return stale
  const server = data.servers.find(item => item.id === draft.id)
  return !server || server.enabled !== draft.enabled ? changed : ''
}
export function ruleError(current: DdnsCurrent, draft: DdnsRule, enabled = false) {
  const data = current()
  if (!data) return stale
  const rule = data.rules.find(item => item.id === draft.id), server = data.servers.find(item => item.id === draft.config.server_id)
  return !rule || !server || rule.busy || !sameRevision(draft.revision, rule.revision) ||
    rule.config.server_id !== draft.config.server_id || (enabled && (!rule.config.enabled || !rule.plugin_enabled || !server.enabled)) ? changed : ''
}
export function editorError(current: DdnsCurrent, config: DdnsConfig, draft?: DdnsRule, slots: 1 | 2 = 1) {
  const data = current()
  if (!data) return stale
  if (draft) {
    const reason = ruleError(current, draft)
    if (reason) return reason
    if ((config.provider ?? 'cloudflare') !== (draft.config.provider ?? 'cloudflare') || config.zone_id !== draft.config.zone_id ||
      config.record_name !== draft.config.record_name || config.record_type !== draft.config.record_type || (config.line ?? '') !== (draft.config.line ?? '')) return changed
  } else if (data.rules.length + slots > 32) return slots === 2 ? '双栈需要两条规则名额，最多配置 32 条动态解析规则。' : '最多配置 32 条动态解析规则。'
  const server = data.servers.find(item => item.id === config.server_id)
  return !server || (config.enabled && !server.enabled) ? changed : ''
}
