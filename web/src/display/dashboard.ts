import type { Server } from '../types'
import { filterServers, fresh, network, number, ratio } from './data'

export type DashboardView = 'cards' | 'table'
export type DashboardSort = 'default' | 'name' | 'attention' | 'cpu' | 'memory' | 'network'
export type DashboardFilter = 'all' | 'online' | 'offline' | 'pending' | 'stale'
export const dashboardHome = '#/dashboard'
export const dashboardServer = (id: number) => `${dashboardHome}/${id}`

// The old display links remain valid bookmarks; never reinterpret an unsafe numeric ID.
export function dashboardRoute(path: string): { serverId?: number } | null {
  if (path === '/' || path === '/dashboard' || path === '/overview') return {}
  const match = path.match(/^\/(?:dashboard|overview)\/([1-9]\d*)$/)
  return match && Number.isSafeInteger(Number(match[1])) ? { serverId: Number(match[1]) } : null
}

export function savedView(value: unknown): DashboardView { return value === 'table' ? 'table' : 'cards' }
export function savedSort(value: unknown): DashboardSort {
  return ['default', 'name', 'attention', 'cpu', 'memory', 'network'].includes(String(value)) ? value as DashboardSort : 'default'
}

export function snapshotUnavailable(updatedAt: number | null, now: number, paused: boolean, error: string): boolean {
  return paused || Boolean(error) || updatedAt === null || !Number.isFinite(updatedAt) || now - updatedAt > 15_000 || updatedAt > now + 60_000
}

export function dashboardCounts(servers: Server[]) {
  return {
    all: servers.length,
    online: servers.filter(server => server.online).length,
    offline: servers.filter(server => !server.online && (server.registered ?? Boolean(server.device_public_key))).length,
    pending: servers.filter(server => !server.online && !(server.registered ?? Boolean(server.device_public_key))).length,
    stale: servers.filter(server => server.online && !fresh(server)).length,
  }
}

function metric(server: Server, sort: DashboardSort, unavailable: boolean): number | null {
  if (unavailable || !fresh(server)) return null
  const metrics = server.latest_metrics
  if (sort === 'cpu') return number(metrics.cpu_percent)
  if (sort === 'memory') return ratio(metrics.memory_used, server.static_info.memory_total)
  const up = network(metrics, 'transmit_bytes_per_sec', server.asset_settings?.network_interface), down = network(metrics, 'receive_bytes_per_sec', server.asset_settings?.network_interface)
  return up === null || down === null ? null : up + down
}

export function attention(server: Server): number {
  if (!server.online) return (server.registered ?? Boolean(server.device_public_key)) ? 3 : 1
  if (!fresh(server)) return 2
  const metrics = server.latest_metrics
  return [number(metrics.cpu_percent), ratio(metrics.memory_used, server.static_info.memory_total), ratio(metrics.disk_used, server.static_info.disk_total)]
    .some(value => value !== null && value >= 90) ? 1 : 0
}

export function selectServers(servers: Server[], query: string, filter: DashboardFilter, group: string, region: string, sort: DashboardSort, unavailable: boolean) {
  const visible = filterServers(servers.filter(server => !server.asset_settings?.hidden), query, filter === 'stale' ? 'online' : filter)
    .filter(server => (filter !== 'stale' || !fresh(server)) && (!group || server.asset_settings?.group_name === group) && (!region || server.asset_settings?.region === region))
  return visible.sort((left, right) => {
    if (sort === 'name') return left.name.localeCompare(right.name, 'zh-CN', { numeric: true }) || left.id - right.id
    if (sort === 'attention' && !unavailable) return attention(right) - attention(left) || left.id - right.id
    if (['cpu', 'memory', 'network'].includes(sort)) {
      const a = metric(left, sort, unavailable), b = metric(right, sort, unavailable)
      if (a !== null && b === null) return -1
      if (a === null && b !== null) return 1
      if (a !== null && b !== null && a !== b) return b - a
    }
    return left.id - right.id
  })
}
