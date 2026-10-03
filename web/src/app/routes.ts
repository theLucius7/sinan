import { dashboardRoute } from '../display/dashboard'
import { isCatalogPath } from '../plugins/catalog'
import { nodeRoute } from '../plugins/singbox/nodeRoute'
import { resourceRoute } from '../plugins/singbox/resourceTypes'
import type { ResourceKey } from '../plugins/singbox/resourceTypes'

type ServerSection = 'ip-info' | 'node-quality' | 'tcp-quality' | 'plugins' | 'ddns' | 'fleet' | 'network-workbench' | 'network-configuration' | 'operations'
type SimplePage = 'singbox-overview' | 'servers' | 'statistics' | 'latency' | 'alicloud' | 'ddns'
  | 'proxy-users' | 'groups' | 'plugins' | 'catalog' | 'settings' | 'notifications' | 'security' | 'fleet' | 'network-workbench' | 'network-configuration' | 'operations' | 'control-center' | 'not-found'

export type AppRoute =
  | { page: 'dashboard'; serverId?: number }
  | { page: 'proxy-portal'; account: string; activation?: string }
  | { page: 'server'; serverId: number; section?: ServerSection }
  | { page: 'nodes'; serverId?: number; chains?: boolean; selected?: ResourceKey; kind?: 'direct'; serverRole?: 'any' | 'entry' | 'middle' | 'exit' }
  | { page: SimplePage }

const pages: Readonly<Record<string, SimplePage>> = {
  '/servers': 'servers',
  '/fleet': 'fleet',
  '/network-workbench': 'network-workbench',
  '/network-configuration': 'network-configuration',
  '/operations': 'operations',
  '/system/control-center': 'control-center',
  '/plugins/sing-box': 'singbox-overview',
  '/statistics': 'statistics',
  '/latency': 'latency',
  '/plugins/alicloud': 'alicloud',
  '/plugins/ddns': 'ddns',
  '/plugins/sing-box/users': 'proxy-users',
  '/plugins/sing-box/groups': 'groups',
  '/system/plugins': 'plugins',
  '/system/settings': 'settings',
  '/system/notifications': 'notifications',
  '/system/administrator': 'security',
}

export function resolveRoute(path: string): AppRoute {
  const portal = path.match(/^\/plugins\/sing-box\/account\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\?activate=([A-Za-z0-9_-]{43}))?$/)
  if (portal) return { page: 'proxy-portal', account: portal[1], activation: portal[2] }
  const display = dashboardRoute(path)
  if (display) return { page: 'dashboard', ...display }

  const server = path.match(/^\/servers\/([1-9]\d*)(?:\/(ip-info|node-quality|tcp-quality|plugins|ddns|fleet|network-workbench|network-configuration|operations))?$/)
  if (server && Number.isSafeInteger(Number(server[1]))) {
    return { page: 'server', serverId: Number(server[1]), section: server[2] as ServerSection | undefined }
  }

  if (path === '/plugins/sing-box/chains') return { page: 'nodes', chains: true }
  const node = nodeRoute(path)
  if (node) {
    if (node.resource) return { page: 'nodes', selected: node.resource }
    return { page: 'nodes', ...(node.serverId === undefined ? {} : { serverId: node.serverId }), chains: node.chains,
      ...(node.kind === 'direct' ? { kind: 'direct' as const } : {}), ...(node.serverRole ? { serverRole: node.serverRole } : {}) }
  }
  const resource = resourceRoute(path)
  if (resource) return { page: 'nodes', selected: resource }
  if (isCatalogPath(path)) return { page: 'catalog' }

  return { page: Object.hasOwn(pages, path) ? pages[path] : 'not-found' }
}
