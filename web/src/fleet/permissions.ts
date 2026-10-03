import { createContext, useContext } from 'react'

export type FleetActor = { role: string; capabilities: string[]; all_servers: boolean; server_ids: number[] }
type Scope = number | 'global'
export type FleetPermissions = { allows: (capability: string, server?: Scope) => boolean; reason: (capability: string, server?: Scope) => string }

export function fleetPermissions(resource: { getCurrent: () => FleetActor | undefined; error: string }): FleetPermissions {
  const reason = (capability: string, server?: Scope) => {
    const actor = resource.getCurrent()
    if (!actor) return resource.error ? '管理员权限读取失败，暂不能操作。' : '管理员权限正在刷新，完成后可操作。'
    if (!capability) return '此操作的权限类型尚未识别，需核对后再操作。'
    if (actor.role === 'viewer' && capability.endsWith(':write')) return '当前账号为只读角色，未授权修改。'
    if (actor.role !== 'owner' && !actor.capabilities.includes(capability)) return `当前账号未获 ${capability} 授权。`
    if (server === 'global' && !actor.all_servers) return '此入口需要全局服务器范围授权。'
    if (typeof server === 'number' && !actor.all_servers && !actor.server_ids.includes(server)) return '当前账号未获此服务器范围授权。'
    return ''
  }
  return { reason, allows: (capability, server) => reason(capability, server) === '' }
}

export const FleetPermissionsContext = createContext<FleetPermissions>({ allows: () => false, reason: () => '管理员权限尚未读取，暂不能操作。' })
export const useFleetPermissions = () => useContext(FleetPermissionsContext)

type Operation = { kind: string; action?: string; operation?: { action?: string } }
const readNetwork = ['inventory', 'mesh_status', 'tunnel_status', 'firewall_status']
export function operationCapability(operation: Operation): string {
  switch (operation.kind) {
    case 'snapshot': case 'runtime_permissions': return 'operations:read'
    case 'services': case 'logs': return 'services:read'
    case 'service': return operation.action === 'status' ? 'services:read' : 'services:write'
    case 'ports': return 'monitoring:read'
    case 'file_read': case 'file_inspect': return 'files:read'
    case 'file_write': case 'file_upload': return 'files:write'
    case 'system_network': return readNetwork.includes(operation.operation?.action ?? '') ? 'network:read' : 'network:write'
    case 'port_forward': return operation.operation?.action === 'status' ? 'network:read' : 'network:write'
    case 'certificate_deploy': return 'network:write'
    case 'certificate_inspect': return 'network:read'
    default: return ''
  }
}
export function inspectionCapability(operation: Operation): string {
  const capability = operationCapability(operation)
  return capability.endsWith(':write') ? capability.replace(':write', ':read') : capability
}
