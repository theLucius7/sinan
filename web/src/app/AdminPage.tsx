import { lazy, Suspense } from 'react'
import { Loading } from '../components'
import Servers from '../pages/Servers'
import ServerDetail from '../pages/ServerDetail'
import SingboxOverview from '../plugins/singbox/Overview'
import Nodes from '../plugins/singbox/Nodes'
import ProxyUsers from '../plugins/singbox/ProxyUsers'
import Groups from '../plugins/singbox/Groups'
import Plugins from '../pages/Plugins'
import PluginCatalog from '../pages/PluginCatalog'
import Security from '../pages/Security'
import Settings from '../pages/Settings'
import Notifications from '../pages/Notifications'
import LatencyTasks from '../pages/LatencyTasks'
import Statistics from '../pages/Statistics'
import ServerToolPage from '../pages/ServerToolPage'
import type { AppRoute } from './routes'

const FleetOperations = lazy(() => import('../fleet/FleetOperations'))
const NetworkWorkbench = lazy(() => import('../network-workbench/NetworkWorkbench'))
const NetworkConfiguration = lazy(() => import('../network-configuration/NetworkConfiguration'))
const OperationsPage = lazy(() => import('../operations/OperationsPage'))
const ControlCenter = lazy(() => import('../control-center/ControlCenter'))

const Ddns = lazy(() => import('../plugins/ddns/Ddns'))
const Alicloud = lazy(() => import('../plugins/alicloud/Alicloud'))

export default function AdminPage({ route }: { route: Exclude<AppRoute, { page: 'dashboard' | 'proxy-portal' }> }) {
  switch (route.page) {
    case 'server': {
      const { serverId, section } = route
      if (section === 'fleet') return <Suspense fallback={<Loading />}><FleetOperations key={serverId} serverId={serverId} /></Suspense>
      if (section === 'network-workbench') return <Suspense fallback={<Loading />}><NetworkWorkbench key={serverId} initialServerId={serverId} /></Suspense>
      if (section === 'network-configuration') return <Suspense fallback={<Loading />}><NetworkConfiguration key={serverId} serverId={serverId} /></Suspense>
      if (section === 'operations') return <Suspense fallback={<Loading />}><OperationsPage key={serverId} selectedServerId={serverId} /></Suspense>
      if (section === 'ddns') {
        return <Suspense fallback={<Loading />}><Ddns key={serverId} serverId={serverId} /></Suspense>
      }
      if (section === 'plugins') return <Plugins key={serverId} serverId={serverId} />
      if (section) return <ServerToolPage key={`${serverId}/${section}`} id={serverId} section={section} />
      return <ServerDetail key={serverId} id={serverId} />
    }
    case 'fleet': return <Suspense fallback={<Loading />}><FleetOperations /></Suspense>
    case 'network-workbench': return <Suspense fallback={<Loading />}><NetworkWorkbench /></Suspense>
    case 'network-configuration': return <Suspense fallback={<Loading />}><NetworkConfiguration /></Suspense>
    case 'operations': return <Suspense fallback={<Loading />}><OperationsPage /></Suspense>
    case 'control-center': return <Suspense fallback={<Loading />}><ControlCenter /></Suspense>
    case 'servers': return <Servers />
    case 'singbox-overview': return <SingboxOverview />
    case 'statistics': return <Statistics />
    case 'latency': return <LatencyTasks />
    case 'alicloud': return <Suspense fallback={<Loading />}><Alicloud /></Suspense>
    case 'ddns': return <Suspense fallback={<Loading />}><Ddns /></Suspense>
    case 'nodes': return <Nodes
      key="nodes"
      serverId={route.serverId}
      chainsOnly={route.chains}
      selected={route.selected}
      initialKind={route.kind}
      initialServerRole={route.serverRole}
    />
    case 'proxy-users': return <ProxyUsers />
    case 'groups': return <Groups />
    case 'plugins': return <Plugins />
    case 'catalog': return <PluginCatalog />
    case 'settings': return <Settings />
    case 'notifications': return <Notifications />
    case 'security': return <Security />
    case 'not-found': return <div className="not-found">
      <h1>这个页面不存在</h1>
      <p>从左侧导航选择一个页面，或回到服务器列表。</p>
      <a className="button button-primary" href="#/servers">返回服务器</a>
    </div>
  }
}
