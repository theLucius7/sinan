import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { api, errorMessage } from './api'
import { Brand, Loading } from './components'
import { useAction } from './hooks'
import AdminPage from './app/AdminPage'
import AdminShell from './app/AdminShell'
import Login from './app/Login'
import { currentNavigation } from './app/navigation'
import { resolveRoute } from './app/routes'

const ServerDisplay = lazy(() => import('./display/ServerDisplay'))
const UserPortal = lazy(() => import('./plugins/singbox/UserPortal'))

export default function App() {
  const [session, setSession] = useState<boolean | null>(null)
  const [publicDashboard, setPublicDashboard] = useState(false)
  const [accessRevision, setAccessRevision] = useState(0)
  const [notice, setNotice] = useState('')
  const [path, setPath] = useState(window.location.hash.slice(1) || '/dashboard')
  const sessionRef = useRef(session)
  sessionRef.current = session
  const action = useAction()

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    void api<{ authenticated: boolean; public_dashboard: boolean }>(
      '/api/dashboard/access', 'GET', undefined, controller.signal,
    ).then(access => {
      if (active) {
        setSession(access.authenticated)
        setPublicDashboard(access.public_dashboard)
        if (access.authenticated && (window.location.hash === '' || window.location.hash === '#/dashboard')) {
          void api<{ role: string; all_servers: boolean; capabilities: string[] }>('/api/control-center/me').then(actor => {
            if (active && actor.role !== 'owner' && (!actor.all_servers || !actor.capabilities.includes('monitoring:read'))) window.location.hash = actor.capabilities.includes('servers:read') ? '/servers' : '/system/control-center'
          }).catch(() => {})
        }
      }
    }).catch(error => {
      if (active) {
        setSession(false)
        setPublicDashboard(false)
        setNotice(errorMessage(error))
      }
    })
    const unauthorized = () => {
      if (sessionRef.current) setNotice('登录已过期，请重新登录。')
      setSession(false)
      setPublicDashboard(false)
      setAccessRevision(value => value + 1)
    }
    const hash = () => setPath(window.location.hash.slice(1) || '/dashboard')
    window.addEventListener('sinan:unauthorized', unauthorized)
    window.addEventListener('hashchange', hash)
    return () => {
      active = false
      controller.abort()
      window.removeEventListener('sinan:unauthorized', unauthorized)
      window.removeEventListener('hashchange', hash)
    }
  }, [accessRevision])

  const route = resolveRoute(path)
  const current = currentNavigation(route)
  const title = current?.label ?? '控制面板'
  useEffect(() => { document.title = `${title} · 司南` }, [title])

  if (route.page === 'proxy-portal') return <Suspense fallback={<div className="boot"><Brand /><Loading /></div>}><UserPortal key={route.account} account={route.account} activation={route.activation} /></Suspense>
  if (session === null) return <div className="boot"><Brand /><Loading /></div>
  if (!session && !(route.page === 'dashboard' && publicDashboard)) {
    return <Login notice={notice} onLogin={() => {
      setNotice('')
      setSession(true)
      setAccessRevision(value => value + 1)
    }} />
  }
  if (route.page === 'dashboard') {
    return <Suspense fallback={<div className="boot"><Brand /><Loading /></div>}>
      <ServerDisplay key={session ? 'admin' : 'public'} serverId={route.serverId} />
    </Suspense>
  }

  const logout = () => void action.run(() => api('/api/logout', 'POST'), () => {
    setSession(false)
    setNotice('')
    setPublicDashboard(false)
    setAccessRevision(value => value + 1)
  })
  return <AdminShell current={current} busy={action.busy} error={action.error} onLogout={logout}>
    <AdminPage route={route} />
  </AdminShell>
}
