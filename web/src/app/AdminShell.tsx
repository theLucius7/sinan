import { useEffect, useRef, useState } from 'react'
import { useResource } from '../hooks'
import GlobalSearch from '../control-center/GlobalSearch'
import Reauthentication from '../control-center/Reauthentication'
import Appearance from '../control-center/Appearance'
import type { ReactNode } from 'react'
import { Brand, ErrorNotice, Icon } from '../components'
import { LanguageSelect, useI18n } from '../i18n'
import { navigation } from './navigation'
import type { NavigationItem } from './navigation'
import './shell.css'

type Props = {
  current?: NavigationItem
  busy: boolean
  error: string
  onLogout: () => void
  children: ReactNode
}

export default function AdminShell({ current, busy, error, onLogout, children }: Props) {
  const { t } = useI18n()
  const actor = useResource<{ role: string; display_name: string; all_servers: boolean; capabilities: string[] }>('/api/control-center/me')
  const features: Record<string, string[]> = { servers: ['servers'], fleet: ['servers'], statistics: ['monitoring'], dashboard: ['monitoring'], latency: ['monitoring'], notifications: ['monitoring'], 'network-workbench': ['diagnostics'], 'network-configuration': ['network'], operations: ['operations', 'recovery', 'cloud'], alicloud: ['cloud'], ddns: ['dns'], 'singbox-overview': ['proxy'], nodes: ['proxy'], 'proxy-users': ['proxy'], groups: ['proxy'] }
  const globalPages = new Set(['statistics', 'dashboard', 'latency', 'notifications', 'alicloud', 'singbox-overview', 'nodes', 'proxy-users', 'groups'])
  const visibleNavigation = navigation.filter(item => item.page === 'control-center' || item.page === 'security' || actor.data?.role === 'owner' || ((!globalPages.has(item.page) || actor.data?.all_servers) && features[item.page]?.some(feature => actor.data?.capabilities.includes(`${feature}:read`))))
  const [menuOpen, setMenuOpen] = useState(false)
  const sidebar = useRef<HTMLElement>(null)
  const toggle = useRef<HTMLButtonElement>(null)

  // The compact menu closes after navigation, on Escape and on outside clicks.
  useEffect(() => {
    const close = () => setMenuOpen(false)
    window.addEventListener('hashchange', close)
    return () => window.removeEventListener('hashchange', close)
  }, [])
  useEffect(() => {
    if (!menuOpen) return
    const key = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      setMenuOpen(false)
      toggle.current?.focus()
    }
    const pointer = (event: MouseEvent) => {
      if (event.target instanceof Node && !sidebar.current?.contains(event.target)) setMenuOpen(false)
    }
    document.addEventListener('keydown', key)
    document.addEventListener('mousedown', pointer)
    return () => {
      document.removeEventListener('keydown', key)
      document.removeEventListener('mousedown', pointer)
    }
  }, [menuOpen])

  return <div className="app-shell">
    <Reauthentication /><Appearance />
    <aside ref={sidebar} className={menuOpen ? 'sidebar menu-open' : 'sidebar'}>
      <div className="sidebar-header">
        <a href="#/servers" className="brand-link" aria-label={t('司南首页')}><Brand /></a>
        <button ref={toggle} type="button" className="menu-toggle" aria-expanded={menuOpen}
          aria-controls="admin-navigation" onClick={() => setMenuOpen(open => !open)}>
          <Icon name={menuOpen ? 'close' : 'menu'} size={18} /><span>{t('菜单')}</span>
        </button>
      </div>
      <nav id="admin-navigation" aria-label={t('主导航')}>
        {visibleNavigation.map((item, index) => <div className="nav-entry" key={item.path}>
          {visibleNavigation[index - 1]?.group !== item.group && <div className="nav-group-label">{t(item.group)}</div>}
          <a href={`#${item.path}`} className={current?.path === item.path ? 'active' : ''}
            aria-current={current?.path === item.path ? 'page' : undefined}>
            <Icon name={item.icon} size={18} /><span>{t(item.label)}</span>
          </a>
        </div>)}
      </nav>
      <div className="sidebar-bottom">
        <button className="logout-button" disabled={busy} onClick={onLogout}>
          <span className="admin-avatar">管</span>
          <span><strong>{actor.data?.display_name ?? t('管理员')}</strong><small>{actor.data?.role === 'viewer' ? t('只读 · ') : actor.data?.role === 'operator' ? t('运维 · ') : ''}{t('退出登录')}</small></span>
          <Icon name="logout" size={17} />
        </button>
      </div>
    </aside>
    <div className="main-layout">
      <div className="topbar">
        <nav aria-label={t('当前位置')} className="breadcrumb">
          {current && <><span>{t(current.group)}</span><span aria-hidden="true">/</span></>}
          <strong aria-current="page">{t(current?.label ?? '页面不存在')}</strong>
        </nav>
        <GlobalSearch />
        <LanguageSelect className="topbar-language" />
        <span className="topbar-status"><span className="status-dot" />{t('管理员会话已登录')}</span>
      </div>
      <main className="content"><ErrorNotice message={error} />{children}</main>
      <footer className="app-footer"><span>{t('司南')}</span><span>{t('清晰掌握，自在连接。')}</span></footer>
    </div>
  </div>
}
