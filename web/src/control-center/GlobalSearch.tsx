import { useEffect, useRef, useState } from 'react'
import { api, errorMessage } from '../api'
import { usePreference } from './preferences'
import { useI18n } from '../i18n'
import './control-center.css'
type Item = { kind: string; id: number | string; label: string; path: string }
const kinds: Record<string, string> = { server: '服务器', ip: '服务器地址', 'ip-observation': 'IP来源观测', 'ip-quality': 'IP质量资料', node: '节点', 'proxy-user': '代理用户', domain: '域名', certificate: '证书', 'dns-rule': 'DNS规则', 'network-rule': '网络规则', 'diagnostic-task': '诊断任务', 'test-plan': '测试方案', 'test-run': '测试运行', 'command-task': '远程命令', 'fleet-task': '设备操作', 'operation-task': '运维任务', 'operation-schedule': '任务计划', 'remediation-rule': '自动处置规则', maintenance: '维护窗口', incident: '故障事件', 'probe-rule': '探测规则', 'alert-rule': '告警规则', 'latency-task': '延迟监测', task: '任务', rule: '规则' }
export default function GlobalSearch() {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Item[]>([])
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const input = useRef<HTMLInputElement>(null)
  const recent = usePreference<Item[]>('recent')
  const favorite = usePreference<Item[]>('favorite')
  useEffect(() => {
    const keyboard = (event: KeyboardEvent) => {
      if ((event.key === 'k' && (event.metaKey || event.ctrlKey)) || (event.key === '/' && !(event.target instanceof HTMLInputElement || event.target instanceof HTMLTextAreaElement))) { event.preventDefault(); setOpen(true); input.current?.focus() }
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', keyboard)
    return () => window.removeEventListener('keydown', keyboard)
  }, [])
  useEffect(() => {
    if (!query.trim()) { setResults([]); return }
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      void api<{ results: Item[] }>(`/api/control-center/search?q=${encodeURIComponent(query.trim())}`, 'GET', undefined, controller.signal)
        .then(result => { setResults(result.results); setError('') }).catch(error => { if (!controller.signal.aborted) setError(errorMessage(error)) })
    }, 250)
    return () => { window.clearTimeout(timer); controller.abort() }
  }, [query])
  const visit = (item: Item) => {
    window.location.hash = item.path; setOpen(false)
    if (recent.ready) void recent.save([item, ...(recent.value ?? []).filter(value => value.path !== item.path)].slice(0, 20)).catch(error => setError(errorMessage(error)))
  }
  const pin = (item: Item) => {
    const values = favorite.value ?? []
    void favorite.save(values.some(value => value.path === item.path) ? values.filter(value => value.path !== item.path) : [item, ...values].slice(0, 30)).catch(error => setError(errorMessage(error)))
  }
  const shown = query.trim() ? results : [...(favorite.value ?? []), ...(recent.value ?? []).filter(item => !(favorite.value ?? []).some(value => value.path === item.path))]
  return <div className="global-search">
    <input ref={input} type="search" aria-label={t('全局搜索')} placeholder={t('搜索服务器、域名、节点、任务…')} value={query} onFocus={() => setOpen(true)} onChange={event => { setQuery(event.target.value); setOpen(true) }} />
    {open && <div className="global-search-results"><div className="control-actions"><strong>{query.trim() ? t('搜索结果') : t('收藏与最近访问')}</strong><button className="ui-button" onClick={() => setOpen(false)} aria-label={t('关闭搜索')}>{t('关闭')}</button></div>
      {error && <p role="alert">{error}</p>}{shown.length === 0 && <p>{query.trim() ? t('没有匹配的授权对象') : t('输入搜索词或访问对象后添加收藏。')}</p>}
      {shown.map((item, index) => <div className="search-item" key={`${item.kind}-${item.id}-${index}`}><button className="search-result" onClick={() => visit(item)}><small>{t(kinds[item.kind] ?? item.kind)}</small><span>{item.label}</span></button><button className="icon-button" disabled={!favorite.ready} aria-label={`${t('收藏')}${item.label}`} onClick={() => pin(item)}>{(favorite.value ?? []).some(value => value.path === item.path) ? '★' : '☆'}</button></div>)}
      <small>{t('Ctrl / ⌘ + K 打开，Esc 关闭')}</small>
    </div>}
  </div>
}
