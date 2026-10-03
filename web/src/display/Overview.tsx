import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { ProbeOverview } from '../probes'
import type { Server } from '../types'
import { aggregate, fresh, network, size, speed } from './data'
import { dashboardCounts, savedSort, savedView, selectServers, snapshotUnavailable } from './dashboard'
import type { DashboardFilter, DashboardSort, DashboardView } from './dashboard'
import { Icon } from './Icon'
import { ServerCard } from './ServerCard'
import ServerTable from './ServerTable'
import { useDashboardPoll } from './useDashboardPoll'
import { useDashboardServers } from './useDashboardServers'
import { useCurrency } from './CurrencyContext'
import { costSummary, money, quoteState } from './currency'

function Stat({ icon, label, value, unit, children, tone, title }: { icon?: string; label: string; value: ReactNode; unit?: string; children: ReactNode; tone?: string; title?: string }) {
  return <div className="d-overview-item" title={title}><div className="d-overview-label"><span>{label}</span><span className={`d-stat-icon ${tone ? `d-${tone}` : ''}`}><Icon name={icon ?? 'server'} size={17} /></span></div><div className="d-overview-value"><strong className={tone ? `d-${tone}` : ''}>{value}</strong>{unit && <b>{unit}</b>}</div><div className="d-overview-note">{children}</div></div>
}

function readPreference(key: string): string | null {
  try { return localStorage.getItem(`sinan-dashboard-${key}`) } catch { return null }
}
function savePreference(key: string, value: string) {
  try { localStorage.setItem(`sinan-dashboard-${key}`, value) } catch { /* Keep the in-memory choice when storage is disabled. */ }
}
const filters: [DashboardFilter, string][] = [['all', '全部'], ['online', '在线'], ['offline', '离线'], ['pending', '待接入'], ['stale', '指标待更新']]

export default function Overview({ now }: { now: number }) {
  const resource = useDashboardServers(false)
  const { currency, quote, error: currencyError } = useCurrency()
  const { data: servers, error, loading, updatedAt } = resource
  const probes = useDashboardPoll<ProbeOverview[]>('/api/dashboard/probes/overview', 15_000, false, servers?.some(server => server.public_view) ? 'public' : 'admin')
  const [view, setView] = useState<DashboardView>(() => savedView(readPreference('view')))
  const [sort, setSort] = useState<DashboardSort>(() => savedSort(readPreference('sort')))
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState<DashboardFilter>('all')
  const [group, setGroup] = useState('')
  const [region, setRegion] = useState('')
  const [optionsOpen, setOptionsOpen] = useState(false)
  const unavailable = snapshotUnavailable(updatedAt, now, false, error)
  const probeUnavailable = Boolean(probes.error) || probes.updatedAt === null || now - probes.updatedAt > 45_000
  const byServer = useMemo(() => {
    const grouped = new Map<number, ProbeOverview[]>()
    for (const entry of probes.data ?? []) {
      const items = grouped.get(entry.server_id) ?? []
      items.push(entry); grouped.set(entry.server_id, items)
    }
    return grouped
  }, [probes.data])
  const entries = useMemo(() => (servers ?? []).filter(server => !server.asset_settings?.hidden), [servers])
  const groups = [...new Set(entries.map(server => server.asset_settings?.group_name).filter((value): value is string => Boolean(value)))].sort()
  const regions = [...new Set(entries.map(server => server.asset_settings?.region).filter((value): value is string => Boolean(value)))].sort()
  const visible = useMemo(() => selectServers(entries, query, filter, group, region, sort, unavailable), [entries, query, filter, group, region, sort, unavailable])
  const counts = dashboardCounts(entries)
  const upload = aggregate(entries, 'transmit_bytes_per_sec', true), download = aggregate(entries, 'receive_bytes_per_sec', true)
  const completeCounters = entries.filter(server => network(server.latest_metrics, 'transmitted_bytes', server.asset_settings?.network_interface) !== null && network(server.latest_metrics, 'received_bytes', server.asset_settings?.network_interface) !== null)
  const sent = aggregate(completeCounters, 'transmitted_bytes'), received = aggregate(completeCounters, 'received_bytes')
  const total = sent.value === null || received.value === null ? null : sent.value + received.value
  const costs = costSummary(entries, currency, quote, now)
  const showCosts = entries.some(server => !server.public_view)
  const needsConversion = entries.some(server => !server.public_view && server.asset_settings?.price !== null && server.asset_settings?.price !== undefined && server.asset_settings.currency !== currency)
  const referenceState = quoteState(quote, currencyError)
  const staleCosts = needsConversion && referenceState !== 'fresh'
  const busiest = (field: 'transmit_bytes_per_sec' | 'receive_bytes_per_sec') => entries.filter(fresh).reduce<Server | null>((best, server) => (network(server.latest_metrics, field, server.asset_settings?.network_interface) ?? -1) > (best ? network(best.latest_metrics, field, best.asset_settings?.network_interface) ?? -1 : -1) ? server : best, null)
  const topUpload = busiest('transmit_bytes_per_sec'), topDownload = busiest('receive_bytes_per_sec')
  const peak = (server: Server | null, field: 'transmit_bytes_per_sec' | 'receive_bytes_per_sec') => {
    if (unavailable) return '等待更新'
    if (!server) return '暂无有效速率数据'
    const value = network(server.latest_metrics, field, server.asset_settings?.network_interface)
    return value === null ? '暂无有效速率数据' : value > 0 ? <span title={server.name}>峰值 {server.name}</span> : '暂无实时流量'
  }
  const [uploadValue, uploadUnit] = (unavailable ? '—' : speed(upload.value)).split(' ')
  const [downloadValue, downloadUnit] = (unavailable ? '—' : speed(download.value)).split(' ')
  const refresh = () => { resource.reload(); probes.reload() }
  const reset = () => { setQuery(''); setFilter('all'); setGroup(''); setRegion('') }
  const changed = Boolean(query || filter !== 'all' || group || region)
  const chooseView = (value: DashboardView) => { setView(value); savePreference('view', value) }
  const chooseSort = (value: string) => { const next = savedSort(value); setSort(next); savePreference('sort', next) }
  return <div className="d-home">
    <section className={`d-overview d-glass ${showCosts ? 'd-overview-assets' : ''}`} aria-label="服务器总览">
      <Stat icon="server" label="在线节点" value={!servers || unavailable ? '—' : counts.online} unit={servers ? `/ ${entries.length} 台` : undefined} tone="good">{unavailable ? '等待更新' : !entries.length ? '等待接入' : counts.online === counts.all ? '全部运行正常' : `${counts.offline} 台离线${counts.pending ? ` · ${counts.pending} 台待接入` : ''}`}</Stat>
      {showCosts && <Stat icon="wallet" label="资产" value={money(costs.total, currency)} title={`${costs.converted} 台可折算 · ${costs.missingPrices} 台未填写费用；每 30 天约 ${money(costs.recurring, currency)}`}><span>剩余价值 {money(costs.remaining, currency)}</span>{costs.missingRates > 0 ? <span className="d-warning" title={`${costs.missingRates} 台缺少汇率，未计入合计`}>汇率缺失</span> : staleCosts ? <span className="d-warning" title={referenceState === 'read-error' ? '汇率读取失败，使用上次有效汇率' : referenceState === 'stale' ? '使用上次有效汇率' : '无法确认参考汇率状态'}>{referenceState === 'read-error' ? '汇率读取失败' : referenceState === 'stale' ? '旧汇率' : '汇率状态未知'}</span> : null}</Stat>}
      <Stat icon="database" label="累计流量" value={size(total)} title={`网卡累计 · ${completeCounters.length} / ${entries.length} 台有完整计数`}><span className="d-good">上传 {size(sent.value)}</span><span className="d-info">下载 {size(received.value)}</span></Stat>
      <Stat icon="up" label="实时上行" value={uploadValue} unit={uploadUnit} tone="good" title={`${upload.count} / ${entries.length} 台有有效采样`}>{peak(topUpload, 'transmit_bytes_per_sec')}</Stat>
      <Stat icon="down" label="实时下行" value={downloadValue} unit={downloadUnit} tone="info" title={`${download.count} / ${entries.length} 台有有效采样`}>{peak(topDownload, 'receive_bytes_per_sec')}</Stat>
    </section>
    <div className="d-dashboard-toolbar">
      <div className="d-toolbar"><label className="d-search"><Icon name="search" size={16} /><input type="search" aria-label="搜索服务器" placeholder="搜索节点" value={query} onChange={event => setQuery(event.target.value)} /></label>
        <div className="d-segmented d-group-tabs" role="group" aria-label="服务器分组"><button aria-pressed={!group} onClick={() => setGroup('')}>全部</button>{groups.map(name => <button key={name} aria-pressed={group === name} onClick={() => setGroup(name)}>{name}</button>)}</div>
        <div className="d-toolbar-actions"><span className="d-result-count">{servers ? `${visible.length} 个节点` : '等待数据'}</span><button className={`d-icon-button ${filter !== 'all' || region || sort !== 'default' || view !== 'cards' ? 'd-options-active' : ''}`} aria-label="筛选与视图" title="筛选与视图" aria-expanded={optionsOpen} aria-controls="dashboard-options" onClick={() => setOptionsOpen(value => !value)}><Icon name="list" size={16} /></button><button className="d-icon-button" aria-label="刷新服务器" title="刷新服务器" onClick={refresh} disabled={loading && probes.loading}><Icon name="refresh" size={17} /></button></div>
      </div>
      {optionsOpen && <div className="d-dashboard-options" id="dashboard-options">
        <div className="d-segmented" role="group" aria-label="服务器状态筛选">{filters.map(([value, label]) => <button key={value} aria-label={label} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}<span className="d-filter-count" aria-hidden="true">{!servers || (value !== 'all' && unavailable) ? '—' : counts[value]}</span></button>)}</div>
        <div className="d-asset-filters"><label>地区<select aria-label="地区" value={region} onChange={event => setRegion(event.target.value)}><option value="">全部地区</option>{regions.map(name => <option key={name} value={name}>{name}</option>)}</select></label>
          <label>排序<select aria-label="排序" value={sort} onChange={event => chooseSort(event.target.value)}><option value="default">默认顺序</option><option value="attention">需关注的优先</option><option value="name">按名称</option><option value="cpu">处理器占用优先</option><option value="memory">内存占用优先</option><option value="network">网络速率优先</option></select></label>
        </div>
        <div className="d-dashboard-view">{changed && <button className="d-clear-filters" onClick={reset}>清除筛选</button>}<div className="d-segmented" role="group" aria-label="看板视图"><button aria-pressed={view === 'cards'} onClick={() => chooseView('cards')}><Icon name="grid" size={14} />卡片</button><button aria-pressed={view === 'table'} onClick={() => chooseView('table')}><Icon name="list" size={14} />表格</button></div></div>
      </div>}
    </div>
    {!error && unavailable && servers && <div className="d-notice" role="status"><span>连接中断，等待更新</span><button onClick={refresh}>重试</button></div>}
    {error && <div className="d-notice d-error" role="alert"><span>{error}</span><button onClick={refresh}>重试</button></div>}
    {probes.error && <div className="d-notice d-error" role="alert"><span>拨测读取失败</span><button onClick={probes.reload}>重试拨测</button></div>}
    {!servers ? !error && <div className="d-empty" role="status">{loading ? <><span className="spinner" />正在读取服务器…</> : '等待数据'}</div> : visible.length ? view === 'cards' ?
      <section className="d-node-grid" aria-label="服务器列表">{visible.map(server => <ServerCard key={server.id} server={server} unavailable={unavailable} probes={probes.data ? byServer.get(server.id) ?? [] : undefined} probeError={probeUnavailable} probeLoading={probes.loading} now={now} />)}</section> :
      <ServerTable servers={visible} unavailable={unavailable} byServer={byServer} probesKnown={probes.data !== undefined} probeError={probeUnavailable} probeLoading={probes.loading} now={now} /> :
      !error && <div className="d-empty"><Icon name="server" size={32} /><strong>{entries.length ? '没有匹配的节点' : resource.hiddenOnly ? '节点已隐藏' : '尚未添加节点'}</strong>{entries.length ? <button className="d-button" onClick={reset}>清除筛选</button> : <a className="d-button" href="#/servers">前往服务器管理</a>}</div>}
  </div>
}
