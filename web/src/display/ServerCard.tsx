import { memo } from 'react'
import type { ProbeOverview } from '../probes'
import ProbeQuality from './ProbeQuality'
import { time, uptime } from '../format'
import type { Server } from '../types'
import { fresh, network, number, percentage, ratio, size, speed, status } from './data'
import { Icon, OSIcon, Region } from './Icon'
import { dashboardServer } from './dashboard'
import { assetDate, assetPrice, defaultAssets, expiryState, trafficSize } from '../server-assets'
import { useCurrency } from './CurrencyContext'
import { convert, money, remainingCost } from './currency'
import CurrencyReference from './CurrencyReference'

export function Metric({ label, value, detail, display }: { label: string; value: number | null; detail: string; display?: string }) {
  const tone = value !== null && value >= 90 ? 'danger' : value !== null && value >= 75 ? 'warning' : 'good'
  return <div className="d-metric">
    <div><span>{label}</span><strong className={value !== null && value >= 75 ? `d-${tone}` : ''}>{display ?? percentage(value)}</strong></div>
    <span className="d-track" aria-hidden="true"><span className={`d-fill d-bg-${tone}`} style={{ width: `${Math.min(100, Math.max(0, value ?? 0))}%` }} /></span>
    <small title={detail}>{detail}</small>
  </div>
}

export const ServerCard = memo(function ServerCard({ server, unavailable, probes, probeError, probeLoading, now }: { server: Server; unavailable: boolean; probes?: ProbeOverview[]; probeError: boolean; probeLoading: boolean; now: number }) {
  const metrics = server.latest_metrics, info = server.static_info
  const state = status(server, unavailable), live = fresh(server) && !unavailable
  const up = network(metrics, 'transmit_bytes_per_sec', server.asset_settings?.network_interface), down = network(metrics, 'receive_bytes_per_sec', server.asset_settings?.network_interface)
  const asset = { ...defaultAssets, ...server.asset_settings }
  const { currency, quote } = useCurrency()
  const quota = asset.traffic_limit !== '0'
  const trafficKnown = server.traffic?.observed_from != null || server.traffic?.corrected
  const showAsset = !server.public_view && (asset.price !== null || asset.expires_at !== null)
  const expiry = expiryState(asset, now)
  const remainder = convert(remainingCost(asset, now), asset.currency, currency, quote)
  const sampleTime = server.metrics_sampled_at ? time(server.metrics_sampled_at / 1000) : '采样时间未知'
  return <a className={`d-card d-glass ${!server.online && !unavailable ? 'd-offline' : ''}`} href={dashboardServer(server.id)} aria-label={`${server.name}，${state.label}，查看详情`}>
    <div className="d-card-header"><span className={`d-dot d-bg-${state.tone}`} title={state.label} /><strong title={[server.name, asset.group_name, ...asset.tags].filter(Boolean).join(' · ')}>{server.name}</strong><OSIcon system={info.system} /><Region region={asset.region} /></div>
    <div className="d-card-body">
      <div className="d-chips"><span title={`${info.system ?? '系统尚未上报'} · ${info.arch ?? '架构未知'} · 最近采样 ${sampleTime}`}>{live && metrics.uptime_secs !== undefined ? `运行 ${uptime(metrics.uptime_secs)}` : state.label}</span>{!server.public_view && asset.price !== null && <span title={assetPrice(asset)}>{assetPrice(asset)}</span>}</div>
      <div className={`d-metrics ${!live ? 'd-historical' : ''}`}>
        <Metric label={`处理器${info.cpu_cores ? ` · ${info.cpu_cores} 核` : ''}`} value={number(metrics.cpu_percent)} detail={[metrics.load_1, metrics.load_5, metrics.load_15].map(value => number(value) === null ? '—' : value!.toFixed(2)).join(' / ')} />
        <Metric label="内存" value={ratio(metrics.memory_used, info.memory_total)} detail={`${size(metrics.memory_used)} / ${size(info.memory_total)}`} />
        <Metric label="磁盘" value={ratio(metrics.disk_used, info.disk_total)} detail={`${size(metrics.disk_used)} / ${size(info.disk_total)}`} />
        <Metric label="流量" value={quota ? server.traffic?.percent ?? null : null} display={quota ? undefined : '∞'} detail={`${trafficKnown ? trafficSize(server.traffic?.used) : '—'} / ${quota ? trafficSize(asset.traffic_limit) : '∞'}${server.traffic?.incomplete ? ' · 不完整' : ''}`} />
      </div>
      <div className={`d-data-grid ${showAsset ? '' : 'd-data-two'}`}>
        <div className="d-data" title="实时速率" aria-label="实时速率"><span className="d-good"><Icon name="up" size={12} />{live ? speed(up) : '—'}</span><span className="d-info"><Icon name="down" size={12} />{live ? speed(down) : '—'}</span></div>
        <div className="d-data" title="累计流量" aria-label="累计流量"><span><Icon name="up" size={12} />{size(network(metrics, 'transmitted_bytes', server.asset_settings?.network_interface))}</span><span><Icon name="down" size={12} />{size(network(metrics, 'received_bytes', server.asset_settings?.network_interface))}</span></div>
        {showAsset && <div className="d-data" aria-label="剩余价值与到期"><span className={expiry.tone === 'bad' ? 'd-danger' : expiry.tone === 'warm' ? 'd-warning' : ''} title={`到期 ${assetDate(asset.expires_at)}（UTC）`}><Icon name="calendar" size={12} />{expiry.label}</span><span title={`剩余价值 ${money(remainder, currency)}`}><Icon name="wallet" size={12} />{money(remainder, currency)}</span>{asset.price !== null && <CurrencyReference from={asset.currency} to={currency} compact />}</div>}
      </div>
      <ProbeQuality probes={probes} now={now} online={server.online} unavailable={probeError || unavailable} loading={probeLoading} />
      {!live && server.online && <div className="d-card-foot d-warning" title={`最近采样 ${sampleTime}`}>{unavailable ? '状态待确认' : server.metrics_stale ? '指标已过期' : '采样时间未知'}</div>}
      {!server.online && !unavailable && <div className="d-offline-overlay"><strong>{state.label}</strong><span>{server.last_seen ? `最后在线 ${time(server.last_seen)}` : '等待设备首次接入'}</span></div>}
    </div>
  </a>
})
