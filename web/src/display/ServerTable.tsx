import type { ProbeOverview } from '../probes'
import type { Server } from '../types'
import { uptime } from '../format'
import { AssetChips } from './AssetInfo'
import { dashboardServer } from './dashboard'
import { fresh, network, number, ratio, size, speed, status } from './data'
import { OSIcon } from './Icon'
import ProbeQuality from './ProbeQuality'
import { Metric } from './ServerCard'

export default function ServerTable({ servers, unavailable, byServer, probesKnown, probeError, probeLoading, now }: {
  servers: Server[]; unavailable: boolean; byServer: Map<number, ProbeOverview[]>; probesKnown: boolean;
  probeError: boolean; probeLoading: boolean; now: number;
}) {
  return <section className="d-fleet d-glass" aria-label="服务器列表">
    <div className="d-fleet-scroll" tabIndex={0} role="region" aria-label="服务器表格，可横向滚动">
      <table><caption className="d-sr-only">服务器资源与网络状态。数据不可用时保留历史值，实时速率显示为空缺。</caption>
        <thead><tr><th scope="col">服务器</th><th scope="col">状态</th><th scope="col">处理器</th><th scope="col">内存</th><th scope="col">磁盘</th><th scope="col">实时上下行</th><th scope="col">网络质量</th><th scope="col">运行与采样</th></tr></thead>
        <tbody>{servers.map(server => {
          const metrics = server.latest_metrics, info = server.static_info
          const live = fresh(server) && !unavailable, state = status(server, unavailable)
          const historical = !live ? '（最近上报）' : ''
          return <tr key={server.id} data-server-id={server.id} className={!live ? 'd-historical' : ''}>
            <th scope="row"><a className="d-fleet-name" href={dashboardServer(server.id)}><OSIcon system={info.system} /><strong>{server.name}</strong></a><small>{info.system || '系统尚未上报'}{info.cpu_cores ? ` · ${info.cpu_cores} 核` : ''}</small><AssetChips server={server} /></th>
            <td><span className={`d-status d-${state.tone}`}>{state.label}</span>{!live && <small>{unavailable ? '等待刷新' : server.online ? server.metrics_stale ? '指标已过期' : '采样时间未知' : '历史数据'}</small>}</td>
            <td><Metric label={`处理器${historical}`} value={number(metrics.cpu_percent)} detail={`负载 ${number(metrics.load_1) === null ? '—' : metrics.load_1!.toFixed(2)}`} /></td>
            <td><Metric label={`内存${historical}`} value={ratio(metrics.memory_used, info.memory_total)} detail={`${size(metrics.memory_used)} / ${size(info.memory_total)}`} /></td>
            <td><Metric label={`磁盘${historical}`} value={ratio(metrics.disk_used, info.disk_total)} detail={`${size(metrics.disk_used)} / ${size(info.disk_total)}`} /></td>
            <td><span className="d-good">↑ {live ? speed(network(metrics, 'transmit_bytes_per_sec', server.asset_settings?.network_interface)) : '—'}</span><span className="d-info">↓ {live ? speed(network(metrics, 'receive_bytes_per_sec', server.asset_settings?.network_interface)) : '—'}</span></td>
            <td><ProbeQuality probes={probesKnown ? byServer.get(server.id) ?? [] : undefined} now={now} online={server.online} unavailable={probeError || unavailable} loading={probeLoading} compact /></td>
            <td><span>{number(metrics.uptime_secs) === null ? '—' : uptime(metrics.uptime_secs)}</span><small>{server.metrics_sampled_at ? new Date(server.metrics_sampled_at).toLocaleTimeString('zh-CN', { hour12: false }) : '无采样时间'}</small><a className="d-fleet-detail" href={dashboardServer(server.id)} aria-label={`查看 ${server.name} 详情`}>查看详情 →</a></td>
          </tr>
        })}</tbody>
      </table>
    </div>
  </section>
}
