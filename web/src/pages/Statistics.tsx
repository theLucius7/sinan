import { useState } from 'react'
import { ErrorNotice, Loading, PageHeader, Refresh, Stat } from '../components'
import { bytes, time } from '../format'
import { useResource } from '../hooks'
import Ranking from '../statistics/Ranking'
import TrafficChart from '../statistics/TrafficChart'
import type { ProxyStatistics, ServerStatistics } from '../statistics/data'
import '../statistics/statistics.css'

export default function Statistics() {
  const [days, setDays] = useState(7)
  const servers = useResource<ServerStatistics>(`/api/statistics?days=${days}`, 30_000)
  const proxy = useResource<ProxyStatistics>(`/api/plugins/sing-box/statistics?days=${days}`, 30_000)
  const data = servers.data, business = proxy.data
  return <div className="statistics-page">
    <PageHeader eyebrow="运行概览" title="统计仪表盘" description="查看服务器状态、网卡流量与代理业务统计。">
      <div className="statistics-range ui-tab-list" role="group" aria-label="统计时间范围">{[7, 30].map(value => <button key={value} type="button" aria-pressed={days === value} onClick={() => setDays(value)}>近 {value} 天</button>)}</div>
      <Refresh onClick={() => { servers.reload(); proxy.reload() }} />
    </PageHeader>
    <ErrorNotice message={servers.error} retry={servers.reload} />
    {servers.loading && !data ? <Loading /> : data && <>
      <div className="statistics-status-line"><span>当前服务器 · 含 {data.servers.hidden} 台展示隐藏节点</span><span>{servers.error ? '显示上次成功读取的数据' : '每 30 秒更新'} · {time(data.generated_at)}</span></div>
      <div className="stats-grid stats-four">
        <Stat label="服务器总数" value={data.servers.total} note="全部未删除服务器" icon="server" />
        <Stat label="在线服务器" value={data.servers.online} note="最近 60 秒有通信" icon="activity" />
        <Stat label="离线服务器" value={data.servers.offline} note="已接入，等待重新上线" icon="server" />
        <Stat label="待接入服务器" value={data.servers.pending} note="等待安装并注册 Agent" icon="plus" />
      </div>
      <div className="statistics-section-heading"><div><h2>服务器网卡流量</h2><p>近 {days} 个 UTC 自然日，覆盖 {data.traffic.sampled_servers} / {data.servers.total} 台服务器。</p></div><a href="#/servers" className="text-button">管理服务器</a></div>
      <div className="stats-grid statistics-traffic-totals">
        <Stat label="网卡累计上传" value={bytes(data.traffic.uploaded)} note="从服务器发出的观测流量" icon="up" />
        <Stat label="网卡累计下载" value={bytes(data.traffic.downloaded)} note="服务器收到的观测流量" icon="down" />
        <Stat label="网卡双向合计" value={bytes(data.traffic.total)} note={data.traffic.incomplete ? '存在采样缺失或计数重置' : '累计已收到的网卡观测'} icon="activity" />
      </div>
      <div className="statistics-grid"><TrafficChart title="网卡流量趋势" points={data.points} /><Ranking title="服务器流量排行" rows={data.by_server} link={row => `#/servers/${row.id}`} /></div>
      <p className="statistics-scope">仅统计当前未删除服务器（含展示隐藏）。按当前选择的统计网卡汇总；未选择时包含所有上报网卡。这里使用原始观测，不含账单周期流量矫正。未上报、网卡变化和重启可能使数据不完整。{data.traffic.last_sample_at ? `最新采样：${time(data.traffic.last_sample_at / 1000)}。` : ''}</p>
    </>}
    <div className="statistics-section-heading"><div><h2>代理业务统计</h2><p>独立汇总代理用户账本，不能与服务器网卡流量相加。</p></div><a href="#/plugins/sing-box/nodes" className="text-button">管理代理节点</a></div>
    <ErrorNotice message={proxy.error} retry={proxy.reload} />
    {proxy.loading && !business ? <Loading /> : business && <>
      <div className="stats-grid stats-four">
        <Stat label="代理节点" value={business.nodes} note="未删除服务器上的节点" icon="nodes" />
        <Stat label="代理用户" value={business.users} note="当前未删除用户" icon="users" />
        <Stat label={`近 ${days} 天代理流量`} value={bytes(business.traffic.total)} note={`${business.traffic.recorded_users} 位用户有账本记录`} icon="activity" />
        <Stat label="有记录的代理节点" value={business.traffic.recorded_nodes} note="统计窗口内，包含历史节点" icon="nodes" />
      </div>
      <TrafficChart title="代理流量趋势" points={business.points} />
      <div className="statistics-grid statistics-rankings"><Ranking title="代理用户流量排行" rows={business.by_user} /><Ranking title="代理节点流量排行" rows={business.by_node} /></div>
      <p className="statistics-scope">上传和下载以代理用户为视角；按计量批次结束时间归入 UTC 日期，不按跨日时长拆分。保留已删除用户、节点的历史记录；离线补报会更新历史，暂无记录不代表实际零流量。{business.traffic.last_record_at ? `最新计量：${time(business.traffic.last_record_at)}。` : ''}{proxy.error ? ' 当前显示上次成功读取的数据。' : ''}</p>
    </>}
  </div>
}
