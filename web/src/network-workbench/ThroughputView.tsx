import { curvePoints, throughput } from './throughput'
import type { IntervalPoint } from './throughput'
const metric = (value: number | null, suffix = '') => value === null ? '未知' : `${value.toLocaleString('zh-CN', { maximumFractionDigits: 3 })}${suffix}`
const directionLabels: Record<string, string> = { forward: '客户端 → 监听端', reverse: '监听端 → 客户端', bidirectional: '客户端 ⇄ 监听端（分别采样）' }
const colors = ['var(--accent, #3972c6)', 'var(--warning, #bd7016)', 'var(--success, #24805b)', 'var(--danger, #bd3b53)']
export default function ThroughputView({ observation, role, sourceServer, clientSource }: { observation: Record<string, unknown> | null; role: string; sourceServer: number | null; clientSource?: string }) {
 const report = throughput(observation, role, sourceServer, clientSource)
 if (!report) return null
 const points = report.series.flatMap(series => series.points.filter((point): point is IntervalPoint => point !== null))
 const xmax = Math.max(1, ...points.map(point => point.end)), ymax = Math.max(1, ...points.map(point => point.bps))
 const x = (time: number) => 58 + time / xmax * 602, y = (bps: number) => 212 - bps / ymax * 178
 function segments(values: (IntervalPoint | null)[]): string[] {
  const paths: string[] = []; let current: string[] = [], previous: IntervalPoint | null = null
  for (const point of values) {
   if (point === null || previous && point.start > previous.end + 0.001) {
    if (current.length) paths.push(current.join(' ')); current = []
   }
   if (point) current.push(`${x(point.start)},${y(point.bps)}`, `${x(point.end)},${y(point.bps)}`)
   previous = point
  }
  if (current.length) paths.push(current.join(' '))
  return paths
 }
 return <section className="nw-throughput" aria-label="实际吞吐区间曲线"><h4>{report.protocol.toUpperCase()} 吞吐区间</h4>
  <p>配置方向：{directionLabels[report.direction] ?? '未知'}；本份报告记录当前执行端的观测。发送端与接收端结果分别保留。</p>
  {report.error ? <p role="status">{report.error}</p> : <><svg viewBox="0 0 700 252" role="img" aria-label="随执行时间变化的吞吐速率曲线，缺失区间留空">
   <line x1="58" y1="212" x2="660" y2="212" stroke="currentColor" /><line x1="58" y1="34" x2="58" y2="212" stroke="currentColor" />
   {[0, 0.5, 1].map(value => <g key={value}><line x1="58" y1={y(value * ymax)} x2="660" y2={y(value * ymax)} stroke="currentColor" opacity=".12" /><text x="52" y={y(value * ymax) + 4} textAnchor="end">{metric(value * ymax / 1_000_000)}</text></g>)}
   <text x="58" y="21">速率（Mbit/s）</text><text x="58" y="234">0</text><text x="660" y="234" textAnchor="end">{metric(xmax)} 秒</text>
   {report.series.map((series, index) => <g key={series.key} stroke={colors[index % colors.length]} fill="none">{segments(curvePoints(series.points)).map((path, part) => <polyline key={part} points={path} strokeWidth="2" />)}</g>)}
  </svg><ul>{report.series.map((series, index) => <li key={series.key}><span className="nw-curve-key" style={{ background: colors[index % colors.length] }} />{series.from} → {series.to} · {series.sender === true ? '本端发送测量' : series.sender === false ? '本端接收测量' : '测量角色未知'}</li>)}</ul>
  <table><caption>末个有效区间的原始指标（完整区间见下方报告）</caption><thead><tr><th>发送方 → 接收方</th><th>速率</th><th>传输量</th>{report.protocol === 'tcp' ? <th>重传</th> : <><th>抖动</th><th>丢包 / 总包</th><th>丢包比例</th></>}</tr></thead><tbody>{report.series.map(series => {
   const last = series.points.filter((point): point is IntervalPoint => point !== null).at(-1)!
   return <tr key={series.key}><td>{series.from} → {series.to}<small> {metric(last.start)}–{metric(last.end)}秒</small></td><td>{metric(last.bps / 1_000_000, ' Mbit/s')}</td><td>{metric(last.bytes, '字节')}</td>{report.protocol === 'tcp' ? <td>{metric(last.retransmits)}</td> : <><td>{metric(last.jitterMs, ' ms')}</td><td>{metric(last.lostPackets)} / {metric(last.packets)}</td><td>{metric(last.lostPercent, '%')}</td></>}</tr>
  })}</tbody></table></>}
  <p>读取{report.inspectedCount}个实际区间；曲线每方向最多512个时长加权区间，缺失或省略样本留空。{report.clipped && '超过3600个区间的部分仅在原始报告中保留。'}原始 TCP/UDP 字段完整保留，不将未知指标转换为零。</p>
 </section>
}
