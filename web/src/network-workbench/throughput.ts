export type IntervalPoint = {
 start: number; end: number; bps: number; bytes: number | null; retransmits: number | null
 jitterMs: number | null; lostPackets: number | null; packets: number | null; lostPercent: number | null
}
export type ThroughputSeries = { key: string; sender: boolean | null; from: string; to: string; points: (IntervalPoint | null)[] }
export type Throughput = { protocol: 'tcp' | 'udp'; direction: string; series: ThroughputSeries[]; intervalCount: number; inspectedCount: number; clipped: boolean; error: string | null }
const object = (value: unknown): Record<string, unknown> | null => value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
const nonnegative = (value: unknown): number | null => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
const sumKeys = ['sum', 'sum_bidir_reverse', 'sum_sent', 'sum_received'] as const
const INPUT_LIMIT = 3600
export const CURVE_POINT_LIMIT = 512

export function throughput(observation: Record<string, unknown> | null, role: string, sourceServer: number | null, clientSource?: string): Throughput | null {
 const parameters = object(observation?.parameters)
 if (parameters?.kind !== 'throughput') return null
 const data = object(observation?.data), output = object(data?.tool_output)
 const protocol = parameters.protocol === 'udp' ? 'udp' : parameters.protocol === 'tcp' ? 'tcp' : null
 if (!protocol) return null
 const direction = typeof parameters.direction === 'string' ? parameters.direction : 'unknown'
 const intervals = Array.isArray(output?.intervals) ? output.intervals : []
 const result: Throughput = { protocol, direction, series: [], intervalCount: intervals.length, inspectedCount: Math.min(INPUT_LIMIT, intervals.length), clipped: intervals.length > INPUT_LIMIT, error: null }
 const receiver = typeof parameters.receiver_server === 'number' && parameters.receiver_server > 0 ? `服务器 ${parameters.receiver_server}` : '接收端未标明'
 const listener = role.startsWith('listener:')
 const client = parameters.client_mode === 'local' ? '本地客户端' : clientSource ?? (!listener && sourceServer ? `服务器 ${sourceServer}` : '客户端未标明')
 const observer = listener ? receiver : client
 const peer = listener ? client : receiver
 const byKey = new Map<string, ThroughputSeries>()
 for (let index = 0; index < result.inspectedCount; index++) {
  const interval = object(intervals[index])
  for (const series of byKey.values()) series.points.push(null)
  for (const key of sumKeys) {
   const sum = object(interval?.[key])
   if (!sum) continue
   const sender = typeof sum.sender === 'boolean' ? sum.sender : null
   const seriesKey = `${key}:${String(sender)}`
   let series = byKey.get(seriesKey)
   if (!series) {
    series = { key: seriesKey, sender, from: sender === true ? observer : sender === false ? peer : '发送方未知', to: sender === true ? peer : sender === false ? observer : '接收方未知', points: Array.from({ length: index + 1 }, () => null) }
    byKey.set(seriesKey, series)
   }
   const start = nonnegative(sum.start), end = nonnegative(sum.end), bps = nonnegative(sum.bits_per_second)
   if (start === null || end === null || bps === null || end <= start || sum.omitted === true) continue
   series.points[index] = { start, end, bps, bytes: nonnegative(sum.bytes), retransmits: nonnegative(sum.retransmits), jitterMs: nonnegative(sum.jitter_ms), lostPackets: nonnegative(sum.lost_packets), packets: nonnegative(sum.packets), lostPercent: nonnegative(sum.lost_percent) }
  }
 }
 result.series = [...byKey.values()].filter(series => series.points.some(point => point !== null))
 if (result.series.length === 0) result.error = '工具未提供有效区间速率；数据保持未知。'
 return result
}

// Bucket averages use actual interval duration. Any missing/omitted sample leaves a visible gap.
export function curvePoints(points: (IntervalPoint | null)[], maximum = CURVE_POINT_LIMIT): (IntervalPoint | null)[] {
 const bound = Math.max(1, Math.min(CURVE_POINT_LIMIT, Math.floor(maximum)))
 if (points.length <= bound) return points
 const result: (IntervalPoint | null)[] = []
 for (let bucket = 0; bucket < bound; bucket++) {
  const first = Math.floor(bucket * points.length / bound), last = Math.floor((bucket + 1) * points.length / bound)
  const values = points.slice(first, last)
  if (values.some(value => value === null)) { result.push(null); continue }
  const valid = values as IntervalPoint[]
  let duration = 0, average = 0
  for (const value of valid) duration += value.end - value.start
  for (const value of valid) average += value.bps * ((value.end - value.start) / duration)
  result.push({ ...valid[valid.length - 1], start: valid[0].start, end: valid[valid.length - 1].end, bps: average })
 }
 return result
}
