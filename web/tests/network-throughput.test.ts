import { expect, test } from 'bun:test'
import { curvePoints, throughput } from '../src/network-workbench/throughput'
import type { IntervalPoint } from '../src/network-workbench/throughput'
const sample = (start: number, end: number, bps: number, sender = true) => ({ start, end, bits_per_second: bps, sender, bytes: bps * (end - start) / 8 })
function report(intervals: unknown[], protocol = 'tcp', direction = 'forward') {
 return { parameters: { kind: 'throughput', protocol, direction, receiver_server: 2, client_mode: 'managed' }, data: { tool_output: { intervals } } }
}

test('actual forward/reverse/bidirectional interval sender markers label both endpoints', () => {
 const both = throughput(report([{ sum: sample(0, 1, 8_000_000), sum_bidir_reverse: sample(0, 1, 6_000_000, false) }], 'tcp', 'bidirectional'), 'source:1', 1)!
 expect(both.series.map(series => [series.from, series.to, series.sender])).toEqual([['服务器 1', '服务器 2', true], ['服务器 2', '服务器 1', false]])
 expect(both.series[0].points[0]?.bytes).toBe(1_000_000)
 const listener = throughput(report([{ sum: sample(0, 1, 8_000_000, false) }]), 'listener:2', 2, '服务器 1')!
 expect(listener.series[0].from).toBe('服务器 1'); expect(listener.series[0].to).toBe('服务器 2')
 const reverse = throughput(report([{ sum: sample(0, 1, 8_000_000, false) }], 'tcp', 'reverse'), 'source:1', 1)!
 expect(reverse.series[0].from).toBe('服务器 2'); expect(reverse.series[0].to).toBe('服务器 1')
})

test('measured UDP zero survives while missing loss/retransmits and sender remain unknown', () => {
 const value = throughput(report([{ sum: { ...sample(0, 1, 0), sender: undefined, jitter_ms: 0, lost_packets: 0, packets: 1 } }], 'udp'), 'source:1', 1)!
 expect(value.series[0].sender).toBeNull(); expect(value.series[0].from).toBe('发送方未知')
 const point = value.series[0].points[0]!
 expect(point.bps).toBe(0); expect(point.jitterMs).toBe(0); expect(point.lostPackets).toBe(0)
 expect(point.lostPercent).toBeNull(); expect(point.retransmits).toBeNull()
})

test('invalid, omitted, missing and nonfinite samples create gaps rather than false zero', () => {
 const value = throughput(report([{ sum: sample(0, 1, 8) }, {}, { sum: { ...sample(2, 3, 8), omitted: true } }, { sum: sample(3, 4, NaN) }, { sum: sample(4, 5, -1) }, { sum: sample(5, 6, 0) }]), 'source:1', 1)!
 expect(value.series[0].points.map(point => point?.bps ?? null)).toEqual([8, null, null, null, null, 0])
 expect(throughput(report([]), 'source:1', 1)?.error).toContain('未知')
})

test('input and chart bounds are explicit; downsampling weights actual interval duration', () => {
 const value = throughput(report(Array.from({ length: 4000 }, (_, i) => ({ sum: sample(i, i + 1, 8) }))), 'source:1', 1)!
 expect(value.clipped).toBe(true); expect(value.intervalCount).toBe(4000); expect(value.series[0].points).toHaveLength(3600)
 expect(curvePoints(value.series[0].points)).toHaveLength(512)
 const points: IntervalPoint[] = [{ start: 0, end: 1, bps: 10, bytes: null, retransmits: null, jitterMs: null, lostPackets: null, packets: null, lostPercent: null }, { start: 1, end: 4, bps: 30, bytes: null, retransmits: null, jitterMs: null, lostPackets: null, packets: null, lostPercent: null }]
 expect(curvePoints(points, 1)[0]?.bps).toBe(25)
 expect(curvePoints([points[0], null], 1)).toEqual([null])
})
