import { expect, test } from 'bun:test'
import { freshInspection, freshObservation, InspectionRequests, type Inspection } from '../src/operations/FleetReconciliation'
const receipt: Inspection = { id: 'new-read', server_id: 7, reconciliation_of: 'original', status: 'succeeded', result: { succeeded: true, completed_at: 1000 } }
test('manual conclusion accepts only the exact fresh successful read-only receipt', () => {
  expect(freshInspection(receipt, 'new-read', 'original', 7, 1050)).toBe(true)
  for (const value of [null, { ...receipt, id: 'prior-read' }, { ...receipt, server_id: 8 }, { ...receipt, reconciliation_of: 'other' },
    { ...receipt, status: 'unknown' }, { ...receipt, result: null },
    { ...receipt, result: { succeeded: false, completed_at: 1000 } },
    { ...receipt, result: { succeeded: true, completed_at: Number.NaN } }]) {
    expect(freshInspection(value, 'new-read', 'original', 7, 1050)).toBe(false)
  }
  expect(freshInspection(receipt, null, 'original', 7, 1050)).toBe(false)
  expect(freshInspection(receipt, 'new-read', 'original', 7, 999)).toBe(false)
  expect(freshInspection(receipt, 'new-read', 'original', 7, 1301)).toBe(false)
})

test('new inspection rejects late prior POST and GET and an unmounted request cannot refill or dispatch', async () => {
  const requests = new InspectionRequests()
  const first = requests.begin()!
  expect(requests.created(first, 'prior-read')).toBe(true)
  const prior = requests.read()!
  const next = requests.begin()!
  expect(requests.read()).toBeNull()
  expect(requests.created(first, 'prior-read')).toBe(false)
  expect(requests.accepts(prior, { ...receipt, id: 'prior-read' })).toBe(false)
  expect(requests.created(next, 'new-read')).toBe(true)
  const current = requests.read()!
  expect(requests.accepts(current, { ...receipt, id: 'prior-read' })).toBe(false)
  expect(requests.accepts(current, receipt)).toBe(true)
  let finish!: (value: Inspection) => void
  const delayed = new Promise<Inspection>(resolve => { finish = resolve })
  const result = delayed.then(value => requests.accepts(current, value))
  requests.dispose()
  finish(receipt)
  expect(await result).toBe(false)
  expect(requests.created(next, 'new-read')).toBe(false)
  expect(requests.current(current)).toBe(false)
  expect(requests.begin()).toBeNull()
  expect(requests.read()).toBeNull()
})

test('human observation must be finite and within the ten minute current window', () => {
  const now = 1800000000
  const date = (seconds: number) => new Date(seconds * 1000).toISOString()
  expect(freshObservation(date(now), now)).toBe(true)
  expect(freshObservation(date(now - 600), now)).toBe(true)
  for (const value of ['', 'invalid', date(now + 1), date(now - 601)]) expect(freshObservation(value, now)).toBe(false)
})
