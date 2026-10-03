import { expect, test } from 'bun:test'
import { accountWrite, billUsable, message, status } from '../src/plugins/alicloud/types'
import type { Account } from '../src/plugins/alicloud/types'

test('cloud edits do not copy cached billing or write-only credentials back into requests', () => {
  const input = { name: ' 云账号 ', site: 'china' as const, enabled: true, auto_enabled: false, limit_gb: 100, bill: { sensitive: 'cached' } }
  expect(accountWrite(input, ' ', '', 2)).toEqual({ name: '云账号', site: 'china', enabled: true, auto_enabled: false, limit_gb: 100, revision: 2 })
  expect(accountWrite(input, ' TEST_ONLY_ID ', ' TEST_ONLY_SECRET ').access_key_secret).toBeUndefined()
  expect(accountWrite(input, ' TEST_ONLY_ID ', ' TEST_ONLY_SECRET ', undefined, '', true)).toMatchObject({legacy_credentials: true, access_key_id: 'TEST_ONLY_ID', access_key_secret: 'TEST_ONLY_SECRET'})
  expect(accountWrite(input, ' TEST_ONLY_ID ', ' TEST_ONLY_SECRET ', 3, 'TEST_ONLY_CREDENTIAL_REF', true)).toEqual({ name: '云账号', site: 'china', enabled: true, auto_enabled: false, limit_gb: 100, revision: 3, credential_id: 'TEST_ONLY_CREDENTIAL_REF' })
  expect(message('TEST_ONLY_SECRET')).toBe('云接口暂时不可用')
  for (const code of ['constructor', '__proto__', 'toString']) { expect(status(code)).toBe('状态未知'); expect(message(code)).toBe('云接口暂时不可用') }
})
test('billing status rejects previous month, stale, future and incomplete evidence', () => {
  const now = Date.parse('2026-10-01T00:00:00Z') / 1000
  const account = { enabled: true, error_code: null, bill: { month: '2026-10', queried_at: now, usage_micro_gb: 100000000, rows: [] } } as unknown as Account
  expect(billUsable(account, now)).toBeTrue()
  for (const changed of [{ month: '2026-09' }, { queried_at: now - 901 }, { queried_at: now + 1 }, { usage_micro_gb: null }]) expect(billUsable({ ...account, bill: { ...account.bill!, ...changed } }, now)).toBeFalse()
  expect(billUsable({ ...account, error_code: 'network_error' }, now)).toBeFalse()
  expect(billUsable({ ...account, enabled: false }, now)).toBeFalse()
})
