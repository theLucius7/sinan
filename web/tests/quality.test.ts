import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { qualityValue } from '../src/quality'
import type { QualityField } from '../src/types'

test('legacy UI field types agree with every registered backend field', () => {
  const source = readFileSync(new URL('../../crates/panel-host/src/ip_quality/fields.rs', import.meta.url), 'utf8')
  const kindNames: Record<string, NonNullable<QualityField['kind']>> = { Text: 'text', CountryCode: 'country_code', Boolean: 'boolean', Score: 'score', Asn: 'asn', Latitude: 'latitude', Longitude: 'longitude' }
  let checked = 0
  for (const database of source.matchAll(/"([a-z0-9-]+)" => &\[([\s\S]*?)\n        \],/g)) {
    for (const field of database[2].matchAll(/\(\s*"[^"]+"\s*,\s*"([^"]+)"\s*,\s*QualityFieldKind::(\w+)\s*,?\s*\)/g)) {
      const kind = kindNames[field[2]]
      expect(kind).toBeDefined()
      for (const value of [false, 0, -1, 91, 181, 4294967296, 'fixture', 'ZZ', '0', '0 (Very Low)']) {
        const legacy = { label: field[1], value }
        expect(qualityValue(legacy, database[1])).toBe(qualityValue({ ...legacy, kind }, database[1]))
      }
      checked += 1
    }
  }
  expect(checked).toBe(80)
})

test('legacy known labels cannot turn wrong scalar types into successful facts', () => {
  expect(qualityValue({ label: '代理', value: 0 }, 'ipqualityscore')).toBeUndefined()
  expect(qualityValue({ label: '欺诈评分（上游原值）', value: false }, 'ipqualityscore')).toBeUndefined()
  expect(qualityValue({ label: '代理', value: false }, 'ipqualityscore')).toBe('否')
  expect(qualityValue({ label: '欺诈评分（上游原值）', value: 0 }, 'ipqualityscore')).toBe('0')
  expect(qualityValue({ label: '欺诈评分（上游原值）', value: '0', kind: null }, 'ipqualityscore')).toBe('0')
  expect(qualityValue({ label: '旧自定义', value: false }, 'ipqualityscore')).toBe('否')
  expect(qualityValue({ label: '代理', value: 0 }, 'unregistered')).toBe('0')
})

test('unconfirmed values and placeholder ratings remain unknown', () => {
  for (const value of [null, {}, [], '', ' ', 'unknown', false, '0 ()', '0 ( )', '0 (null)', '0 (unknown)', 'NaN', 'Infinity', -1]) {
    expect(qualityValue({ label: 'score', value, kind: 'score' })).toBeUndefined()
  }
  for (const value of [0, '0', '0.0047 (Very Low)']) {
    expect(qualityValue({ label: 'score', value, kind: 'score' })).toBe(String(value))
  }
})

test('legacy labels retain their registered ranges without inventing custom semantics', () => {
  expect(qualityValue({ label: 'ASN', value: 0 }, 'maxmind')).toBeUndefined()
  expect(qualityValue({ label: '纬度', value: 91 }, 'maxmind')).toBeUndefined()
  expect(qualityValue({ label: '国家代码', value: 'unknown' }, 'maxmind')).toBeUndefined()
  expect(qualityValue({ label: 'ASN', value: '64500' }, 'maxmind')).toBe('64500')
  expect(qualityValue({ label: '纬度', value: 0 }, 'maxmind')).toBe('0')
  expect(qualityValue({ label: '国家代码', value: 'ZZ' }, 'maxmind')).toBe('ZZ')
  expect(qualityValue({ label: 'constructor', value: 0 }, 'ipqualityscore')).toBe('0')
})


test('official confidence remains a documented integer percent with no boolean or text default', () => {
  for (const kind of [undefined, 'score'] as const) {
    for (const value of [null, false, '0', -1, 101, 0.5]) {
      expect(qualityValue({ label: '滥用置信度（0–100 原值）', value, kind }, 'abuseipdb-v2')).toBeUndefined()
    }
    expect(qualityValue({ label: '滥用置信度（0–100 原值）', value: 0, kind }, 'abuseipdb-v2')).toBe('0')
    expect(qualityValue({ label: '滥用置信度（0–100 原值）', value: 100, kind }, 'abuseipdb-v2')).toBe('100')
  }
  expect(qualityValue({ label: 'Tor', value: false }, 'abuseipdb-v2')).toBe('否')
  expect(qualityValue({ label: 'Tor', value: null }, 'abuseipdb-v2')).toBeUndefined()
  expect(qualityValue({ label: 'Tor', value: 'false' }, 'abuseipdb-v2')).toBeUndefined()
})
