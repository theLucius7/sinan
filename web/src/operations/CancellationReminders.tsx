import { useEffect, useState } from 'react'
import { api, errorMessage } from '../api'
import type { ActionRunner } from './types'
import { time } from './types'

type Reminder = { record_id: string; server_id: number; server_name: string; valid_until: number | null; reference: string; enabled: boolean; lead_secs: number; notified_at: number | null; last_error: string | null }
type Draft = { enabled: boolean; lead_secs: number }
const defaultLead = 604800
const leadOptions = [[3600, '提前 1 小时'], [21600, '提前 6 小时'], [86400, '提前 1 天'], [259200, '提前 3 天'], [defaultLead, '提前 7 天'], [1209600, '提前 14 天'], [2592000, '提前 30 天']] as const

export default function CancellationReminders({ run, version }: { run: ActionRunner; version: number }) {
  const [records, setRecords] = useState<Reminder[] | null>(null)
  const [drafts, setDrafts] = useState<Record<string, Draft>>({})
  const [errors, setErrors] = useState<Record<string, string>>({})
  const [messages, setMessages] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<Record<string, boolean>>({})
  const [loadError, setLoadError] = useState('')

  const refresh = async (savedId?: string) => {
    try {
      const next = await api<Reminder[]>('/api/operations/cancellation-reminders')
      setRecords(next)
      setDrafts(previous => Object.fromEntries(next.map(record => [record.record_id, record.record_id !== savedId && previous[record.record_id] ? previous[record.record_id] : { enabled: record.enabled, lead_secs: record.lead_secs || defaultLead }])))
      setLoadError('')
    } catch (value) {
      setLoadError(errorMessage(value))
      throw value
    }
  }
  useEffect(() => { run(() => refresh()) }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
  const change = (id: string, update: Partial<Draft>) => {
    setDrafts(previous => ({ ...previous, [id]: { ...previous[id], ...update } }))
    setMessages(previous => ({ ...previous, [id]: '' }))
  }
  const save = (record: Reminder, draft: Draft) => run(async () => {
    const id = record.record_id
    setSaving(previous => ({ ...previous, [id]: true }))
    setErrors(previous => ({ ...previous, [id]: '' }))
    setMessages(previous => ({ ...previous, [id]: '' }))
    let submitted = false
    try {
      if (draft.enabled && record.valid_until === null) throw new Error('此退订记录没有计划生效日期，请先在服务器费用台账补充日期再启用提醒。')
      if (!Number.isInteger(draft.lead_secs) || draft.lead_secs < 3600 || draft.lead_secs > 2592000) throw new Error('提前提醒时间须在 1 小时至 30 天之间。')
      await api('/api/operations/cancellation-reminders', 'POST', { record_id: id, enabled: draft.enabled, lead_secs: draft.lead_secs })
      submitted = true
      await refresh(id)
      setMessages(previous => ({ ...previous, [id]: '提醒设置已保存。' }))
    } catch (value) {
      setErrors(previous => ({ ...previous, [id]: `${submitted ? '设置已提交，读取最新状态失败：' : ''}${errorMessage(value)}` }))
      throw value
    } finally {
      setSaving(previous => ({ ...previous, [id]: false }))
    }
  })

  return <section className="operations-card">
    <h3>计划退订日期提醒</h3>
    <p>每条退订记录默认关闭，只有明确启用后才记录站内提醒事件。同一退订记录已有提醒事件后不再重建；渠道实际送达状态在故障事件详情查看。提醒不执行退订、停止设备代理或付款。</p>
    <button className="ui-button" type="button" onClick={() => run(() => refresh())}>读取提醒状态</button>
    {loadError && <p className="operations-error" role="alert">{loadError}{records && '；下方保留上次读取结果和未保存的编辑。'}</p>}
    {records === null && !loadError && <p role="status">正在读取退订记录。</p>}
    {records?.length === 0 && <p>暂无可读取的退订记录；先在服务器费用台账登记退订计划及生效日期。</p>}
    <div className="operations-table-wrap"><table><thead><tr><th>服务器／退订参考</th><th>生效日期与提醒结果</th><th>提醒设置</th><th>保存结果</th></tr></thead><tbody>{records?.map(record => {
      const draft = drafts[record.record_id] ?? { enabled: record.enabled, lead_secs: record.lead_secs || defaultLead }
      const changed = draft.enabled !== record.enabled || draft.lead_secs !== (record.lead_secs || defaultLead)
      return <tr key={record.record_id}>
        <td>{record.server_name}<small>服务器编号：{record.server_id}</small><small>退订参考：{record.reference || '未填写'}</small><small>记录编号：{record.record_id}</small></td>
        <td>{record.valid_until === null ? '缺少生效日期，不能启用提醒' : `计划退订生效 ${time(record.valid_until)}`}<small>{record.notified_at === null ? '尚未记录提醒事件' : `提醒事件已记录 ${time(record.notified_at)}，不再重建`}</small>{record.last_error && <small>上次记录提醒事件错误：{record.last_error}</small>}</td>
        <td><label><input type="checkbox" checked={draft.enabled} disabled={Boolean(saving[record.record_id]) || (record.valid_until === null && !draft.enabled)} onChange={event => change(record.record_id, { enabled: event.target.checked })} />明确启用此记录提醒</label><label>提前多久提醒<select value={draft.lead_secs} disabled={Boolean(saving[record.record_id])} onChange={event => change(record.record_id, { lead_secs: Number(event.target.value) })}>{!leadOptions.some(([seconds]) => seconds === draft.lead_secs) && <option value={draft.lead_secs}>{draft.lead_secs} 秒（已有设置）</option>}{leadOptions.map(([seconds, name]) => <option key={seconds} value={seconds}>{name}</option>)}</select></label></td>
        <td><button className="ui-button" type="button" disabled={!changed || Boolean(saving[record.record_id]) || (draft.enabled && record.valid_until === null)} onClick={() => save(record, { ...draft })}>{saving[record.record_id] ? '正在保存' : '保存此记录设置'}</button>{errors[record.record_id] && <p className="operations-error" role="alert">{errors[record.record_id]}</p>}{messages[record.record_id] && <p role="status">{messages[record.record_id]}</p>}{changed && <small>此条记录有未保存的修改。</small>}</td>
      </tr>
    })}</tbody></table></div>
  </section>
}
