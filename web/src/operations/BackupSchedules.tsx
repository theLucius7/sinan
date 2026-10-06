import { useEffect, useState } from 'react'
import { api } from '../api'
import type { ActionRunner } from './types'
import { time } from './types'

type Schedule = { id: string; name: string; paused: boolean; next_run_at: number; last_started_at: number | null; last_finished_at: number | null; last_error: string | null; claimed_id: string | null }
export default function BackupSchedules({ run, version }: { run: ActionRunner; version: number }) {
  const [schedules, setSchedules] = useState<Schedule[]>([])
  const [name, setName] = useState('定时完整备份')
  const [next, setNext] = useState('')
  const [interval, setInterval] = useState(86400)
  const [recipient, setRecipient] = useState('')
  const [count, setCount] = useState(7)
  const [days, setDays] = useState(30)
  const [storageConfigured, setStorageConfigured] = useState(false)
  const [imagesConfigured, setImagesConfigured] = useState(false)
  const refresh = async () => { const value = await api<{ schedules: Schedule[]; storage_configured: boolean; immutable_images_configured: boolean }>('/api/operations/backup-schedules'); setSchedules(value.schedules); setStorageConfigured(value.storage_configured); setImagesConfigured(value.immutable_images_configured) }
  useEffect(() => { run(refresh) }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
  return <section className="operations-card"><h3>定时完整备份执行器</h3><p>由面板本机执行数据库一致性导出和签名制品快照，然后用独立保管方的 age 公钥加密；只有工具实际完成才登记备份结果。</p><p>{storageConfigured ? '已指定备份存储目标；是否为异地挂载由运维配置决定。' : '当前使用面板私有本机目录，请配置独立存储目标后用于灾难恢复。'}{!imagesConfigured && ' 尚未配置固定恢复镜像身份，执行将记录失败；请先完成恢复环境配置。'}</p><div className="operations-fields"><label>计划名称<input value={name} onChange={event => setName(event.target.value)} /></label><label>首次执行<input type="datetime-local" value={next} onChange={event => setNext(event.target.value)} /></label><label>周期（秒）<input type="number" min={3600} value={interval} onChange={event => setInterval(Number(event.target.value))} /></label><label>加密公钥<input value={recipient} placeholder="独立保管方的 age1 公钥" onChange={event => setRecipient(event.target.value)} /></label><label>至少保留份数<input type="number" min={1} max={1000} value={count} onChange={event => setCount(Number(event.target.value))} /></label><label>至少保留天数<input type="number" min={1} max={3650} value={days} onChange={event => setDays(Number(event.target.value))} /></label></div><p>仅在份数和日期同时超过策略、且没有恢复依赖时，清理本执行器创建的加密归档。解密主密钥不会进入备份。</p><button className="ui-button" disabled={!next || !recipient || !imagesConfigured} onClick={() => run(async () => { await api('/api/operations/backup-schedules', 'POST', { name, interval_secs: interval, next_run_at: Math.floor(new Date(next).getTime() / 1000), recipient, retention_count: count, retention_days: days }); await refresh() }, true)}>验证身份并启用备份与保留策略</button>{schedules.map(schedule => <article key={schedule.id}><strong>{schedule.name} · {schedule.claimed_id ? '正在生成加密备份' : schedule.paused ? '已暂停' : '按计划执行'}</strong><p>下次 {time(schedule.next_run_at)}；最近开始 {time(schedule.last_started_at)}；最近结束 {time(schedule.last_finished_at)}</p>{schedule.last_error && <p role="alert">{schedule.last_error}</p>}<button className="ui-button" disabled={Boolean(schedule.claimed_id)} onClick={() => run(async () => { await api(`/api/operations/backup-schedules/${schedule.id}/pause`, 'POST', { paused: !schedule.paused }); await refresh() }, schedule.paused)}>{schedule.paused ? '核对后恢复计划' : '人工暂停计划'}</button></article>)}</section>
}
