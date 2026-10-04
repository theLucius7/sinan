import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import type { ActionRunner } from './types'
import { time } from './types'

export type Inspection = { id: string; server_id: number; reconciliation_of: string; status: string; result: { succeeded: boolean; completed_at: number } | null }
export function freshInspection(value: Inspection | null, selected: string | null, original: string, server: number, now: number) {
  const completed = value?.result?.completed_at
  return Boolean(selected && value && value.id === selected && value.reconciliation_of === original && value.server_id === server && value.status === 'succeeded'
    && value.result?.succeeded === true && Number.isFinite(completed) && completed! <= now && completed! >= now - 300)
}
export function freshObservation(value: string, now: number) {
  const observed = value ? Math.floor(new Date(value).getTime() / 1000) : Number.NaN
  return Number.isFinite(observed) && observed <= now && observed >= now - 600
}

export class InspectionRequests {
  private active = true
  private revision = 0
  private selected: string | null = null
  begin() { if (!this.active) return null; this.selected = null; return ++this.revision }
  created(revision: number, id: string) {
    if (!this.active || this.revision !== revision || !id) return false
    this.selected = id; return true
  }
  read() { return this.active && this.selected ? { revision: this.revision, id: this.selected } : null }
  current(request: { revision: number; id: string }) { return this.active && this.revision === request.revision && this.selected === request.id }
  accepts(request: { revision: number; id: string }, value: Inspection) { return this.current(request) && value.id === request.id }
  dispose() { this.active = false; this.selected = null; ++this.revision }
}

export default function FleetReconciliation({ job, server, original, run, refresh, close }: { job: string; server: number; original: string; run: ActionRunner; refresh: () => Promise<void>; close: () => void }) {
  const [inspection, setInspection] = useState<string | null>(null)
  const [receipt, setReceipt] = useState<Inspection | null>(null)
  const [stopped, setStopped] = useState(false), [cleaned, setCleaned] = useState(false)
  const [observedAt, setObservedAt] = useState(''), [evidence, setEvidence] = useState('')
  const requests = useRef(new InspectionRequests())
  useEffect(() => {
    const current = new InspectionRequests(); requests.current = current
    setInspection(null); setReceipt(null); setStopped(false); setCleaned(false); setObservedAt(''); setEvidence('')
    return () => current.dispose()
  }, [job, server, original])
  const now = Math.floor(Date.now() / 1000)
  const ready = freshInspection(receipt, inspection, original, server, now)
  const bytes = new TextEncoder().encode(evidence.trim()).length
  return <section className="operations-review"><h4>核对服务器 {server} 的原日常操作</h4>
    <p>原操作：{original}。先取得新的实际只读设备回执，再确认原进程和临时资源。人工结论保留原未知结果，迟到的真实回执仍可记录。</p>
    <button onClick={() => { const current = requests.current; run(async () => {
      const revision = current.begin()
      if (revision === null) return
      setInspection(null); setReceipt(null); setStopped(false); setCleaned(false); setObservedAt(''); setEvidence('')
      const created = await api<{ id: string }>(`/api/operations/jobs/${job}/inspection`, 'POST', { server_id: server, operation_id: original })
      if (!current.created(revision, created.id)) return
      setInspection(created.id); await refresh()
    }, true) }}>验证身份并发起新的只读核对</button>
    {inspection && <><p>检查任务：{inspection} · {ready ? '已取得五分钟内的成功设备回执' : '等待有效设备回执'}</p><button onClick={() => { const current = requests.current, request = current.read(); run(async () => {
      if (!request || request.id !== inspection || !current.current(request)) return
      const value = await api<Inspection>(`/api/fleet/operations/${request.id}`)
      if (current.accepts(request, value)) setReceipt(value)
    }) }}>读取实际只读回执</button><details><summary>查看设备观测</summary><pre>{JSON.stringify(receipt, null, 2)}</pre></details><p>实际回执时间：{time(receipt?.result?.completed_at)}</p></>}
    <label><input type="checkbox" checked={stopped} onChange={event => setStopped(event.target.checked)} />已实际确认原操作进程停止</label>
    <label><input type="checkbox" checked={cleaned} onChange={event => setCleaned(event.target.checked)} />已实际核对并清理临时文件、监听与恢复资源</label>
    <label>实际观察时间<input type="datetime-local" value={observedAt} onChange={event => setObservedAt(event.target.value)} /></label>
    <label>核对方法、来源与失败或未知结论（32 至 4096 字节，不填凭据）<textarea value={evidence} maxLength={4096} onChange={event => setEvidence(event.target.value)} /></label>
    <button disabled={!inspection || !ready || !stopped || !cleaned || !freshObservation(observedAt, now) || bytes < 32 || bytes > 4096} onClick={() => { const current = requests.current, request = current.read(); run(async () => {
      const now = Math.floor(Date.now() / 1000)
      if (!request || !current.current(request) || request.id !== inspection || !freshInspection(receipt, inspection, original, server, now) || !freshObservation(observedAt, now)) return
      await api(`/api/operations/jobs/${job}/reconcile`, 'POST', { server_id: server, operation_id: original, inspection_id: inspection, process_stopped: stopped, cleanup_confirmed: cleaned, observed_at: Math.floor(new Date(observedAt).getTime() / 1000), evidence: evidence.trim() })
      if (current.current(request)) { close(); await refresh() }
    }, true) }}>验证身份并记录人工核对，停止后续步骤</button><button onClick={close}>保留原任务并关闭表单</button>
  </section>
}
