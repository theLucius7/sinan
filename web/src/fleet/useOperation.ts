import { useEffect, useRef, useState } from 'react'
import { ApiError, api, errorMessage } from '../api'
import type { OperationRecord } from './types'

const terminal = ['succeeded', 'failed', 'expired', 'cancelled', 'reconciled']
const failure = ['failed', 'expired', 'cancelled']
export const operationStages: Record<string, string> = {
  idle: '尚未请求', submitting: '正在请求传输或操作', querying: '正在读取已有任务状态', rejected: '面板已拒绝请求', reconciled: '已人工核对结束，未认定设备执行成功', queued: '已排队，等待面板分发', dispatched: '已发送目标 Agent，等待执行回执', running: '目标 Agent 正在执行',
  succeeded: '目标 Agent 已回报成功', failed: '目标 Agent 回报失败', expired: '请求已过期', cancelled: '已取消', cancel_requested: '已请求取消，等待设备确认', unknown: '执行结果未知，需要核对', awaiting_receipt: '尚未取得最终回执，保留原任务', connection_lost: '状态查询中断，原任务可能仍在执行',
}

export function useOperation(server: number) {
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [record, setRecord] = useState<OperationRecord | null>(null), [phase, setPhase] = useState('idle')
  const latest = useRef<OperationRecord | null>(null), tracking = useRef<string | null>(null), uncertain = useRef(false), active = useRef(false), generation = useRef(0)
  useEffect(() => {
    generation.current += 1; latest.current = null; tracking.current = null; uncertain.current = false; active.current = false; setRecord(null); setBusy(false); setError(''); setPhase('idle')
    return () => { generation.current += 1 }
  }, [server])
  const save = (value: OperationRecord) => { latest.current = value; tracking.current = value.id; uncertain.current = !terminal.includes(value.status); setRecord(value); setPhase(value.status) }
  const resultOf = (value: OperationRecord) => {
    if (value.status === 'unknown') { setError('设备执行结果未知。先核对原任务及远端状态，不能把超时当成未执行并重复上传。'); return null }
    if (failure.includes(value.status)) { setError(value.result?.error ?? '操作未成功，请查看原任务与设备结果。'); return null }
    if (value.status === 'succeeded') {
      if (value.result?.succeeded !== true || !value.result.result) { uncertain.current = true; setPhase('unknown'); setError('成功状态缺少完整设备结果，继续核对原任务。'); return null }
      return value.result.result
    }
    return null
  }
  const wait = async (id: string, current: number) => {
    for (let attempt = 0; attempt < 120; attempt++) {
      if (attempt > 0) await new Promise(resolve => window.setTimeout(resolve, 500))
      if (current !== generation.current) return null
      const value = await api<OperationRecord>(`/api/fleet/operations/${id}`)
      if (current !== generation.current) return null
      save(value)
      if (terminal.includes(value.status) || value.status === 'unknown') return resultOf(value)
    }
    setPhase('awaiting_receipt'); setError('仍在等待 Agent 回报。原任务已保存，请读取其状态；不要重复提交变更。')
    return null
  }
  const execute = async (operation: unknown) => {
    if (active.current) return null
    if (uncertain.current || (latest.current && !terminal.includes(latest.current.status))) { setError('原任务仍未确定，请先读取原任务状态，避免重复执行。'); return null }
    const current = generation.current
    latest.current = null; tracking.current = null; active.current = true; setRecord(null); setBusy(true); setError(''); setPhase('submitting')
    try {
      const job = await api<{ id: string; status: string }>(`/api/servers/${server}/fleet/operations`, 'POST', operation)
      if (current !== generation.current) return null
      save({ ...job, result: null })
      return await wait(job.id, current)
    } catch (failure) {
      if (current === generation.current) {
        const rejected = !latest.current && failure instanceof ApiError && [400, 401, 403, 404, 409, 422].includes(failure.status)
        uncertain.current = !rejected
        setError(latest.current || rejected ? errorMessage(failure) : `${errorMessage(failure)} 提交结果尚未确定，请先查看服务器操作历史，避免重复提交。`); setPhase(rejected ? 'rejected' : latest.current ? 'connection_lost' : 'unknown')
      }
      return null
    } finally { if (current === generation.current) { active.current = false; setBusy(false) } }
  }
  const refresh = async () => {
    const id = tracking.current
    if (!id || active.current) return null
    const current = generation.current
    active.current = true; setBusy(true); setError('')
    try {
      const value = await api<OperationRecord>(`/api/fleet/operations/${id}`)
      if (current !== generation.current) return null
      save(value)
      return resultOf(value)
    } catch (failure) { if (current === generation.current) { setError(errorMessage(failure)); setPhase('connection_lost') }; return null }
    finally { if (current === generation.current) { active.current = false; setBusy(false) } }
  }
  const resume = async (id: string) => {
    if (active.current) return null
    const current = generation.current
    tracking.current = id; latest.current = null; active.current = true; setRecord(null); setBusy(true); setError(''); setPhase('querying')
    try { return await wait(id, current) }
    catch (failure) { if (current === generation.current) { setError(errorMessage(failure)); setPhase('connection_lost') }; return null }
    finally { if (current === generation.current) { active.current = false; setBusy(false) } }
  }
  return { busy, error, record, phase, operationId: tracking.current, pending: Boolean(record && !terminal.includes(record.status)) || phase === 'unknown' || (phase === 'connection_lost' && !record), execute, refresh, resume }
}
