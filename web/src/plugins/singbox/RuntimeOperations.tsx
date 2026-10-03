import { useState } from 'react'
import { api } from '../../api'
import { Badge, ErrorNotice, Loading } from '../../components'
import { time } from '../../format'
import { resourceWriteError, useAction, useResource } from '../../hooks'
import type { Deployment } from '../../types'
import './runtime-operations.css'
import OperationsWorkflows from './OperationsWorkflows'

type Operation = 'inspect' | 'restart' | 'retry_deployment'
type Failure = 'expired' | 'interrupted' | 'module_unavailable' | 'target_changed' | 'retiring' | 'manifest_unavailable' | 'operation_failed'
type Entry = { timestamp: number | null; level: 'error' | 'warning' | 'info' | 'unknown'; kind: 'started' | 'stopped' | 'connection_failed' | 'configuration_failed' | 'certificate_failed' | 'other' }
type Snapshot = { observed_at: number; applied_revision: number | null; service: 'active' | 'inactive' | 'unknown'; healthy: boolean | null; logs_available: boolean; logs_service_events: boolean; logs_truncated: boolean; logs: Entry[] }
type OperationRecord = { spec: { id: string; operation: Operation; requested_at: number; expires_at: number }; dispatched_at: number | null; result: { error: Failure | null; snapshot: Snapshot | null; finished_at: number } | null }
type View = { supported: boolean; online: boolean; retiring: boolean; operations: OperationRecord[] }
const operationNames: Record<Operation, string> = { inspect: '读取状态与日志', restart: '重启运行时', retry_deployment: '重试失败部署' }
const failureNames: Record<Failure, string> = { expired: '请求已过期，未执行', interrupted: 'Agent 曾中断，未重复执行；请重新读取状态', module_unavailable: '设备未提供此运行时', target_changed: '期望版本已改变，请刷新', retiring: '设备正在退役', manifest_unavailable: '无法获取当前部署目标', operation_failed: '操作失败，已按部署流程处理恢复；请检查状态及本机日志' }
const logNames: Record<Entry['kind'], string> = { started: '服务启动', stopped: '服务停止', connection_failed: '连接错误', configuration_failed: '配置错误', certificate_failed: '证书或加密连接错误', other: '日志正文已隐藏' }
const levelNames: Record<Entry['level'], string> = { error: '错误', warning: '警告', info: '信息', unknown: '未分类' }

export default function RuntimeOperations({ serverId, status, deploymentError, getStatus }: { serverId: number; status?: Deployment['status']; deploymentError?: () => string; getStatus?: () => Deployment['status'] | undefined }) {
  const path = `/api/plugins/sing-box/servers/${serverId}/runtime-operations`
  const resource = useResource<View>(path)
  const action = useAction()
  const [confirmation, setConfirmation] = useState<{ operation: Operation; revision: number } | null>(null)
  const records = resource.data?.operations ?? []
  const pending = records.find(record => !record.result)
  const snapshot = records.find(record => record.result?.snapshot)?.result?.snapshot
  const available = resource.data?.supported && resource.data.online && !resource.data.retiring
  const writeError = () => resourceWriteError(resource) || deploymentError?.() || ''
  const disabled = !available || !!pending || action.busy || Boolean(writeError())
  const submit = (operation: Operation, expectedRevision?: number) => {
    if (writeError()) return
    const current = resource.getCurrent(), currentStatus = getStatus ? getStatus() : status
    if (!current?.supported || !current.online || current.retiring || current.operations.some(record => !record.result)) return
    if (operation !== 'inspect' && (!currentStatus || currentStatus.target_rev !== expectedRevision)) return
    if (operation === 'restart' && (!currentStatus?.applied_rev || currentStatus.applied_rev !== currentStatus.target_rev)) return
    if (operation === 'retry_deployment' && !(currentStatus && currentStatus.last_result_rev === currentStatus.target_rev && currentStatus.last_error)) return
    void action.run(() => api(path, 'POST', { operation, expected_revision: operation === 'inspect' ? null : currentStatus?.target_rev }), () => { setConfirmation(null); resource.reload() }) }
  const failed = status && status.last_result_rev === status.target_rev && !!status.last_error
  return <section className="runtime-operations">
    <div className="panel-heading"><h3>运行时运维</h3>{snapshot && <Badge tone={snapshot.service === 'active' && snapshot.healthy ? 'good' : 'warm'}>{snapshot.service === 'active' ? '服务运行中' : snapshot.service === 'inactive' ? '服务已停止' : '服务状态未知'}</Badge>}</div>
    <ErrorNotice message={resource.error || action.error} retry={resource.reload} />
    {resource.loading && !resource.data ? <Loading /> : <>
      {!resource.data?.supported && <p>此 Agent 尚不支持运行时运维，请先升级 Agent。</p>}
      {resource.data?.supported && !resource.data.online && <p>设备离线，恢复连接后可读取状态和执行操作。</p>}
      {resource.data?.retiring && <p>服务器正在退役，运维操作已停用。</p>}
      <div className="runtime-operation-actions">
        <button className="button button-secondary" disabled={disabled} onClick={() => submit('inspect')}>读取状态与日志</button>
        <button className="button button-secondary" disabled={disabled || !status?.applied_rev || status.applied_rev !== status.target_rev} onClick={() => { if (!writeError() && status) setConfirmation({ operation: 'restart', revision: status.target_rev }) }}>重启运行时</button>
        <button className="button button-secondary" disabled={disabled || !failed} onClick={() => { if (!writeError() && status) setConfirmation({ operation: 'retry_deployment', revision: status.target_rev }) }}>重试失败部署</button>
      </div>
      {confirmation && <div className="notice"><div><strong>{operationNames[confirmation.operation]} · 版本 {confirmation.revision}</strong><p>{confirmation.operation === 'restart' ? '重启会短暂中断现有连接。完成后重新检查健康状态，失败时执行恢复流程。' : '按当前期望版本重新执行完整部署校验；如果目标版本已改变，本次请求会被拒绝。'}</p><button className="button" disabled={disabled || status?.target_rev !== confirmation.revision} onClick={() => submit(confirmation.operation, confirmation.revision)}>确认{confirmation.operation === 'restart' ? '重启' : '重试'}</button>{' '}<button className="button button-secondary" disabled={action.busy} onClick={() => setConfirmation(null)}>取消</button>{status?.target_rev !== confirmation.revision && <p role="alert">期望版本已改变，请取消后重新确认。</p>}</div></div>}
      {pending && <p role="status">{operationNames[pending.spec.operation]}：{pending.dispatched_at ? '设备已领取，等待执行结果' : '等待设备领取'}。设备中断后会在重连时确认结果。</p>}
      {records[0]?.result?.error && <p className="notice notice-error">{failureNames[records[0].result.error]}</p>}
      {snapshot && <><p className="subtle">采集于 {time(snapshot.observed_at)} · 已应用版本 {snapshot.applied_revision ?? '—'} · {snapshot.healthy === null ? '尚无可检查的配置' : snapshot.healthy ? '健康检查通过' : '健康检查未通过'}</p><h4>{snapshot.logs_service_events ? '脱敏任务事件日志' : '脱敏服务日志'}</h4><p>{snapshot.logs_service_events ? '来自系统任务事件，不包含运行时标准输出。' : '来自实际服务输出。'}最多 100 条、64 KiB；正文与地址、凭据均隐藏，只展示时间、级别及事件分类。系统日志读取最近一小时，文件日志读取末尾窗口。</p>{!snapshot.logs_available ? <p>当前系统服务后端不支持读取日志，或读取失败。请在服务器本机查看服务日志。</p> : !snapshot.logs.length ? <p>近期窗口内没有可显示的服务日志。</p> : <div className="runtime-service-logs" role="log">{snapshot.logs.map((entry, index) => <div key={index}><time>{entry.timestamp ? time(entry.timestamp) : '时间未提供'}</time>{' · '}{levelNames[entry.level]}{' · '}{logNames[entry.kind]}</div>)}</div>}{snapshot.logs_truncated && <p className="subtle">日志已达到窗口上限，较早或过长的内容已截断。</p>}</>}
      {records.length > 0 && <details><summary>操作记录（最近 20 条）</summary><ul>{records.map(record => <li key={record.spec.id}>{time(record.spec.requested_at)} · {operationNames[record.spec.operation]} · {record.result ? record.result.error ? failureNames[record.result.error] : '已完成' : record.dispatched_at ? '等待设备结果' : '等待领取'}</li>)}</ul></details>}
    </>}
    <OperationsWorkflows serverId={serverId} />
  </section>
}
