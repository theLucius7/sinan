import { useEffect, useState } from 'react'
import { api } from '../api'
import type { ActionRunner, Plan } from './types'

type Incident = { id: string; title: string; source_key: string; status: string; server_id: number | null }
type Rule = { id: string; name: string; paused: boolean; run_count: number; max_runs: number; cooldown_secs: number }
export default function RemediationRules({ plan, targets, run, version }: { plan: Plan; targets: number[]; run: ActionRunner; version: number }) {
  const [rules, setRules] = useState<Rule[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [incidentId, setIncidentId] = useState('')
  const [cooldown, setCooldown] = useState(1800)
  const [maxRuns, setMaxRuns] = useState(3)
  const refresh = async () => { const [values, events] = await Promise.all([api<Rule[]>('/api/operations/remediation'), api<Incident[]>('/api/operations/incidents')]); setRules(values); setIncidents(events.filter(event => event.source_key.startsWith('service:') && event.status !== 'resolved')) }
  useEffect(() => { run(refresh) }, [version]) // eslint-disable-line react-hooks/exhaustive-deps
  return <section className="operations-card"><h3>有界自动处置</h3><p>复用上面的固定目标和步骤，仅在同一受管服务故障有两分钟内的新观测时触发。旧数据、任务结果未知、权限撤销或人工暂停时不继续发起。</p><div className="operations-fields"><label>实际故障来源<select value={incidentId} onChange={event => setIncidentId(event.target.value)}><option value="">选择受管服务故障</option>{incidents.filter(event => event.server_id !== null && targets.includes(event.server_id)).map(event => <option key={event.id} value={event.id}>{event.title}</option>)}</select></label><label>冷却期（秒）<input type="number" min={300} max={604800} value={cooldown} onChange={event => setCooldown(Number(event.target.value))} /></label><label>最多触发次数<input type="number" min={1} max={100} value={maxRuns} onChange={event => setMaxRuns(Number(event.target.value))} /></label></div><button className="ui-button" disabled={!incidentId || !targets.length} onClick={() => run(async () => { await api('/api/operations/remediation', 'POST', { name: `${plan.name}自动处置`, incident_id: incidentId, plan, targets, cooldown_secs: cooldown, max_runs: maxRuns }); await refresh() }, true)}>验证身份并启用明确处置规则</button>{rules.map(rule => <p key={rule.id}>{rule.name} · {rule.paused ? '已暂停' : '已启用'} · {rule.run_count}/{rule.max_runs} 次 · 冷却 {rule.cooldown_secs} 秒 <button className="ui-button" onClick={() => run(async () => { await api(`/api/operations/remediation/${rule.id}/pause`, 'POST', { paused: !rule.paused }); await refresh() }, rule.paused)}>{rule.paused ? '恢复规则' : '人工暂停'}</button></p>)}</section>
}
