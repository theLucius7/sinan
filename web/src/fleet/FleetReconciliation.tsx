import { useState } from 'react'
import { api, errorMessage } from '../api'
import { ErrorNotice, Field } from '../components'
import type { OperationRecord } from './types'
import { operationStages, useOperation } from './useOperation'
import { inspectionCapability, operationCapability, useFleetPermissions } from './permissions'

export default function FleetReconciliation({server,operations,reload}:{server:number;operations:OperationRecord[];reload:()=>void}) {
  const permissions=useFleetPermissions()
  const candidates=operations.filter(operation=>operation.status==='unknown'&&!operation.reconciliation_of)
  const [selected,setSelected]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false),[created,setCreated]=useState<string|null>(null),[finished,setFinished]=useState<unknown>(null)
  const check=useOperation(server),original=selected||candidates[0]?.id||''
  const source=candidates.find(operation=>operation.id===original)?.operation
  const originalCapability=source?operationCapability(source):'',observedCapability=source?inspectionCapability(source):''
  const denialNow=()=>!source?'请先选择当前未知操作。':!originalCapability||!observedCapability?'此操作类型暂不支持安全的只读核对。':['operations:write',originalCapability,observedCapability].map(capability=>permissions.allows(capability,server)?'':permissions.reason(capability,server)).find(Boolean)||''
  const denial=denialNow()
  const inspect=async()=>{
    const currentDenial=denialNow();if(currentDenial){setError(currentDenial);return}
    if(busy||check.busy)return
    setBusy(true);setError('');setFinished(null)
    try{
      const job=await api<{id:string;status:string}>(`/api/fleet/operations/${original}/inspection`,'POST',{})
      setCreated(job.id);await check.resume(job.id);reload()
    }catch(failure){setError(errorMessage(failure))}finally{setBusy(false)}
  }
  const complete=async(form:FormData)=>{
    const currentDenial=denialNow();if(currentDenial){setError(currentDenial);return}
    if(busy||check.busy||!created||check.record?.status!=='succeeded'){setError('请等待新的实际只读检查成功回执后再记录人工结论。');return}
    setBusy(true);setError('')
    try{
      const result=await api(`/api/fleet/operations/${original}/reconcile`,'POST',{inspection_id:created,outcome:String(form.get('outcome')),conclusion:String(form.get('conclusion')),processes_stopped:form.get('stopped')==='on',cleanup_confirmed:form.get('cleaned')==='on'})
      setFinished(result);setCreated(null);setSelected('');reload()
    }catch(failure){setError(errorMessage(failure))}finally{setBusy(false)}
  }
  return <section className="panel" style={{gridColumn:'1 / -1'}}><h2>未知结果人工核对</h2><ErrorNotice message={error||check.error}/>
    <p className="subtle">先取得新的实际只读观测，人工核对原操作执行及临时资源，再记录失败或未知结论。原任务不会重放；迟到的设备回执继续保留。自动化任务在所属作业中处理。</p>
    {candidates.length?<>{denial&&<p className="notice" role="status">人工核对不可用：{denial}</p>}<Field label="未知操作"><select value={original} disabled={busy||check.busy} onChange={event=>{setSelected(event.target.value);setCreated(null);setFinished(null)}}>{candidates.map(operation=><option key={operation.id} value={operation.id}>{operation.operation?.kind} · {operation.id}</option>)}</select></Field>
      <div className="fleet-controls"><button className="button button-secondary" disabled={Boolean(denial)||busy||check.busy} onClick={()=>void inspect()}>发起新的只读核对</button><button className="button button-secondary" disabled={Boolean(denial)||!created||busy||check.busy} onClick={()=>{const currentDenial=denialNow();if(currentDenial){setError(currentDenial);return}void check.refresh()}}>读取只读检查回执</button><button className="button button-secondary" disabled={busy||check.busy} onClick={reload}>刷新操作历史</button></div>
      {created&&<><p aria-live="polite">检查任务：{created} · {operationStages[check.phase]??check.phase}</p><pre className="fleet-output">{JSON.stringify(check.record??{},null,2)}</pre></>}
      <form onSubmit={event=>{event.preventDefault();void complete(new FormData(event.currentTarget))}}><fieldset disabled={Boolean(denial)||busy||check.busy}><Field label="明确人工结论"><select name="outcome"><option value="unknown">实际结果仍未知，人工结束并保留该结论</option><option value="failed">人工确认未达到目标，记录失败结论</option></select></Field><Field label="核对步骤、实际依据与失败 / 未知结论（至少32字，不填凭据）"><textarea name="conclusion" minLength={32} maxLength={4096} required /></Field><label><input type="checkbox" name="stopped" required />已人工确认原操作执行进程停止</label><label><input type="checkbox" name="cleaned" required />已人工核对临时文件、监听及恢复资源清理</label><p className="subtle">只读证据需五分钟内成功的 Agent 回执。人工确认会解除此未知操作的互斥阻塞，设备完成状态仍单独记录。</p><button className="button button-primary" disabled={Boolean(denial)||busy||check.busy||!created||check.record?.status!=='succeeded'}>再次认证并保存人工核对</button></fieldset></form>
    </>:<p>当前没有可在此处理的独立未知操作。</p>}
    {finished!==null&&<pre className="fleet-output">{JSON.stringify(finished,null,2)}</pre>}
  </section>
}
