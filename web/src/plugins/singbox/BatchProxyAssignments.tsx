import { useState } from 'react'
import { ErrorNotice } from '../../components'
import { resourceWriteError, useResource } from '../../hooks'
import type { ProxyUser } from '../../types'
import type { PolicyGroup } from './groupTypes'
import OperationReview from './OperationReview'
import type { WorkflowOperation } from './OperationReview'

export default function BatchProxyAssignments({ users, userError, onChanged }: { users: ProxyUser[]; userError: () => string; onChanged: () => void }) {
  const policies = useResource<PolicyGroup[]>('/api/plugins/sing-box/policy-groups')
  const [selectedUsers, setSelectedUsers] = useState<number[]>([])
  const [selectedGroups, setSelectedGroups] = useState<number[]>([])
  const [operation, setOperation] = useState<WorkflowOperation | null>(null)
  const error = userError() || resourceWriteError(policies) || (selectedUsers.some(id => !users.some(user => user.id === id)) ? '部分已选用户不存在，原选择保留，请重新核对。' : '') || (selectedGroups.some(id => !policies.data?.some(group => group.id === id)) ? '部分已选策略组不存在，原选择保留，请重新核对。' : '')
  return <section className="panel"><details className="panel-body"><summary>批量分配策略组</summary><ErrorNotice message={error} retry={policies.reload} /><h3>固定用户目标</h3><div className="group-choices">{users.map(user => <label className="group-choice" key={user.id}><input type="checkbox" checked={selectedUsers.includes(user.id)} onChange={event => setSelectedUsers(previous => event.target.checked ? [...previous, user.id] : previous.filter(id => id !== user.id))} /><span>{user.name}</span></label>)}</div><h3>变更后的策略组集合</h3><div className="group-choices">{policies.data?.map(group => <label className="group-choice" key={group.id}><input type="checkbox" checked={selectedGroups.includes(group.id)} onChange={event => setSelectedGroups(previous => event.target.checked ? [...previous, group.id] : previous.filter(id => id !== group.id))} /><span>{group.name}</span></label>)}</div><p>提交前逐个预览新增与撤销节点。此操作替换所选用户全部策略组，空集合表示取消策略组；单独授权保留。</p><button className="button button-secondary" disabled={Boolean(error) || !selectedUsers.length} onClick={() => setOperation({ operation: 'policy_batch', user_ids: [...selectedUsers], group_ids: [...selectedGroups] })}>预览影响 {selectedUsers.length} 位用户</button>{operation && <OperationReview request={operation} onClose={() => setOperation(null)} onApplied={() => { setOperation(null); onChanged() }} />}</details></section>
}
