import { useState } from 'react'
import { api } from '../api'
import { ErrorNotice, Loading, Refresh } from '../components'
import { useAction, useResource } from '../hooks'

type Observation = { status: string; checked_at?: number; observed_at?: number; stale?: boolean; error?: string; reason?: string; evidence?: { ids?: string[]; details_incomplete?: boolean; details?: { id: string; summary: string; withdrawn?: string; fixed_versions: string[] }[] } }
type Package = { name: string; version: string; ecosystem: string; advisories: Observation }
type Inventory = { dependencies: Package[]; signed_tools: { status: string; reason?: string; entries?: { name: string; version: string; arch: string; sha256: string }[] }; advisory_source: string; limitations: string }
const states: Record<string, string> = { unknown: '尚无来源证据', 'lookup-error': '查询失败，不能判断', 'no-recorded-advisory': '此来源暂未记录建议', 'advisories-recorded': '来源记录了安全建议', 'advisories-incomplete': '已有建议，详情不完整' }
const time = (seconds?: number) => seconds ? new Date(seconds * 1000).toLocaleString('zh-CN') : '尚未观测'
export default function ToolSecurity() {
  const resource = useResource<Inventory>('/api/control-center/tool-security')
  const action = useAction()
  const [filter, setFilter] = useState('')
  const selected = resource.data?.dependencies.filter(item => item.name.toLowerCase().includes(filter.toLowerCase())) ?? []
  return <section className="panel"><div className="panel-heading"><h2>工具与依赖风险</h2><Refresh onClick={resource.reload} /></div><div className="panel-body">
    <ErrorNotice message={resource.error || action.error} retry={resource.reload} />{!resource.data && !resource.error && <Loading />}
    <p>工作区锁文件保留精确版本，包含开发依赖，不表示每个包都进入此面板进程。工具签名、目标平台和运行兼容性分别核对。</p>
    <button className="button button-primary" disabled={action.busy} onClick={() => void action.run(() => api('/api/control-center/tool-security/refresh', 'POST', {}), resource.reload)}>{action.busy ? '正在查询官方来源…' : '查询 OSV 官方安全建议'}</button>
    <p>查询最多耗时一分钟，失败保留上次证据。暂未记录建议不代表没有风险；建议的修复版本需要先检查兼容性，不会自动升级。</p>
    <h3>本地签名工具</h3>{resource.data?.signed_tools.status === 'verified' ? resource.data.signed_tools.entries?.map(entry => <div className="control-row" key={`${entry.name}:${entry.version}:${entry.arch}`}><div style={{ minWidth: 0, overflowWrap: 'anywhere' }}><strong>{entry.name} · {entry.version} · {entry.arch}</strong><p>发布签名及内容摘要已核对</p><small>{entry.sha256}</small></div></div>) : <p>{resource.data?.signed_tools.reason || '尚无可用签名工具'}</p>}
    <h3>锁定依赖版本</h3><label className="field"><span>按包名称筛选</span><input value={filter} onChange={event => setFilter(event.target.value)} /></label><p>共 {resource.data?.dependencies.length ?? 0} 个版本，当前匹配 {selected.length} 个；最多显示 100 项，可继续筛选。</p>
    {selected.slice(0, 100).map(item => <details key={`${item.ecosystem}:${item.name}:${item.version}`} style={{ overflowWrap: 'anywhere' }}><summary>{item.name} · {item.version} · {states[item.advisories.status] || '未知'}{item.advisories.stale ? ' · 查询已过期' : ''}</summary><p>{item.ecosystem === 'crates.io' ? '公开 crates.io 包' : item.ecosystem === 'Go' ? '签名制品库存中的 Go 模块，不表示当前已部署' : '工作区或其他来源，未查询此生态'} · 最近查询 {time(item.advisories.checked_at)} · 原始证据 {time(item.advisories.observed_at)}</p>{item.advisories.error && <p role="status">{item.advisories.error}</p>}{item.advisories.evidence?.details?.map(detail => <div key={detail.id}><strong>{detail.id}</strong><p>{detail.summary}</p><p>{detail.withdrawn ? `来源已撤回：${detail.withdrawn}` : '来源未标记撤回'} · 来源列出的修复版本：{detail.fixed_versions.join('、') || '未提供'}</p></div>)}{item.advisories.evidence?.details_incomplete && <p>部分详情尚未查询，不据此判断全部影响。</p>}{Boolean(item.advisories.evidence?.ids?.length) && <p>来源身份：{item.advisories.evidence?.ids?.join('、')}</p>}</details>)}
    <p>{resource.data?.limitations}</p>
  </div></section>
}
