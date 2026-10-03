import { usePreference } from './preferences'
import { useAction } from '../hooks'
import { ErrorNotice } from '../components'
export type ServerView = { query: string; online: 'all' | 'online' | 'offline'; group: string; groupBy: 'none' | 'group' | 'region'; sort: 'id' | 'name' | 'cpu' | 'expiry'; columns: string[]; density: 'comfortable' | 'compact' }
export const defaultServerView: ServerView = { query: '', online: 'all', group: '', groupBy: 'none', sort: 'id', columns: ['cpu', 'memory', 'cost', 'traffic', 'version'], density: 'comfortable' }
export default function ServerListView({ value, onChange, groups }: { value: ServerView; onChange: (value: ServerView) => void; groups: string[] }) {
  const saved = usePreference<ServerView>('view:servers')
  const action = useAction()
  const columns: [string, string][] = [['cpu', '处理器'], ['memory', '内存'], ['cost', '成本到期'], ['traffic', '流量'], ['version', '版本']]
  return <section className="panel"><div className="panel-body"><div className="control-form-grid">
    <label className="field"><span>筛选名称、标签或地区</span><input type="search" value={value.query} onChange={event => onChange({ ...value, query: event.target.value })} /></label>
    <label className="field"><span>状态</span><select value={value.online} onChange={event => onChange({ ...value, online: event.target.value as ServerView['online'] })}><option value="all">全部</option><option value="online">在线</option><option value="offline">离线或未接入</option></select></label>
    <label className="field"><span>分组</span><select value={value.group} onChange={event => onChange({ ...value, group: event.target.value })}><option value="">全部分组</option>{groups.map(group => <option key={group} value={group}>{group || '未分组'}</option>)}</select></label>
    <label className="field"><span>排序</span><select value={value.sort} onChange={event => onChange({ ...value, sort: event.target.value as ServerView['sort'] })}><option value="id">接入顺序</option><option value="name">名称</option><option value="cpu">CPU 使用率</option><option value="expiry">到期时间</option></select></label>
    <label className="field"><span>列表分组方式</span><select value={value.groupBy} onChange={event => onChange({ ...value, groupBy: event.target.value as ServerView['groupBy'] })}><option value="none">不分组</option><option value="group">按服务器分组</option><option value="region">按地区分组</option></select></label>
  </div><div className="control-actions">{columns.map(([key, label]) => <label key={key}><input type="checkbox" checked={value.columns.includes(key)} onChange={event => onChange({ ...value, columns: event.target.checked ? [...value.columns, key] : value.columns.filter(item => item !== key) })} />{label}</label>)}<label><input type="checkbox" checked={value.density === 'compact'} onChange={event => onChange({ ...value, density: event.target.checked ? 'compact' : 'comfortable' })} />紧凑列表</label></div>
    <ErrorNotice message={saved.error || action.error} retry={saved.reload} /><div className="control-actions"><button className="button button-secondary" disabled={!saved.ready || action.busy} onClick={() => void action.run(() => saved.save(value))}>保存当前视图</button><button className="button button-secondary" disabled={!saved.ready || !saved.value} onClick={() => saved.value && onChange({ ...defaultServerView, ...saved.value })}>应用已保存视图</button><button className="button button-secondary" onClick={() => onChange(defaultServerView)}>恢复默认视图</button></div>
  </div></section>
}
