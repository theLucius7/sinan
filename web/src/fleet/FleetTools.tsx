import { useEffect, useState } from 'react'
import { ErrorNotice, Field } from '../components'
import { operationStages, useOperation } from './useOperation'
import FleetFileTransfer from './FleetFileTransfer'
import type { FleetProfile } from './types'
import { operationCapability, useFleetPermissions } from './permissions'

const encoded = (bytes: Uint8Array) => { let value = ''; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value) }
const digest = async (bytes: Uint8Array) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer))).map(byte => byte.toString(16).padStart(2, '0')).join('')
export default function FleetTools({profile}: {profile: FleetProfile}) {
  const permissions=useFleetPermissions(), server=profile.server_id
  const common=profile.capabilities.includes('fleet:operations:v1'), serviceAvailable=common&&profile.capabilities.includes('fleet:services:v1')&&profile.policy.services.length>0
  const canServiceRead=serviceAvailable&&permissions.allows('services:read',server), canServiceWrite=serviceAvailable&&permissions.allows('services:write',server)
  const fileAvailable=common&&profile.capabilities.includes('fleet:files:v1')&&profile.policy.maximum_file_bytes>0
  const canFileRead=fileAvailable&&profile.policy.read_directories.length>0&&permissions.allows('files:read',server), canFileWrite=fileAvailable&&profile.policy.write_directories.length>0&&permissions.allows('files:write',server)
  const tracker = useOperation(profile.server_id)
  const operation = {...tracker, busy: tracker.busy || tracker.pending, execute: async (spec: Record<string,unknown>)=>{
    const denied=permissions.reason(operationCapability(spec as {kind:string;action?:string;operation?:{action?:string}}),server)
    if(denied){setFileError(denied);return null}
    return tracker.execute(spec)
  }}
  const [unit, setUnit] = useState(profile.policy.services[0] ?? ''), [action, setAction] = useState('status'), [since, setSince] = useState(''), [priority, setPriority] = useState(''), [search, setSearch] = useState(''), [follow, setFollow] = useState(false), [logs, setLogs] = useState('')
  const [path, setPath] = useState(''), [content, setContent] = useState(''), [original, setOriginal] = useState(''), [previousHash, setPreviousHash] = useState(''), [syntax, setSyntax] = useState('json'), [preview, setPreview] = useState(false), [fileError, setFileError] = useState('')
  const readLogs = async () => {
    const result = await operation.execute({kind: 'logs', unit, since: since ? Math.floor(new Date(since).getTime() / 1000) : undefined, priority: priority ? Number(priority) : undefined, search})
    if (result) setLogs(JSON.stringify(result, null, 2))
  }
  useEffect(() => { if (!follow || !unit || !canServiceRead) return; const timer = window.setInterval(() => { if (!operation.busy) void readLogs() }, 5000); return () => window.clearInterval(timer) }, [follow, unit, canServiceRead, operation.busy, since, priority, search])
  const read = async () => {
    setFileError(''); setPreviousHash('')
    const result = await operation.execute({kind: 'file_read', path})
    if (!result) return
    try {
      if (result.path !== path || typeof result.content !== 'string' || typeof result.sha256 !== 'string') throw new Error('文件回执缺少路径与完整性证据。')
      const bytes = Uint8Array.from(atob(result.content), value => value.charCodeAt(0))
      if (bytes.length > Math.min(profile.policy.maximum_file_bytes, 262144) || result.bytes !== bytes.length || await digest(bytes) !== result.sha256.toLowerCase()) throw new Error('文件完整性校验失败。')
      const text = new TextDecoder('utf-8', {fatal: true}).decode(bytes)
      setContent(text); setOriginal(text); setPreviousHash(result.sha256); setPreview(false)
    } catch (failure) { setFileError(failure instanceof TypeError ? '该文件不是有效 UTF-8 配置文本，请使用独立二进制文件传输。' : failure instanceof Error ? failure.message : '无法读取配置文件。') }
  }
  const upload = async (file: File) => { if (file.size > Math.min(profile.policy.maximum_file_bytes, 256 * 1024)) { setFileError('文件超过允许大小'); return } try { setContent(new TextDecoder('utf-8', {fatal: true}).decode(await file.arrayBuffer())); setPreview(false); setFileError('') } catch { setFileError('该文件不是有效 UTF-8 配置文本，请使用独立二进制文件传输。') } }
  const save = async () => {
    setFileError('')
    try {
      const bytes = new TextEncoder().encode(content), sha256 = await digest(bytes)
      if (bytes.length > Math.min(profile.policy.maximum_file_bytes, 262144)) throw new Error('配置内容超过允许大小，草稿保留。')
      const result = await operation.execute({kind: 'file_write', path, content: encoded(bytes), sha256, previous_sha256: previousHash, syntax})
      if (result) {
        if (result.path !== path || result.sha256 !== sha256 || result.saved !== true || result.applied !== false) throw new Error('配置保存回执与本次内容不同，请核对设备结果，草稿保留。')
        setPreviousHash(sha256); setOriginal(content); setPreview(false)
      }
    } catch (failure) { setFileError(failure instanceof Error ? failure.message : '配置内容未确认保存，草稿保留。') }
  }
  const download = () => { if(!permissions.allows('files:read',server))return;const url = URL.createObjectURL(new Blob([content], {type: 'text/plain'})); const link = document.createElement('a'); link.href = url; link.download = path.split('/').pop() || 'managed-config'; link.click(); URL.revokeObjectURL(url) }
  return <><ErrorNotice message={operation.error || fileError} /><div className="fleet-grid">
    <section className="panel"><h2>服务与端口</h2>{!serviceAvailable&&<p className="fleet-warning">设备未提供受管服务能力，或面板未授权任何服务。</p>}{!permissions.allows('services:write',server)&&<p className="subtle">{permissions.reason('services:write',server)}已获读取授权时仍可查看状态与日志。</p>}<div className="fleet-controls"><Field label="受管服务"><select value={unit} onChange={event => setUnit(event.target.value)}>{profile.policy.services.map(unit => <option key={unit}>{unit}</option>)}</select></Field><Field label="动作"><select value={action} onChange={event => setAction(event.target.value)}>{[['status', '查看状态'], ['start', '启动'], ['stop', '停止'], ['restart', '重启'], ['enable', '开机启动'], ['disable', '关闭开机启动']].map(([value, label]) => <option key={value} value={value} disabled={value==='status'?!canServiceRead:!canServiceWrite}>{label}</option>)}</select></Field><button className="button button-primary" disabled={operation.busy || !unit || (action==='status'?!canServiceRead:!canServiceWrite)} onClick={() => { if (action === 'status' || window.confirm(`确认对 ${unit} 执行此服务变更？`)) void operation.execute({kind: 'service', unit, action}) }}>执行</button></div><button className="button button-secondary" disabled={operation.busy || !common || !permissions.allows('monitoring:read',server)} onClick={() => void operation.execute({kind: 'ports'})}>监听地址、协议、端口与进程</button><button className="button button-secondary" disabled={operation.busy||!common||!permissions.allows('operations:read',server)} onClick={()=>void operation.execute({kind:'snapshot'})}>系统只读快照</button><p className="subtle">状态包含启动失败原因；开机启动配置按设备实际支持提供。</p></section>
    <section className="panel"><h2>实时日志</h2>{!permissions.allows('services:read',server)&&<p className="fleet-warning">{permissions.reason('services:read',server)}</p>}<div className="fleet-controls"><Field label="起始时间"><input type="datetime-local" value={since} onChange={event => setSince(event.target.value)} /></Field><Field label="最高等级"><select value={priority} onChange={event => setPriority(event.target.value)}><option value="">全部</option>{[['3', '错误'], ['4', '警告'], ['6', '信息'], ['7', '调试']].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field><Field label="搜索"><input value={search} onChange={event => setSearch(event.target.value)} /></Field></div><div className="fleet-controls"><button className="button button-secondary" disabled={operation.busy || !unit || !canServiceRead} onClick={() => void readLogs()}>读取当前窗口</button><button className="button button-secondary" disabled={!unit || !canServiceRead} onClick={() => setFollow(!follow)}>{follow ? '暂停跟随' : '开始跟随'}</button><button className="button button-secondary" disabled={!logs || !canServiceRead} onClick={() => { if(!permissions.allows('services:read',server))return;const url = URL.createObjectURL(new Blob([logs], {type: 'application/json'})); const link = document.createElement('a'); link.href = url; link.download = 'service-log.json'; link.click(); URL.revokeObjectURL(url) }}>导出已授权日志</button></div><pre className="fleet-output">{logs || '选择同一受管服务后读取；仅返回有界近期日志。'}</pre></section>
    <section className="panel"><h2>受管配置编辑</h2>{!permissions.allows('files:write',server)&&<p className="fleet-warning">{permissions.reason('files:write',server)}已获读取授权时可读取和下载文件。</p>}{!fileAvailable&&<p className="fleet-warning">设备未提供受限文件能力，或文件大小预算未授权。</p>}<p className="subtle">有效 UTF-8 配置文本，上限 {Math.min(profile.policy.maximum_file_bytes, 256 * 1024) / 1024} KiB；保存前核对旧版本、完整性与所选语法，保存后需单独应用服务。</p><Field label="配置文件绝对路径"><input value={path} disabled={operation.busy} onChange={event => { setPath(event.target.value); setPreviousHash(''); setPreview(false) }} /></Field><div className="fleet-controls"><button className="button button-secondary" disabled={operation.busy || !path || !canFileRead} onClick={() => void read()}>读取配置与原版本</button><Field label="从本地导入配置草稿"><input type="file" disabled={operation.busy || !canFileWrite} onChange={event => { const file = event.target.files?.[0]; if (file) void upload(file) }} /></Field><Field label="语法检查"><select value={syntax} disabled={operation.busy || !canFileWrite} onChange={event => setSyntax(event.target.value)}><option value="json">JSON</option><option value="toml">TOML</option><option value="text">文本文件</option></select></Field></div><textarea className="fleet-editor" value={content} disabled={operation.busy} readOnly={!canFileWrite} onChange={event => { setContent(event.target.value); setPreview(false) }} aria-label="配置内容" /><div className="fleet-controls"><button className="button button-secondary" disabled={!previousHash || operation.busy || !canFileWrite} onClick={() => setPreview(true)}>预览变更</button><button className="button button-primary" disabled={operation.busy || !canFileWrite || !preview || !previousHash || content === original} onClick={() => void save()}>确认保存新版本</button><button className="button button-secondary" disabled={!previousHash || operation.busy || !canFileRead} onClick={download}>下载当前配置草稿</button></div>{!profile.policy.write_directories.length && <p className="subtle">当前策略只允许读取，未授权写入目录。</p>}{preview && <div><p>原版本：<code>{previousHash}</code>；旧 {new TextEncoder().encode(original).length} 字节 → 新 {new TextEncoder().encode(content).length} 字节</p><details><summary>查看修改前内容</summary><pre className="fleet-output">{original}</pre></details><p className="subtle">正在编辑的内容将作为新版本保存。远端变化时会拒绝覆盖。</p></div>}</section>
    <p className="subtle">界面按当前账号权限、所选服务器和设备能力限制操作；面板配置的服务与目录还须与 Agent 本机策略取交集，由设备执行前再次核对。</p><FleetFileTransfer profile={profile} />
    <section className="panel"><h2>操作结果</h2><p>状态：{operationStages[operation.phase] ?? '等待操作状态'}</p>{operation.operationId && <p>任务 <code>{operation.operationId}</code> <button className="text-button" disabled={tracker.busy} onClick={() => void operation.refresh()}>读取原任务状态</button></p>}{operation.pending && <p className="subtle">请在操作历史中发起与原任务关联的“新的只读核对”，按实际证据人工结束未知记录；不会自动重放操作。</p>}<pre className="fleet-output">{operation.record ? JSON.stringify(operation.record.result, null, 2) : '每次服务、日志和文件操作都保留独立结果。'}</pre></section>
  </div></>
}
