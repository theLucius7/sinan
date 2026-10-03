import { useEffect, useRef, useState } from 'react'
import { ErrorNotice, Field } from '../components'
import type { FleetProfile } from './types'
import { operationStages, useOperation } from './useOperation'
import { useFleetPermissions } from './permissions'

const hash = async (bytes: Uint8Array) => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes).buffer))).map(byte => byte.toString(16).padStart(2, '0')).join('')
const encode = (bytes: Uint8Array) => { let value = ''; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value) }
type Received = { path: string; bytes: Uint8Array; sha256: string }

export default function FleetFileTransfer({ profile }: { profile: FleetProfile }) {
  const reader = useOperation(profile.server_id), writer = useOperation(profile.server_id)
  const permissions = useFleetPermissions()
  const [path, setPath] = useState(''), [mode, setMode] = useState('create'), [previous, setPrevious] = useState(''), [selected, setSelected] = useState<File | null>(null)
  const [received, setReceived] = useState<Received | null>(null), [error, setError] = useState(''), [preparing, setPreparing] = useState(false), [checking, setChecking] = useState(false), [verified, setVerified] = useState(false), [preparedHash, setPreparedHash] = useState('')
  const scope = useRef(0), selectedPath = useRef(''), uploadTarget = useRef<{ path: string; sha256: string; bytes: number; created: boolean } | null>(null)
  const maximum = Number.isSafeInteger(profile.policy.maximum_file_bytes) ? Math.max(0, Math.min(profile.policy.maximum_file_bytes, 262144)) : 0
  const readReason = !permissions.allows('files:read', profile.server_id) ? permissions.reason('files:read', profile.server_id) : !profile.capabilities.includes('fleet:files:v1') ? 'Agent 尚未声明受限文件读取能力 fleet:files:v1。' : !profile.policy.read_directories.length ? '尚未授权任何只读目录。' : maximum <= 0 ? '文件传输大小预算尚未授权。' : ''
  const writeReason = !permissions.allows('files:write', profile.server_id) ? permissions.reason('files:write', profile.server_id) : !profile.capabilities.includes('fleet:files:transfer:v1') ? 'Agent 尚未声明二进制传输能力 fleet:files:transfer:v1。' : !profile.policy.write_directories.length ? '尚未授权任何允许保存目录。' : maximum <= 0 ? '文件传输大小预算尚未授权。' : ''
  const readReasonNow = () => permissions.allows('files:read', profile.server_id) ? readReason : permissions.reason('files:read', profile.server_id)
  const writeReasonNow = () => permissions.allows('files:write', profile.server_id) ? writeReason : permissions.reason('files:write', profile.server_id)
  const permissionsNow = useRef({ readReason: readReasonNow, writeReason: writeReasonNow })
  permissionsNow.current = { readReason: readReasonNow, writeReason: writeReasonNow }
  const busy = reader.busy || writer.busy || preparing || checking
  useEffect(() => { scope.current += 1; setPath(''); setMode('create'); setPrevious(''); setSelected(null); setReceived(null); setError(''); setPreparing(false); setChecking(false); setVerified(false); setPreparedHash(''); selectedPath.current = ''; uploadTarget.current = null; return () => { scope.current += 1 } }, [profile.server_id])
  const readResult = async (result: Record<string, unknown>) => {
    const current = scope.current
    setChecking(true)
    try {
      if (typeof result.path !== 'string' || result.path !== selectedPath.current || typeof result.content !== 'string' || result.content.length > 4 * Math.ceil(maximum / 3) || typeof result.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(result.sha256) || typeof result.bytes !== 'number' || !Number.isSafeInteger(result.bytes) || result.bytes < 0 || result.bytes > maximum) throw new Error('设备文件结果缺少路径、大小或完整性证据。')
      const bytes = Uint8Array.from(atob(result.content), value => value.charCodeAt(0))
      if (bytes.length !== result.bytes || await hash(bytes) !== result.sha256.toLowerCase()) throw new Error('下载内容大小或 SHA-256 校验失败，不生成下载文件。')
      if (current !== scope.current) return
      setReceived({ path: result.path, bytes, sha256: result.sha256.toLowerCase() }); setPrevious(result.sha256.toLowerCase()); setError('')
    } catch (failure) { if (current === scope.current) setError(failure instanceof Error ? failure.message : '二进制下载校验失败。') }
    finally { if (current === scope.current) setChecking(false) }
  }
  const uploadResult = (result: Record<string, unknown>) => {
    const target = uploadTarget.current
    if (!target || result.path !== target.path || result.bytes !== target.bytes || result.sha256 !== target.sha256 || result.saved !== true || result.created !== target.created || result.applied !== false) { setError('上传回执缺少与本次文件一致的保存证据；请核对原任务和远端文件。'); return }
    setVerified(true)
    if (path === target.path) setPrevious(target.sha256)
  }
  const read = async () => {
    if (permissionsNow.current.readReason()) { setError(permissionsNow.current.readReason()); return }
    if (busy || reader.pending || !path.trim()) return
    selectedPath.current = path; setReceived(null); setError('')
    const result = await reader.execute({ kind: 'file_read', path })
    if (result) await readResult(result)
  }
  const upload = async () => {
    if (permissionsNow.current.writeReason()) { setError(permissionsNow.current.writeReason()); return }
    if (!selected || busy || writer.pending) return
    const current = scope.current, targetPath = path, oldHash = mode === 'create' ? null : previous.trim().toLowerCase()
    setPreparing(true); setError(''); setVerified(false)
    try {
      if (selected.size > maximum) throw new Error('文件超过授权大小上限。')
      if (oldHash !== null && !/^[a-f0-9]{64}$/.test(oldHash)) throw new Error('覆盖已有文件必须提供读取或核对后的旧 SHA-256。')
      const bytes = new Uint8Array(await selected.arrayBuffer()), sha256 = await hash(bytes)
      if (bytes.length !== selected.size || bytes.length > maximum) throw new Error('本地文件大小发生变化或超过上限。')
      if (current !== scope.current) return
      if (permissionsNow.current.writeReason()) throw new Error(permissionsNow.current.writeReason())
      uploadTarget.current = { path: targetPath, sha256, bytes: bytes.length, created: oldHash === null }; setPreparedHash(sha256)
      const result = await writer.execute({ kind: 'file_upload', path: targetPath, content: encode(bytes), sha256, previous_sha256: oldHash })
      if (current === scope.current && result) uploadResult(result)
    } catch (failure) { if (current === scope.current) setError(failure instanceof Error ? failure.message : '上传文件准备失败。') }
    finally { if (current === scope.current) setPreparing(false) }
  }
  const download = () => {
    if (permissionsNow.current.readReason()) { setError(permissionsNow.current.readReason()); return }
    if (!received) return
    const url = URL.createObjectURL(new Blob([new Uint8Array(received.bytes).buffer], { type: 'application/octet-stream' })), link = document.createElement('a')
    link.href = url; link.download = received.path.split(/[\\/]/).pop() || 'server-file'; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <section className="panel"><h2>二进制文件传输</h2><ErrorNotice message={error || reader.error || writer.error} /><p className="subtle">受限普通文件，最大 {maximum} 字节。保留原始字节并核对 SHA-256；上传只保存文件，不应用配置或重启服务。</p><p className="subtle">允许读取目录：{profile.policy.read_directories.join('、') || '未授权'}；允许写入目录：{profile.policy.write_directories.join('、') || '未授权'}。敏感文件与符号链接限制由设备再次核对。</p>
    {readReason && <p className="notice" role="status">读取不可用：{readReason}</p>}{writeReason && <p className="notice" role="status">上传不可用：{writeReason}</p>}
    <Field label="目标文件绝对路径"><input value={path} disabled={busy || writer.pending || reader.pending || Boolean(readReason && writeReason)} onChange={event => { scope.current += 1; setPath(event.target.value); setPrevious(''); setReceived(null); setVerified(false); setPreparedHash('') }} /></Field>
    <div className="fleet-controls"><button className="button button-secondary" disabled={Boolean(readReason) || busy || reader.pending || !path.trim() || !profile.policy.read_directories.length} onClick={() => void read()}>请求读取原始文件</button><button className="button button-secondary" disabled={Boolean(readReason) || !received || busy} onClick={download}>下载已校验的原始文件</button></div>
    {received && <p>已校验 {received.bytes.length} 字节 · <code>{received.sha256}</code>。可用作覆盖前的旧版本依据。</p>}
    <Field label="本地二进制文件"><input type="file" disabled={Boolean(writeReason) || busy || writer.pending} onChange={event => { const file = event.target.files?.[0] ?? null; setSelected(file); setVerified(false); setPreparedHash(''); setError(file && file.size > maximum ? '文件超过授权大小上限。' : '') }} /></Field>
    <Field label="目标文件条件"><select value={mode} disabled={Boolean(writeReason) || busy || writer.pending} onChange={event => setMode(event.target.value)}><option value="create">仅创建新文件（已有文件会拒绝）</option><option value="replace">更新已有文件（必须核对旧 SHA-256）</option></select></Field>
    {mode === 'replace' && <Field label="远端旧文件 SHA-256"><input value={previous} disabled={Boolean(writeReason) || busy || writer.pending} maxLength={64} onChange={event => setPrevious(event.target.value)} placeholder="先读取原文件或填入独立核对的摘要" /></Field>}
    {selected && <p>待上传：{selected.name} · {selected.size} 字节；目标 {path || '未填写'}。{preparedHash && <code>{preparedHash}</code>}</p>}
    <button className="button button-primary" disabled={Boolean(writeReason) || busy || writer.pending || maximum <= 0 || !selected || selected.size > maximum || !path.trim() || !profile.policy.write_directories.length || (mode === 'replace' && !/^[a-f0-9]{64}$/i.test(previous.trim()))} onClick={() => void upload()}>确认受限上传并保存</button>
    <p role="status">上传阶段：{preparing && !writer.busy ? '正在读取本地文件并计算完整性摘要' : operationStages[writer.phase] ?? '等待操作状态'}。{verified && '本次完整性与设备保存回执已匹配；尚未应用到服务。'}</p>
    <p role="status">下载阶段：{checking ? '正在核对设备回执的原始字节完整性' : operationStages[reader.phase] ?? '等待操作状态'}。{received && '原始字节完整性已通过本地核对。'}</p>
    <p className="subtle">当前通道不提供逐字节进度，阶段和总字节数按真实证据显示。结果未知或查询中断时保留原任务，不自动重传。</p>
    {(writer.pending || reader.pending) && <p className="subtle">在服务器操作历史中发起与原任务关联的“新的只读核对”，再按真实设备证据人工结束未知记录。人工结束不等于上传成功。</p>}
    {writer.operationId && <p>上传任务 <code>{writer.operationId}</code> <button className="text-button" disabled={Boolean(writeReason) || busy} onClick={() => { if (permissionsNow.current.writeReason()) { setError(permissionsNow.current.writeReason()); return } void writer.refresh().then(result => { if (result) uploadResult(result) }) }}>读取原任务状态</button></p>}
    {reader.operationId && <p>下载任务 <code>{reader.operationId}</code> <button className="text-button" disabled={Boolean(readReason) || busy} onClick={() => { if (permissionsNow.current.readReason()) { setError(permissionsNow.current.readReason()); return } void reader.refresh().then(result => { if (result) return readResult(result) }) }}>读取原任务状态</button></p>}
  </section>
}
