import { useEffect, useRef, useState } from 'react'
import { api, errorMessage } from '../api'
import { ErrorNotice, Field } from '../components'
import type { FleetProfile, TerminalResult } from './types'
import { useFleetPermissions } from './permissions'

export default function FleetTerminal({ profile }: {profile: FleetProfile}) {
  const permissions=useFleetPermissions(), authorization=useRef(permissions)
  authorization.current=permissions
  const canRead=permissions.allows('terminal:read',profile.server_id), canWrite=permissions.allows('terminal:write',profile.server_id)
  const [account, setAccount] = useState(profile.policy.terminal_accounts[0] ?? ''), [password, setPassword] = useState(''), [totp, setTotp] = useState('')
  const [id, setId] = useState(''), [status, setStatus] = useState('未连接'), [output, setOutput] = useState(''), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const [columns, setColumns] = useState(100), [rows, setRows] = useState(28)
  const view = useRef<HTMLDivElement>(null), cursor = useRef(0), sending = useRef(Promise.resolve())
  const deviceAvailable=profile.capabilities.includes('fleet:terminal:pty:v1')&&profile.policy.terminal_accounts.length>0
  const available = deviceAvailable && canRead && canWrite
  useEffect(() => {
    if (!id) return
    let cancelled = false, timer = 0
    const poll = async () => {
      if(!authorization.current.allows('terminal:read',profile.server_id)){if(!cancelled)timer=window.setTimeout(poll,1000);return}
      try {
        const result = await api<TerminalResult>(`/api/fleet/terminals/${id}?after=${cursor.current}`)
        if (cancelled) return
        setStatus(result.session.close_requested && !['closed', 'failed'].includes(result.session.status) ? '等待停止确认' : result.session.status)
        if (result.output.length) {
          cursor.current = result.output[result.output.length - 1].sequence
          setOutput(previous => (previous + result.output.map(frame => frame.data).join('')).slice(-256 * 1024))
        }
        if (result.session.error) setError(result.session.error)
        if (!['closed', 'failed'].includes(result.session.status)) timer = window.setTimeout(poll, 500)
      } catch (failure) { if (!cancelled) { setError(errorMessage(failure)); timer = window.setTimeout(poll, 2000) } }
    }
    void poll()
    return () => { cancelled = true; window.clearTimeout(timer); if(authorization.current.allows('terminal:write',profile.server_id))void api(`/api/fleet/terminals/${id}`, 'DELETE').catch(() => {}) }
  }, [id])
  useEffect(() => { if (view.current) view.current.scrollTop = view.current.scrollHeight }, [output])
  const start = async () => {
    const denied=permissions.reason('terminal:write',profile.server_id)||permissions.reason('terminal:read',profile.server_id)
    if(denied||!deviceAvailable){setError(denied||'此设备尚未提供终端能力或允许账号。');return}
    setBusy(true); setError('')
    try {
      await api('/api/control-center/reauth', 'POST', {password, totp_code: totp || undefined})
      setPassword(''); setTotp('')
      const result = await api<{id: string}>(`/api/servers/${profile.server_id}/fleet/terminals`, 'POST', {account, columns, rows, timeout_secs: 900})
      cursor.current = 0; setOutput(''); setId(result.id); setStatus('等待 Agent 建立会话')
      window.setTimeout(() => view.current?.focus(), 100)
    } catch (failure) { setError(errorMessage(failure)) } finally { setBusy(false) }
  }
  const send = (data: string, resize = false) => {
    if(!authorization.current.allows('terminal:write',profile.server_id)||!deviceAvailable)return
    if (!id || ['closed', 'failed', '等待停止确认'].includes(status)) return
    sending.current = sending.current.then(async () => { if(!authorization.current.allows('terminal:write',profile.server_id))return;try { await api(`/api/fleet/terminals/${id}/input`, 'POST', {data, columns: resize ? columns : undefined, rows: resize ? rows : undefined}) } catch (failure) { setError(errorMessage(failure)) } })
  }
  const key = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if(!authorization.current.allows('terminal:write',profile.server_id))return
    const special: Record<string, string> = {Enter: '\r', Backspace: '\x7f', Tab: '\t', Escape: '\x1b', ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D'}
    if (event.ctrlKey && event.key.toLowerCase() === 'c') { event.preventDefault(); send('\x03'); return }
    if (event.ctrlKey && event.key.toLowerCase() === 'd') { event.preventDefault(); send('\x04'); return }
    if (event.metaKey || event.ctrlKey || event.altKey) return
    const data = special[event.key] ?? (event.key.length === 1 ? event.key : '')
    if (data) { event.preventDefault(); send(data) }
  }
  return <section className="panel"><h2>交互式终端</h2><p className="subtle">在指定系统账号下建立独立 PTY。会话最长 15 分钟，空闲五分钟自动关闭；Ctrl+C 发送中断信号。</p><ErrorNotice message={error} />
    {(!canRead||!canWrite)&&<div className="fleet-warning">{permissions.reason('terminal:write',profile.server_id)||permissions.reason('terminal:read',profile.server_id)}交互终端需要读取输出和执行输入两项授权。</div>}
    {!deviceAvailable && <div className="fleet-warning">此服务器尚未提供终端能力或账号授权。需要在 Agent 本机和面板同时配置允许账号。</div>}
    <fieldset disabled={busy||!available}><div className="fleet-controls"><Field label="执行账号"><select value={account} onChange={event => setAccount(event.target.value)}>{profile.policy.terminal_accounts.map(account => <option key={account}>{account}</option>)}</select></Field><Field label="管理员密码"><input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} /></Field><Field label="动态验证码（已启用时）"><input inputMode="numeric" value={totp} onChange={event => setTotp(event.target.value)} /></Field><button className="button button-primary" disabled={busy || !available || !password || !!id && !['closed', 'failed'].includes(status)} onClick={() => void start()}>验证并连接</button></div></fieldset>
    <fieldset disabled={busy||!id||!canWrite||!deviceAvailable}><div className="fleet-controls"><span>状态：{status}</span><Field label="列"><input type="number" min={20} max={300} value={columns} onChange={event => setColumns(Number(event.target.value))} /></Field><Field label="行"><input type="number" min={5} max={120} value={rows} onChange={event => setRows(Number(event.target.value))} /></Field><button className="button button-secondary" disabled={!id} onClick={() => send('', true)}>调整窗口</button><button className="button button-secondary" disabled={!id} onClick={() => send('\x03')}>Ctrl+C</button><button className="button button-danger" disabled={!id} onClick={() => { if(!authorization.current.allows('terminal:write',profile.server_id))return;void api(`/api/fleet/terminals/${id}`, 'DELETE').then(() => setStatus('等待停止确认')).catch(failure => setError(errorMessage(failure))) }}>强制断开</button></div></fieldset>
    <div ref={view} className="fleet-terminal" tabIndex={0} role="textbox" aria-label="远程终端，点击后直接输入" aria-multiline="true" aria-readonly={!canWrite} onKeyDown={key} onPaste={event => { event.preventDefault(); send(event.clipboardData.getData('text').slice(0, 8000)) }}>{output || '点击终端后直接输入；输出会自动刷新。'}</div>
  </section>
}
