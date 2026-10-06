import { useEffect, useRef, useState } from 'react'
import { api, errorMessage } from '../api'
import './control-center.css'

import type { ReauthenticationRequest } from './reauthentication-request'
export default function Reauthentication() {
  const [pending, setPending] = useState<ReauthenticationRequest[]>([])
  const requests = useRef<ReauthenticationRequest[]>([])
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    const request = (event: Event) => {
      requests.current = [...requests.current, (event as CustomEvent<ReauthenticationRequest>).detail]
      setPending(requests.current)
    }
    window.addEventListener('sinan:reauthentication', request)
    return () => {
      window.removeEventListener('sinan:reauthentication', request)
      for (const item of requests.current) item.reject(new Error('管理员会话已结束，操作尚未提交。'))
      requests.current = []
    }
  }, [])
  if (!pending.length) return null
  const close = () => {
    for (const item of requests.current) item.reject(new Error('已取消再次验证，操作尚未提交。'))
    requests.current = []
    setPending([]); setPassword(''); setCode(''); setError('')
  }
  return <div className="control-modal-backdrop"><section role="dialog" aria-modal="true" aria-labelledby="reauth-title" className="control-modal">
    <h2 id="reauth-title">再次验证身份</h2><p>此操作需要验证当前管理员密码；启用二步验证时还需验证码。证明在当前会话内有效五分钟。</p>
    <form onSubmit={event => {
      event.preventDefault(); if (busy) return
      setBusy(true); setError('')
      void api('/api/control-center/reauth', 'POST', { password, totp_code: code || null }).then(() => {
        const accepted = requests.current
        requests.current = []
        for (const item of accepted) item.resolve()
        setPending([]); setPassword(''); setCode('')
      }).catch(error => setError(errorMessage(error))).finally(() => setBusy(false))
    }}>
      <label className="field">当前管理员密码<input type="password" autoComplete="current-password" autoFocus required value={password} onChange={event => setPassword(event.target.value)} disabled={busy} /></label>
      <label className="field">二步验证码<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={event => setCode(event.target.value)} disabled={busy} /></label>
      {error && <p role="alert">{error}</p>}<div className="control-actions"><button className="ui-button" type="submit" disabled={busy}>{busy ? '正在验证…' : '验证并继续'}</button><button className="ui-button" type="button" disabled={busy} onClick={close}>取消操作</button></div>
    </form>
  </section></div>
}
