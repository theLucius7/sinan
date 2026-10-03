import type { FormEvent } from 'react'
import { api, ApiError } from '../api'
import { Brand, ErrorNotice, Icon } from '../components'
import { useAction } from '../hooks'
import { loginPasskey, passkeySupport } from '../passkeys'

export default function Login({ onLogin, notice }: { onLogin: () => void; notice: string }) {
  const action = useAction()
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    const login_name = String(data.get('login_name') ?? 'admin')
    const password = String(data.get('password') ?? '')
    const totp_code = String(data.get('totp_code') ?? '')
    void action.run(async () => {
      try {
        await api('/api/login', 'POST', { login_name, password, totp_code })
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          throw new Error('密码或验证码不正确、已过期或已使用，请重新输入。')
        }
        throw error
      }
    }, onLogin)
  }

  return <main className="login-page">
    <div className="login-story">
      <Brand />
      <div className="login-story-content">
        <span className="eyebrow">一处管理，始终有序</span>
        <h1>掌握每一台<br />服务器。</h1>
        <p>从设备接入到节点授权，<br />让网络的每一步都清晰可见。</p>
        <div className="login-benefits">
          <span><Icon name="server" size={19} />设备主动连接</span>
          <span><Icon name="check" size={19} />配置自动对账</span>
          <span><Icon name="activity" size={19} />流量按用户统计</span>
        </div>
      </div>
      <div className="login-bottom">司南 · 自托管服务器与节点面板</div>
    </div>
    <div className="login-form-side">
      <div className="login-card">
        <span className="login-lock"><Icon name="lock" size={23} /></span>
        <h2>欢迎回来</h2>
        <p>输入管理员密码；已启用二步验证时，还需验证器中的验证码。</p>
        <ErrorNotice message={action.error || notice} />
        <form onSubmit={submit}>
          <label className="field"><span>管理员登录名</span><input name="login_name" required defaultValue="admin" autoComplete="username" disabled={action.busy} /></label>
          <label className="field">
            <span>管理员密码</span>
            <input name="password" type="password" required autoComplete="current-password" autoFocus
              disabled={action.busy} placeholder="请输入密码" />
          </label>
          <label className="field">
            <span>二步验证码</span>
            <input name="totp_code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
              autoComplete="one-time-code" disabled={action.busy} placeholder="未启用时留空" />
            <small>启用二步验证后，请输入验证器当前的六位数字。</small>
          </label>
          <button className="button button-primary login-submit" disabled={action.busy}>
            {action.busy ? <><span className="spinner" />正在登录…</> : <>登录面板<Icon name="arrow" size={18} /></>}
          </button>
        </form>
        <button className="button button-secondary login-submit" type="button" disabled={action.busy || Boolean(passkeySupport())}
          onClick={() => void action.run(() => loginPasskey('/api/login/passkey'), onLogin)}>使用初始所有者 Passkey 登录</button>
        {passkeySupport() && <p className="helper">{passkeySupport()}</p>}
        <div className="login-hint"><Icon name="lock" size={13} />仅限管理员访问，使用部署时设置的密码。</div>
      </div>
      <div className="login-footer">你的服务器，你的控制权。</div>
    </div>
  </main>
}
