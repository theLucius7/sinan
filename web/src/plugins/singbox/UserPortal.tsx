import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { api, errorMessage } from '../../api'
import { Brand, CopyField, ErrorNotice, Field, FormDialog, Loading } from '../../components'
import { bytes, time } from '../../format'
import { useAction } from '../../hooks'
import { loginPasskey, passkeySupport, registerPasskey } from '../../passkeys'
import type { PasskeyEntry, PasskeyInfo } from '../../passkeys'
import { LanguageSelect, useI18n } from '../../i18n'
import './portal.css'

type View = { configuration: PasskeyInfo } & ({ authenticated: false } | {
  authenticated: true; name: string; subscription_url: string; usage: { uplink: string; downlink: string }; keys: PasskeyEntry[];
  subscription_status: { status: string; message: string; entitlement: { package_name: string | null; used_bytes: string; monthly_bytes: string | null; expires_at: number | null; next_reset: number | null } }
})

export default function UserPortal({ account, activation }: { account: string; activation?: string }) {
  const { t } = useI18n()
  const base = `/api/plugins/sing-box/portal/${account}`
  const bookmark = `${window.location.origin}/#/plugins/sing-box/account/${account}`
  const [token, setToken] = useState(activation)
  const [data, setData] = useState<View>()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)
  const [editing, setEditing] = useState<PasskeyEntry | 'new' | null>(null)
  const [notice, setNotice] = useState('')
  const action = useAction()
  const reload = () => setRevision(value => value + 1)
  useEffect(() => {
    document.title = `${t('代理用户')} · ${t('司南')}`
    if (activation) window.history.replaceState(null, '', `#/plugins/sing-box/account/${account}`)
  }, [account, activation, t])
  useEffect(() => {
    const controller = new AbortController()
    let active = true, pending = false
    const load = async () => {
      if (pending) return
      pending = true
      try {
        const value = await api<View>(base, 'GET', undefined, controller.signal, false)
        if (active) { setData(value); setError('') }
      } catch (error) { if (active) { setError(errorMessage(error)); setData(undefined) } }
      finally { pending = false; if (active) setLoading(false) }
    }
    setLoading(true); void load()
    const timer = window.setInterval(() => { if (document.visibilityState === 'visible') void load() }, 30000)
    return () => { active = false; controller.abort(); window.clearInterval(timer) }
  }, [base, revision])
  const disabled = passkeySupport() || data?.configuration.reason || ''
  const activate = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const name = String(new FormData(event.currentTarget).get('name') ?? '')
    void action.run(() => registerPasskey(base, { name, activation_token: token }, false), () => {
      setToken(undefined); setNotice('Passkey 已绑定，请收藏此入口供下次登录。'); reload()
    })
  }
  const manage = (form: FormData) => {
    if (!editing) return
    void action.run(async () => {
      await loginPasskey(`${base}/login`, false)
      if (editing === 'new') await registerPasskey(base, { name: String(form.get('name') ?? '') }, false)
      else await api(`${base}/keys/${editing.id}/remove`, 'POST', undefined, undefined, false)
    }, () => { setEditing(null); setNotice(editing === 'new' ? '新 Passkey 已绑定。' : 'Passkey 已删除，其他用户会话已退出。'); reload() })
  }
  return <main className="proxy-portal">
    <header><Brand /><span>{t('代理用户')}</span><LanguageSelect className="portal-language" />{data?.authenticated && <button className="button button-secondary button-small" disabled={action.busy} onClick={() => void action.run(() => api(`${base}/logout`, 'POST', undefined, undefined, false), () => { setData(undefined); setNotice(''); setEditing(null); reload() })}>{t('退出登录')}</button>}</header>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={!editing ? action.error : ''} />
    {notice && <p className="notice notice-success" role="status">{notice}</p>}
    {loading && !data ? <Loading /> : data?.authenticated ? <>
      <section className="panel"><div className="panel-heading"><h1>{data.name}</h1><button className="text-button" onClick={reload}>刷新</button></div><div className="panel-body">
        <div className="user-usage"><div><span>受管节点累计上传</span><strong>{bytes(data.usage.uplink)}</strong></div><div><span>受管节点累计下载</span><strong>{bytes(data.usage.downlink)}</strong></div></div>
        <Field label="我的 sing-box 订阅"><CopyField text={data.subscription_url} label="复制我的订阅" /></Field>
        {data.subscription_status.status === 'ready' ? <a className="button button-primary button-small" href={`${data.subscription_url}&download=true`}>下载订阅配置</a> : <p className="notice" role="status">{data.subscription_status.message}</p>}
        <dl className="group-details"><div><dt>套餐</dt><dd>{data.subscription_status.entitlement.package_name ?? '未设置套餐限制'}</dd></div><div><dt>本期已用 / 额度</dt><dd>{bytes(data.subscription_status.entitlement.used_bytes)} / {data.subscription_status.entitlement.monthly_bytes === null ? '不限量' : bytes(data.subscription_status.entitlement.monthly_bytes)}</dd></div><div><dt>到期</dt><dd>{data.subscription_status.entitlement.expires_at ? time(data.subscription_status.entitlement.expires_at) : '不限期'}</dd></div><div><dt>下次额度重置</dt><dd>{data.subscription_status.entitlement.next_reset ? time(data.subscription_status.entitlement.next_reset) : '不适用'}</dd></div></dl>
        <p className="helper">订阅检查当前授权与套餐状态。受管流量约每三十秒刷新；外部节点用量由提供方计量，已下载的外部凭据也由提供方控制。</p>
        <Field label="我的登录地址"><CopyField text={bookmark} label="复制我的登录地址" /></Field>
      </div></section>
      <section className="panel"><div className="panel-heading"><h2>我的 Passkey</h2><button className="button button-primary button-small" disabled={action.busy || Boolean(disabled) || data.keys.length >= 10} onClick={() => { action.clearError(); setEditing('new') }}>添加 Passkey</button></div><div className="panel-body">
        {disabled && <p className="helper">{disabled}</p>}
        <p>可添加备用密钥；丢失全部密钥时，请联系管理员重置。管理密钥前需要重新验证。</p>
        <div className="table-wrap"><table><thead><tr><th>名称</th><th>最近使用</th><th>操作</th></tr></thead><tbody>{data.keys.map(key => <tr key={key.id}><td>{key.name}</td><td>{key.last_used_at ? time(key.last_used_at) : '尚未使用'}</td><td><button className="text-button danger-text" disabled={action.busy || data.keys.length <= 1 || Boolean(disabled)} onClick={() => { action.clearError(); setEditing(key) }}>删除</button></td></tr>)}</tbody></table></div>
        {data.keys.length === 1 && <p className="helper">至少保留一把密钥。添加备用密钥后可删除旧密钥。</p>}
      </div></section>
    </> : data ? <section className="panel"><div className="panel-heading"><h1>{token ? '开通代理用户入口' : '代理用户登录'}</h1></div><div className="panel-body">
      {disabled && <p className="helper">{disabled}</p>}
      {token ? <form onSubmit={activate}><p>为此账户绑定 Passkey，之后可查看自己的订阅和流量。开通链接只能使用一次。</p><Field label="密钥名称"><input name="name" required maxLength={64} placeholder="例如：我的手机" disabled={action.busy} /></Field><button className="button button-primary" disabled={action.busy || Boolean(disabled)}>绑定 Passkey 并开通</button></form> : <>
        <p>使用已绑定的设备或安全密钥验证身份。</p>
        <button className="button button-primary" disabled={action.busy || Boolean(disabled)} onClick={() => void action.run(() => loginPasskey(`${base}/login`, false), () => { setNotice(''); reload() })}>{action.busy ? '正在验证…' : '使用 Passkey 登录'}</button>
        <p className="helper">尚未开通或丢失密钥时，请联系管理员获取新的开通链接。</p>
      </>}
    </div></section> : null}
    {editing && <FormDialog title={editing === 'new' ? '添加备用 Passkey' : `删除「${editing.name}」？`} onClose={() => setEditing(null)} onSubmit={manage} busy={action.busy} error={action.error} submitLabel={editing === 'new' ? '验证并添加' : '验证并删除'}>
      {editing === 'new' ? <><p>先验证已有密钥，再选择新设备或另一把安全密钥。</p><Field label="新密钥名称"><input name="name" required maxLength={64} /></Field></> : <p>该密钥将无法再登录，其他用户会话将退出。当前会话保留。</p>}
    </FormDialog>}
  </main>
}
