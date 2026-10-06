import { useEffect, useId, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { FormEvent, ReactNode } from 'react'
import { errorMessage } from './api'
import { resourceRefreshingMessage } from './hooks'
import { useI18n } from './i18n'

const paths: Record<string, ReactNode> = {
  server: <><rect x="4" y="3" width="16" height="7" rx="2" /><rect x="4" y="14" width="16" height="7" rx="2" /><path d="M8 6.5h.01M8 17.5h.01M12 6.5h4M12 17.5h4" /></>,
  nodes: <><circle cx="12" cy="5" r="3" /><circle cx="5" cy="18" r="3" /><circle cx="19" cy="18" r="3" /><path d="m10.5 8-4 7m7-7 4 7M8 18h8" /></>,
  users: <><circle cx="9" cy="8" r="3" /><path d="M3 21v-3a6 6 0 0 1 12 0v3m2-16a3 3 0 0 1 0 6m1 4a5 5 0 0 1 3 4v2" /></>,
  box: <><path d="m12 3 9 5-9 5-9-5 9-5Zm-9 5v9l9 5 9-5V8M12 13v9m-4-17 9 5" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  close: <path d="m6 6 12 12M6 18 18 6" />,
  menu: <path d="M4 7h16M4 12h16M4 17h16" />,
  arrow: <path d="M5 12h14m-6-6 6 6-6 6" />,
  back: <path d="M19 12H5m6-6-6 6 6 6" />,
  copy: <><rect x="8" y="8" width="12" height="13" rx="2" /><path d="M16 8V4a1 1 0 0 0-1-1H4a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h4" /></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 13-3l2 3M4 16l2 3a8 8 0 0 0 13-3" /></>,
  logout: <><path d="M10 4H4v16h6M10 12h11m-4-4 4 4-4 4" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  activity: <path d="M2 12h5l3-8 4 16 3-8h5" />,
  down: <path d="M12 3v18m-6-6 6 6 6-6" />,
  up: <path d="M12 21V3m-6 6 6-6 6 6" />,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2" /></>,
}
export function Icon({ name, size = 20 }: { name: string; size?: number }) { return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] ?? paths.box}</svg> }
export function Brand() { const { t } = useI18n(); return <div className="brand"><span className="brand-mark"><svg viewBox="0 0 32 32" fill="none" aria-hidden="true"><circle cx="16" cy="16" r="10.5" stroke="currentColor" opacity=".5" /><path d="m21 8-3 11-7 5 3-11 7-5Z" fill="currentColor" /><path d="M16 1v4m0 22v4M1 16h4m22 0h4" stroke="currentColor" /></svg></span><div><strong>{t('司南')}</strong><small>{t('服务器与节点')}</small></div></div> }
export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'good' | 'bad' | 'warm' | 'neutral' }) { return <span className={`badge badge-${tone}`}><span className="badge-dot" />{children}</span> }
export function PageHeader({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children?: ReactNode }) { const { t } = useI18n(); return <header className="page-header"><div><div className="eyebrow">{t(eyebrow)}</div><h1>{t(title)}</h1><p>{t(description)}</p></div><div className="header-actions">{children}</div></header> }
export function ErrorNotice({ message, retry }: { message?: string; retry?: () => void }) {
  const { t } = useI18n()
  const transient = message === resourceRefreshingMessage
  const [showRefresh, setShowRefresh] = useState(false)
  useEffect(() => {
    setShowRefresh(false)
    if (!transient) return
    const timer = window.setTimeout(() => setShowRefresh(true), 250)
    return () => window.clearTimeout(timer)
  }, [message, transient])
  return message && (!transient || showRefresh) ? <div className="notice notice-error" role="alert"><span>{message}</span>{retry && <button className="text-button" type="button" onClick={retry}>{t('重试')}</button>}</div> : null
}
/** Explains why a click made during a background refresh did nothing. */
export function RefreshNotice() {
  const { t } = useI18n(); return <div className="notice" role="status"><span>{t('最新信息正在同步，本次操作未执行；请稍候再试。')}</span></div>
}
export function Empty({ icon = 'box', title, description, children }: { icon?: string; title: string; description: string; children?: ReactNode }) { const { t } = useI18n(); return <div className="empty"><span className="empty-icon"><Icon name={icon} size={27} /></span><h3>{t(title)}</h3><p>{t(description)}</p>{children}</div> }
export function Loading() { const { t } = useI18n(); return <div className="loading" role="status"><span className="spinner" />{t('正在加载…')}</div> }
export function Refresh({ onClick }: { onClick: () => void }) { const { t } = useI18n(); return <button className="button button-secondary" onClick={onClick}><Icon name="refresh" size={16} /><span>{t('刷新')}</span></button> }
export function Stat({ label, value, note, icon }: { label: string; value: ReactNode; note?: ReactNode; icon: string }) { const { t } = useI18n(); return <div className="stat"><div className="stat-label">{t(label)}<span><Icon name={icon} size={18} /></span></div><strong>{value}</strong>{note && <small>{note}</small>}</div> }
export function Meter({ value }: { value?: number }) { return <span className="meter"><span style={{ width: `${Math.min(100, Math.max(0, value ?? 0))}%` }} /></span> }
export function Modal({ title, children, onClose, busy = false, wide = false, className = '' }: { title: string; children: ReactNode; onClose: () => void; busy?: boolean; wide?: boolean; className?: string }) {
  const { t } = useI18n()
  const dialog = useRef<HTMLDivElement>(null)
  const titleId = useId()
  const close = useRef(onClose); close.current = onClose
  const pending = useRef(busy); pending.current = busy
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const element = dialog.current
    const initial = element?.querySelector<HTMLElement>('input:not([type="hidden"]), select, button')
    initial?.focus()
    const key = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !pending.current) { event.preventDefault(); close.current() }
      if (event.key !== 'Tab' || !element) return
      const focusable = Array.from(element.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]'))
      const first = focusable[0], last = focusable[focusable.length - 1]
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus() }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus() }
    }
    document.addEventListener('keydown', key)
    const overflow = document.body.style.overflow; document.body.style.overflow = 'hidden'
    return () => { document.removeEventListener('keydown', key); document.body.style.overflow = overflow; previous?.focus() }
  }, [])
  // Dialogs render at the document root so hidden page sections, such as inactive
  // tabs, never hide a dialog that one of their components opened.
  return createPortal(<div className="modal-shade" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose() }}>
    <div ref={dialog} className={`modal ${wide ? 'modal-wide' : ''} ${className}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <header><h2 id={titleId}>{t(title)}</h2><button className="icon-button" aria-label={t('关闭对话框')} disabled={busy} onClick={onClose}><Icon name="close" /></button></header>
      {children}
    </div>
  </div>, document.body)
}
export function FormDialog({ title, children, onClose, onSubmit, busy, disabled = false, submitDisabled = false, error, retry, submitLabel = '保存', wide = false, className = '' }: { title: string; children: ReactNode; onClose: () => void; onSubmit: (data: FormData) => void; busy: boolean; disabled?: boolean; submitDisabled?: boolean; error?: string; retry?: () => void; submitLabel?: string; wide?: boolean; className?: string }) {
  const { t } = useI18n()
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (!busy && !disabled && !submitDisabled) onSubmit(new FormData(event.currentTarget)) }
  // A background refresh only holds the submit; the draft stays editable so typing
  // and draft rows are never lost to a briefly disabled fieldset.
  const locked = busy || (disabled && error !== resourceRefreshingMessage)
  return <Modal title={title} onClose={onClose} busy={busy} wide={wide} className={className}><form onSubmit={submit}><div className="modal-body"><ErrorNotice message={error} retry={retry} /><fieldset disabled={locked}>{children}</fieldset></div><footer><button className="button button-secondary" type="button" onClick={onClose} disabled={busy}>{t('取消')}</button><button className="button button-primary" disabled={busy || disabled || submitDisabled}>{busy && <span className="spinner" />}{busy ? t('正在保存…') : t(submitLabel)}</button></footer></form></Modal>
}
export function Confirm({ title, children, busy, disabled = false, confirmDisabled = false, confirmLabel = '确认删除', busyLabel = '正在删除…', error, retry, onClose, onConfirm }: { title: string; children: ReactNode; busy: boolean; disabled?: boolean; confirmDisabled?: boolean; confirmLabel?: string; busyLabel?: string; error?: string; retry?: () => void; onClose: () => void; onConfirm: () => void }) { const { t } = useI18n(); return <Modal title={title} onClose={onClose} busy={busy}><div className="modal-body"><ErrorNotice message={error} retry={retry} /><p className="confirm-copy">{children}</p></div><footer><button className="button button-secondary" disabled={busy} onClick={onClose}>{t('取消')}</button><button className="button button-danger" disabled={busy || disabled || confirmDisabled} onClick={() => { if (!busy && !disabled && !confirmDisabled) onConfirm() }}>{busy ? t(busyLabel) : t(confirmLabel)}</button></footer></Modal> }
export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) { const { t } = useI18n(); return <label className="field"><span>{t(label)}</span>{children}{hint && <small>{t(hint)}</small>}</label> }
export function CopyButton({ text, label = '复制' }: { text: string; label?: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState('')
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  useEffect(() => { if (!copied) return; const timer = setTimeout(() => setCopied(false), 2000); return () => clearTimeout(timer) }, [copied])
  const copy = async () => {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text)
      else {
        const textarea = document.createElement('textarea'); textarea.value = text; textarea.style.position = 'fixed'; textarea.style.opacity = '0'; document.body.append(textarea); textarea.select()
        const success = document.execCommand('copy'); textarea.remove(); if (!success) throw new Error(t('浏览器禁止自动复制，请选中文字手动复制。'))
      }
      if (alive.current) { setCopied(true); setError('') }
    } catch (error) { if (alive.current) setError(errorMessage(error)) }
  }
  return <span className="copy-control"><button className="button button-secondary button-small" onClick={() => void copy()} type="button"><Icon name={copied ? 'check' : 'copy'} size={15} />{copied ? t('已复制') : t(label)}</button>{error && <small className="copy-error" role="alert">{t('复制失败，请手动选择并复制。')}</small>}</span>
}
export function CopyField({ text, label }: { text: string; label: string }) { return <div className="copy-field"><code tabIndex={0}>{text}</code><CopyButton text={text} label={label} /></div> }
