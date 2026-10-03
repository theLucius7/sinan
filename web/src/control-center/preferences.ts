import { useCallback, useEffect, useState } from 'react'
import { api, errorMessage } from '../api'
export type Preference<T> = { value: T | null; revision: number; updated_at?: number }
export function usePreference<T>(key: string) {
  const [record, setRecord] = useState<Preference<T>>({ value: null, revision: 0 })
  const [ready, setReady] = useState(false)
  const [error, setError] = useState('')
  const read = useCallback(async () => {
    setReady(false)
    try { const result = await api<Preference<T>>(`/api/control-center/preferences/${encodeURIComponent(key)}`); setRecord(result); setError(''); setReady(true) }
    catch (error) { setError(errorMessage(error)) }
  }, [key])
  useEffect(() => { void read() }, [read])
  const save = async (value: T) => {
    if (!ready) throw new Error('偏好尚未读取成功，请先重试。')
    const result = await api<{ revision: number }>(`/api/control-center/preferences/${encodeURIComponent(key)}`, 'PUT', { value, expected_revision: record.revision })
    setRecord({ value, revision: result.revision })
    if (key === 'appearance') window.dispatchEvent(new Event('sinan:appearance-updated'))
  }
  return { ...record, ready, error, save, reload: read }
}
export function useFormDraft<T>(key: string, dirty: boolean) {
  const preference = usePreference<T>(`draft:${key}`)
  useEffect(() => {
    if (!dirty) return
    const leave = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = '' }
    const navigate = (event: MouseEvent) => {
      if (!(event.target instanceof Element)) return
      const link = event.target.closest<HTMLAnchorElement>('a[href^="#"]')
      if (link && link.hash !== window.location.hash && !window.confirm('表单有未保存内容。确定离开此页面吗？')) {
        event.preventDefault()
        event.stopImmediatePropagation()
      }
    }
    window.addEventListener('beforeunload', leave)
    document.addEventListener('click', navigate, true)
    return () => { window.removeEventListener('beforeunload', leave); document.removeEventListener('click', navigate, true) }
  }, [dirty])
  return preference
}
