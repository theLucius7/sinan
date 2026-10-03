import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, errorMessage } from './api'

export const resourceRefreshingMessage = '相关信息正在刷新或刷新失败，请成功刷新后再提交；当前草稿已保留。'
const backgroundNoticeDelay = 250

export function useResource<T>(path: string | null, poll = 5000) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [revision, setRevision] = useState(0)
  const [availability, setAvailability] = useState({ ready: false })
  const previousPath = useRef<string | null>(null)
  const currentPath = useRef(path)
  currentPath.current = path
  const generation = useRef(0)
  const snapshot = useRef<{ path: string | null; valid: boolean; value?: T }>({ path: null, valid: false })
  const reload = useCallback(() => {
    ++generation.current
    snapshot.current.valid = false
    setAvailability({ ready: false }); setLoading(true)
    setRevision(value => value + 1)
  }, [])
  const isCurrent = useCallback(() => currentPath.current === path && snapshot.current.valid && snapshot.current.path === path, [path])
  const getCurrent = useCallback(() => isCurrent() ? snapshot.current.value : undefined, [isCurrent])
  useEffect(() => {
    if (!path) { snapshot.current = { path: null, valid: false }; setData(undefined); setAvailability({ ready: false }); setLoading(false); return }
    if (previousPath.current !== path) { setData(undefined); setLoading(true); setError('') }
    previousPath.current = path
    const controller = new AbortController()
    let active = true
    let sequence = 0
    let pending = false
    let presentation: number | undefined
    const load = async (background = false) => {
      if (pending) return
      pending = true
      const current = ++sequence, epoch = ++generation.current
      snapshot.current.valid = false
      // Writes are blocked immediately, even before React renders. Brief polls
      // retain the current view; a slow read still exposes its unavailable state.
      if (background && snapshot.current.value !== undefined) {
        presentation = window.setTimeout(() => { if (active && epoch === generation.current) setAvailability({ ready: false }) }, backgroundNoticeDelay)
      } else { setAvailability({ ready: false }); setLoading(true) }
      try {
        const result = await api<T>(path, 'GET', undefined, controller.signal)
        if (active && current === sequence && epoch === generation.current) {
          snapshot.current = { path, valid: true, value: result }
          setData(previous => JSON.stringify(previous) === JSON.stringify(result) ? previous : result)
          // Publish completion even for unchanged data: another component may
          // have rendered a disabled action while this request was pending.
          setError(''); setAvailability({ ready: true })
        }
      } catch (error) {
        if (active && current === sequence && epoch === generation.current) {
          setError(errorMessage(error)); setAvailability({ ready: false })
          if (path.startsWith('/api/dashboard/') && error instanceof ApiError && [401, 403, 404].includes(error.status)) setData(undefined)
        }
      } finally { window.clearTimeout(presentation); pending = false; if (active && current === sequence && epoch === generation.current) setLoading(false) }
    }
    void load()
    const timer = poll ? window.setInterval(() => { if (document.visibilityState === 'visible') void load(true) }, poll) : undefined
    return () => { active = false; snapshot.current.valid = false; ++generation.current; controller.abort(); window.clearTimeout(presentation); window.clearInterval(timer) }
  }, [path, poll, revision])
  const currentData = previousPath.current === path ? data : undefined
  return { data: currentData, error, loading, ready: previousPath.current === path && availability.ready,
    refreshing: loading || !isCurrent(), fresh: currentData !== undefined && currentData !== null && !error && isCurrent(),
    reload, isCurrent, getCurrent }
}

export type ResourceState<T> = ReturnType<typeof useResource<T>>

export function resourceWriteError(...resources: { isCurrent?: () => boolean; fresh?: boolean; error?: string }[]): string {
  const failure = resources.find(resource => resource.error)
  if (failure) return `最新信息读取失败，暂不能修改；草稿已保留。${failure.error}`
  return resources.every(resource => resource.isCurrent ? resource.isCurrent() : resource.fresh === true)
    ? '' : resourceRefreshingMessage
}

export function useAction() {
  const alive = useRef(true)
  const locked = useRef(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const run = async <T,>(task: () => Promise<T>, success?: (value: T) => void) => {
    if (locked.current) return
    locked.current = true
    setBusy(true); setError('')
    try { const result = await task(); if (alive.current) success?.(result) }
    catch (error) { if (alive.current) setError(errorMessage(error)) }
    finally { locked.current = false; if (alive.current) setBusy(false) }
  }
  return { busy, error, run, clearError: () => setError('') }
}
