import { requestReauthentication } from './control-center/reauthentication-request'
export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}
export async function api<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal, adminSession = true, attemptedReauthentication = false): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store', signal,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error
    throw new Error('无法连接面板，请检查网络后重试。')
  }
  if (!response.ok) {
    const text = await response.text()
    let message = `请求未完成（${response.status}），请稍后重试。`
    try { const value = JSON.parse(text); if (typeof value.error === 'string') message = value.error } catch { /* Framework responses may be plain text. */ }
    if (response.status === 403 && adminSession && !attemptedReauthentication && message.includes('请先再次验证管理员密码')) {
      await requestReauthentication()
      return api<T>(path, method, body, signal, adminSession, true)
    }
    if (response.status === 401 && adminSession && path !== '/api/login' && !path.startsWith('/api/login/passkey/')) window.dispatchEvent(new Event('sinan:unauthorized'))
    throw new ApiError(response.status, message)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}
export const errorMessage = (error: unknown) => error instanceof Error ? error.message : '操作未完成，请重试。'
