export type ReauthenticationRequest = { resolve: () => void; reject: (error: Error) => void }
export function requestReauthentication(): Promise<void> {
  return new Promise((resolve, reject) => window.dispatchEvent(new CustomEvent<ReauthenticationRequest>('sinan:reauthentication', { detail: { resolve, reject } })))
}
