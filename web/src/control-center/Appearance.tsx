import { useEffect } from 'react'
import { usePreference } from './preferences'
export default function Appearance() {
  const preference = usePreference<{ theme: string; density: string }>('appearance')
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const theme = preference.value?.theme ?? 'system'
      document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme
      document.documentElement.dataset.density = preference.value?.density ?? 'comfortable'
    }
    apply(); media.addEventListener('change', apply)
    const update = () => { void preference.reload() }
    window.addEventListener('sinan:appearance-updated', update)
    return () => { media.removeEventListener('change', apply); window.removeEventListener('sinan:appearance-updated', update) }
  }, [preference.value, preference.reload])
  return null
}
