import { useEffect } from 'react'
import { usePreference } from './preferences'
import type { Locale } from '../i18n'
import { useI18n } from '../i18n'
export default function Appearance() {
  const preference = usePreference<{ theme: string; density: string; locale?: Locale }>('appearance')
  const { locale, setLocale } = useI18n()
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const apply = () => {
      const theme = preference.value?.theme ?? 'system'
      document.documentElement.dataset.theme = theme === 'system' ? (media.matches ? 'dark' : 'light') : theme
      document.documentElement.dataset.density = preference.value?.density ?? 'comfortable'
      const preferredLocale = preference.value?.locale
      if (preferredLocale && preferredLocale !== locale) setLocale(preferredLocale)
    }
    apply(); media.addEventListener('change', apply)
    const update = () => { void preference.reload() }
    window.addEventListener('sinan:appearance-updated', update)
    return () => { media.removeEventListener('change', apply); window.removeEventListener('sinan:appearance-updated', update) }
  }, [locale, preference.value, preference.reload, setLocale])
  return null
}
