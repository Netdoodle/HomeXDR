import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react'

export type ThemeChoice = 'system' | 'dark' | 'light'
const KEY = 'homexdr.theme'

function readChoice(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY)
    if (v === 'dark' || v === 'light' || v === 'system') return v
  } catch {
    // storage unavailable (private mode, blocked): the default applies
  }
  return 'dark'
}

function apply(choice: ThemeChoice) {
  const root = document.documentElement
  if (choice === 'system') delete root.dataset.theme
  else root.dataset.theme = choice
}

const Ctx = createContext<{ choice: ThemeChoice; setChoice: (c: ThemeChoice) => void }>({
  choice: 'dark',
  setChoice: () => undefined,
})

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [choice, setChoiceState] = useState<ThemeChoice>(readChoice)
  useEffect(() => apply(choice), [choice])
  const setChoice = useCallback((c: ThemeChoice) => {
    setChoiceState(c)
    try {
      localStorage.setItem(KEY, c)
    } catch {
      // ignore
    }
  }, [])
  return <Ctx.Provider value={{ choice, setChoice }}>{children}</Ctx.Provider>
}

export const useTheme = () => useContext(Ctx)

/** What is on screen: the choice, or the OS setting when following the system. */
export function resolvedTheme(choice: ThemeChoice): 'dark' | 'light' {
  if (choice !== 'system') return choice
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}
