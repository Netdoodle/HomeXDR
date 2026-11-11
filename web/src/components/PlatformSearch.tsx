// The top bar search: finds places in the console (Settings → Suppressions, Agent updates →
// Inactive agents, ...) as you type, and searches events on Enter when no place is picked.

import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { placeHref, searchPlaces, slug, type PlatformPlace } from '../lib/platformIndex'
import { useCan } from './Auth'
import { Icon } from './Icon'

type Option = { kind: 'place'; place: PlatformPlace } | { kind: 'events' }

export function PlatformSearch() {
  const navigate = useNavigate()
  const isAdmin = useCan('admin')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const box = useRef<HTMLDivElement>(null)

  const places = useMemo(() => searchPlaces(q, isAdmin), [q, isAdmin])
  // A query with field syntax is an event search; otherwise places come first.
  const looksLikeQuery = /[:=<>"*()]/.test(q)
  const options: Option[] = useMemo(() => {
    const p: Option[] = places.map((place) => ({ kind: 'place', place }))
    return looksLikeQuery ? [{ kind: 'events' }, ...p] : [...p, { kind: 'events' }]
  }, [places, looksLikeQuery])

  useEffect(() => setActive(0), [q])
  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [])

  const choose = (o: Option | undefined) => {
    if (!o) return
    if (o.kind === 'events') {
      if (!q.trim()) return
      navigate(`/search?q=${encodeURIComponent(q.trim())}`)
    } else {
      navigate(placeHref(o.place))
    }
    setQ('')
    setOpen(false)
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setOpen(true)
      setActive((a) => Math.min(a + 1, options.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(a - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      choose(options[active])
    } else if (e.key === 'Escape') {
      setOpen(false)
    }
  }
  const show = open && q.trim().length >= 2

  return (
    <div className="topbar-search platform-search" ref={box} role="search">
      <input
        className="input"
        style={{ width: '100%' }}
        placeholder="Search HomeXDR or events (Suppressions, process.name:powershell.exe)"
        value={q}
        onChange={(e) => {
          setQ(e.target.value)
          setOpen(true)
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={onKey}
        aria-label="Search pages, settings and events"
        aria-expanded={show}
        aria-controls="platform-search-results"
        role="combobox"
        aria-autocomplete="list"
      />
      {show ? (
        <ul className="platform-search-results" id="platform-search-results" role="listbox">
          {options.map((o, i) => (
            <li
              key={o.kind === 'events' ? 'events' : placeHref(o.place) + o.place.crumbs.join('/')}
              role="option"
              aria-selected={i === active}
              className={i === active ? 'active' : ''}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => {
                e.preventDefault()
                choose(o)
              }}
            >
              {o.kind === 'events' ? (
                <>
                  <Icon name="search" />
                  <span>
                    Search events for <span className="mono">{q.trim()}</span>
                  </span>
                </>
              ) : (
                <>
                  <Icon name={o.place.crumbs[0] === 'Settings' ? 'settings' : 'chevronRight'} />
                  <span>
                    {o.place.crumbs.map((c, j) => (
                      <span key={j}>
                        {j > 0 ? <span className="muted"> › </span> : null}
                        {j === o.place.crumbs.length - 1 ? <strong>{c}</strong> : <span className="muted">{c}</span>}
                      </span>
                    ))}
                  </span>
                </>
              )}
            </li>
          ))}
          {places.length === 0 && !looksLikeQuery ? <li className="muted small empty">No page or setting matches</li> : null}
        </ul>
      ) : null}
    </div>
  )
}

/**
 * Scrolls to the section named in the URL hash once the page has rendered it: an element
 * with that id, or a heading whose text slugs to it. Content often loads after
 * navigation, so it keeps looking for a few seconds.
 */
export function useHashSection() {
  const loc = useLocation()
  useEffect(() => {
    const want = decodeURIComponent(loc.hash.replace(/^#/, ''))
    if (!want) return
    let tries = 0
    const timer = window.setInterval(() => {
      tries++
      const el =
        document.getElementById(want) ??
        Array.from(document.querySelectorAll<HTMLElement>('main h1, main h2, main h3')).find((h) => slug(h.textContent ?? '') === want) ??
        null
      if (el || tries > 40) window.clearInterval(timer)
      if (!el) return
      const target = (el.closest('.panel') as HTMLElement | null) ?? el
      target.scrollIntoView({ behavior: 'smooth', block: 'start' })
      target.classList.add('flash-target')
      window.setTimeout(() => target.classList.remove('flash-target'), 1800)
    }, 100)
    return () => window.clearInterval(timer)
  }, [loc.pathname, loc.hash])
}
