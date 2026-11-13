// An "Investigate" button listing what can be looked up from an event, alert or host. Each
// entry opens the Investigate page with it filled in and checked. With onBlock, IP
// addresses also get a "Block this IP everywhere" entry (host firewall control).

import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { investigateHref, type InvestigateTarget } from '../lib/intel'
import { Icon } from './Icon'

export function InvestigateMenu({
  targets,
  small,
  align = 'right',
  onBlock,
}: {
  targets: InvestigateTarget[]
  small?: boolean
  align?: 'left' | 'right'
  /** offered for IP targets: block the address in every host's firewall */
  onBlock?: (t: InvestigateTarget) => void
}) {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false)
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', esc)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', esc)
    }
  }, [open])
  if (targets.length === 0) return null
  const cls = small ? 'btn sm' : 'btn'
  const blockable = onBlock ? targets.filter((t) => t.ip) : []
  if (targets.length === 1 && blockable.length === 0) {
    const t = targets[0]
    return (
      <button type="button" className={cls} onClick={() => navigate(investigateHref(t.value))} title={`Investigate ${t.value}`}>
        <Icon name="radar" size={13} /> Investigate {t.label.toLowerCase()}
      </button>
    )
  }
  return (
    <div className="menu" ref={ref} onClick={(e) => e.stopPropagation()}>
      <button type="button" className={cls} aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="radar" size={13} /> Investigate <Icon name="chevronDown" size={11} />
      </button>
      {open ? (
        <div className={align === 'left' ? 'menu-pop left' : 'menu-pop'} role="menu" style={{ minWidth: 300 }}>
          {targets.map((t) => (
            <button
              key={t.label + t.value}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                setOpen(false)
                navigate(investigateHref(t.value))
              }}
              title={t.local ? 'A private address: only your own events are searched' : 'Check threat intelligence and your own events'}
            >
              <span className="grow" style={{ minWidth: 0 }}>
                <span className="xsmall muted" style={{ display: 'block' }}>
                  {t.label}
                  {t.local ? ' · your network' : ''}
                </span>
                <span className="mono small" style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.value}
                </span>
              </span>
            </button>
          ))}
          {blockable.map((t) => (
            <button
              key={'block' + t.value}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                setOpen(false)
                onBlock!(t)
              }}
              title="Block this address in every host's own firewall"
            >
              <Icon name="isolate" size={13} />
              <span className="grow" style={{ minWidth: 0 }}>
                <span className="xsmall muted" style={{ display: 'block' }}>
                  Block this IP everywhere
                </span>
                <span className="mono small" style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.value}
                </span>
              </span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )
}
