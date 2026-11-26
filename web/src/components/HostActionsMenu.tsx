// The per-host Actions menu (host page header and each row of the host list): a searchable
// dropdown of everything that can be done to a host, grouped Response / Endpoint / Agent /
// Danger, with recently used and favourite items on top. What shows, and what is greyed
// out and why, comes from lib/hostMenu.ts.

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router'
import { api, queryKeys, type CommandRequest, type Host } from '../api'
import { HostGroupPicker } from '../pages/GroupsSettings'
import { formatDelay, POWER_DEFAULT_DELAY } from '../lib/commands'
import {
  FAVOURITES_KEY,
  filterEntries,
  isUnraid,
  menuEntries,
  pushRecent,
  readList,
  RECENT_KEY,
  SECTION_LABEL,
  SECTION_ORDER,
  toggleFavourite,
  writeList,
  type MenuEntry,
} from '../lib/hostMenu'
import { ActionConfirmDialog } from './ActionDialog'
import { useMe } from './Auth'
import { Icon } from './Icon'
import { ConfirmDialog, Modal } from './Modal'
import { RemoveHostDialog } from './RemoveHostDialog'
import { useToast } from './Toast'

type Pending =
  | { kind: 'command'; request: CommandRequest }
  | { kind: 'power'; type: 'host.reboot' | 'host.shutdown' }
  | { kind: 'group' | 'rescan' | 'update-now' | 'decommission' | 'recommission' | 'revoke' | 'remove' }

interface Row {
  key: string
  entry: MenuEntry
  /** shown on the right in search results, where there are no group headings */
  hint?: string
}
interface Group {
  label: string
  rows: Row[]
}

const POP_WIDTH = 340
const DELAYS = [0, 60, 300, 900, 3600]

export function HostActionsMenu({ host, small }: { host: Host; small?: boolean }) {
  const navigate = useNavigate()
  const role = useMe().data?.role
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const [recent, setRecent] = useState<string[]>(() => readList(RECENT_KEY))
  const [favs, setFavs] = useState<string[]>(() => readList(FAVOURITES_KEY))
  const [pending, setPending] = useState<Pending | null>(null)
  const [pos, setPos] = useState<{ top: number; left: number; maxHeight: number } | null>(null)
  const btnRef = useRef<HTMLButtonElement>(null)
  const popRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const listId = useId()

  const groups = useMemo<Group[]>(() => {
    const entries = menuEntries(host, role)
    const row = (prefix: string, e: MenuEntry, hint?: string): Row => ({ key: `${prefix}:${e.item.id}`, entry: e, hint })
    if (query.trim()) {
      const hits = filterEntries(entries, query)
      return hits.length ? [{ label: 'Results', rows: hits.map((e) => row('q', e, SECTION_LABEL[e.item.section])) }] : []
    }
    const byId = new Map(entries.map((e) => [e.item.id, e]))
    const out: Group[] = []
    const fav = favs.map((id) => byId.get(id)).filter((e): e is MenuEntry => !!e)
    if (fav.length) out.push({ label: 'Favourites', rows: fav.map((e) => row('f', e)) })
    const rec = recent.map((id) => byId.get(id)).filter((e): e is MenuEntry => !!e)
    if (rec.length) out.push({ label: 'Recently used', rows: rec.map((e) => row('r', e)) })
    for (const s of SECTION_ORDER) {
      const rows = entries.filter((e) => e.item.section === s).map((e) => row(s, e))
      if (rows.length) out.push({ label: SECTION_LABEL[s], rows })
    }
    return out
  }, [host, role, query, favs, recent])
  const flat = useMemo(() => groups.flatMap((g) => g.rows), [groups])
  const activeIndex = Math.min(active, Math.max(flat.length - 1, 0))

  const place = useCallback(() => {
    const r = btnRef.current?.getBoundingClientRect()
    if (!r) return
    const left = Math.max(8, Math.min(r.right - POP_WIDTH, window.innerWidth - POP_WIDTH - 8))
    const top = r.bottom + 4
    setPos({ top, left, maxHeight: Math.max(220, window.innerHeight - top - 12) })
  }, [])

  const close = useCallback((focusButton = true) => {
    setOpen(false)
    setQuery('')
    setActive(0)
    if (focusButton) btnRef.current?.focus()
  }, [])

  useLayoutEffect(() => {
    if (open) place()
  }, [open, place])

  useEffect(() => {
    if (!open) return
    const down = (e: MouseEvent) => {
      const t = e.target as Node
      if (popRef.current?.contains(t) || btnRef.current?.contains(t)) return
      close(false)
    }
    const reflow = () => place()
    document.addEventListener('mousedown', down)
    window.addEventListener('resize', reflow)
    window.addEventListener('scroll', reflow, true)
    return () => {
      document.removeEventListener('mousedown', down)
      window.removeEventListener('resize', reflow)
      window.removeEventListener('scroll', reflow, true)
    }
  }, [open, close, place])

  // The popup mounts once it has a position, so focus the search box then.
  const placed = pos !== null
  useEffect(() => {
    if (open && placed) inputRef.current?.focus()
  }, [open, placed])

  useEffect(() => {
    if (!open) return
    popRef.current?.querySelector('[data-active="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [open, activeIndex, flat.length])

  const enc = encodeURIComponent(host.id)
  const run = (e: MenuEntry) => {
    if (e.availability.state !== 'enabled') return
    const next = pushRecent(recent, e.item.id)
    setRecent(next)
    writeList(RECENT_KEY, next)
    close(false)
    const a = e.item.action(host)
    switch (a.kind) {
      case 'command':
        setPending({ kind: 'command', request: { type: a.type, params: {} } as CommandRequest })
        break
      case 'power':
        setPending({ kind: 'power', type: a.type })
        break
      case 'form':
        navigate(`/hosts/${enc}?tab=actions&focus=${a.anchor}`)
        break
      case 'search':
        navigate(`/search?q=${encodeURIComponent(`host.id:${host.id}`)}`)
        break
      case 'applications':
        navigate(`/hosts/${enc}?tab=applications`)
        break
      default:
        setPending({ kind: a.kind })
    }
  }

  const toggleFav = (id: string) => {
    const next = toggleFavourite(favs, id)
    setFavs(next)
    writeList(FAVOURITES_KEY, next)
  }

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault()
      e.stopPropagation()
      close()
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      if (flat.length) setActive((activeIndex + (e.key === 'ArrowDown' ? 1 : -1) + flat.length) % flat.length)
    } else if (e.key === 'Home' || e.key === 'End') {
      if (e.ctrlKey || !query) {
        e.preventDefault()
        setActive(e.key === 'Home' ? 0 : Math.max(flat.length - 1, 0))
      }
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const r = flat[activeIndex]
      if (r) run(r.entry)
    } else if (e.key === 'Tab') {
      close(false)
    }
  }

  return (
    <div onClick={(e) => e.stopPropagation()} style={{ display: 'inline-block' }}>
      <button
        ref={btnRef}
        type="button"
        className={small ? 'btn sm' : 'btn'}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => (open ? close() : setOpen(true))}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' && !open) {
            e.preventDefault()
            setOpen(true)
          }
        }}
      >
        Actions <Icon name="chevronDown" size={11} />
      </button>
      {open && pos
        ? createPortal(
            <div
              ref={popRef}
              className="menu-pop host-actions-pop"
              style={{ position: 'fixed', top: pos.top, left: pos.left, width: POP_WIDTH, maxHeight: pos.maxHeight, right: 'auto' }}
              onKeyDown={onKey}
            >
              <input
                ref={inputRef}
                type="search"
                className="input"
                placeholder={`Search actions for ${host.hostname}`}
                aria-label="Search actions"
                role="combobox"
                aria-expanded="true"
                aria-controls={listId}
                aria-activedescendant={flat[activeIndex] ? `${listId}-${flat[activeIndex].key}` : undefined}
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value)
                  setActive(0)
                }}
              />
              <div id={listId} role="listbox" aria-label="Actions" className="host-actions-list">
                {groups.length === 0 ? <div className="menu-label">No action matches &ldquo;{query}&rdquo;</div> : null}
                {groups.map((g) => (
                  <div key={g.label} role="group" aria-label={g.label}>
                    <div className="menu-label">{g.label}</div>
                    {g.rows.map((r) => {
                      const idx = flat.indexOf(r)
                      const dis = r.entry.availability.state === 'disabled'
                      const reason = r.entry.availability.state === 'disabled' ? r.entry.availability.reason : undefined
                      const isFav = favs.includes(r.entry.item.id)
                      const danger = r.entry.item.section === 'danger'
                      return (
                        <div
                          key={r.key}
                          id={`${listId}-${r.key}`}
                          role="option"
                          aria-selected={idx === activeIndex}
                          aria-disabled={dis}
                          data-active={idx === activeIndex}
                          title={reason}
                          className={`menu-item host-action-item${idx === activeIndex ? ' active' : ''}${dis ? ' disabled' : ''}${danger ? ' danger' : ''}`}
                          onMouseMove={() => setActive(idx)}
                          onClick={() => run(r.entry)}
                        >
                          <span className="grow" style={{ minWidth: 0 }}>
                            {r.entry.label}
                            {dis ? <span className="xsmall muted" style={{ display: 'block' }}>{reason}</span> : null}
                          </span>
                          {r.hint ? <span className="xsmall faint">{r.hint}</span> : null}
                          <button
                            type="button"
                            tabIndex={-1}
                            className={`star${isFav ? ' on' : ''}`}
                            aria-pressed={isFav}
                            aria-label={`${isFav ? 'Remove' : 'Add'} ${r.entry.label} ${isFav ? 'from' : 'to'} favourites`}
                            title={isFav ? 'Remove from favourites' : 'Add to favourites'}
                            onClick={(e) => {
                              e.stopPropagation()
                              toggleFav(r.entry.item.id)
                            }}
                          >
                            {isFav ? '★' : '☆'}
                          </button>
                        </div>
                      )
                    })}
                  </div>
                ))}
              </div>
            </div>,
            document.body,
          )
        : null}
      {pending ? <HostActionDialogs host={host} pending={pending} onClose={() => setPending(null)} /> : null}
    </div>
  )
}

/** The dialog for whichever action was picked. Mounted only while one is open. */
function HostActionDialogs({ host, pending, onClose }: { host: Host; pending: Pending; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const navigate = useNavigate()
  const [delay, setDelay] = useState(POWER_DEFAULT_DELAY)
  const [message, setMessage] = useState('')

  const refresh = () => {
    qc.invalidateQueries({ queryKey: queryKeys.hosts() })
    qc.invalidateQueries({ queryKey: queryKeys.host(host.id) })
  }
  const updateNow = useMutation({ mutationFn: () => api.updateHostNow(host.id), onSuccess: refresh })
  const decommission = useMutation({ mutationFn: () => api.decommissionHost(host.id), onSuccess: refresh })
  const recommission = useMutation({ mutationFn: () => api.recommissionHost(host.id), onSuccess: refresh })

  switch (pending.kind) {
    case 'command':
      return (
        <ActionConfirmDialog
          host={host}
          request={pending.request}
          onClose={onClose}
          onDone={() => {
            // agent.logs ends as a file download, which lives on the Commands tab.
            if (pending.request.type === 'agent.logs') navigate(`/hosts/${encodeURIComponent(host.id)}?tab=commands`)
          }}
        />
      )
    case 'power': {
      const request: CommandRequest = { type: pending.type, params: { delay_sec: delay, ...(message.trim() ? { message: message.trim() } : {}) } }
      return (
        <ActionConfirmDialog host={host} request={request} onClose={onClose}>
          <div className="stack" style={{ gap: 10 }}>
            {isUnraid(host) ? (
              <div className="callout danger" role="alert">
                <Icon name="warning" size={14} />
                <span>
                  {host.hostname} runs Unraid: the array will be stopped first. Docker containers and VMs on it go down, and a {pending.type === 'host.reboot' ? 'reboot' : 'shutdown'} during a parity check interrupts the check.
                </span>
              </div>
            ) : null}
            <div className="field">
              <label htmlFor="pw-delay">When</label>
              <select id="pw-delay" className="select" value={delay} onChange={(e) => setDelay(Number(e.target.value))}>
                {(DELAYS.includes(delay) ? DELAYS : [...DELAYS, delay]).map((d) => (
                  <option key={d} value={d}>
                    {d === 0 ? 'Immediately' : `After ${formatDelay(d).replace(/^in /, '')}`}
                  </option>
                ))}
              </select>
              <span className="help">A delay gives people on the host time to save their work.</span>
            </div>
            <div className="field">
              <label htmlFor="pw-msg">Message to users (optional)</label>
              <input id="pw-msg" className="input" maxLength={200} value={message} onChange={(e) => setMessage(e.target.value)} />
            </div>
          </div>
        </ActionConfirmDialog>
      )
    }
    case 'group':
      return (
        <Modal
          open
          onClose={onClose}
          title={`Move ${host.hostname} to a group`}
          footer={
            <button type="button" className="btn primary" onClick={onClose}>
              Done
            </button>
          }
        >
          <HostGroupPicker hostId={host.id} groupId={host.group_id} />
        </Modal>
      )
    case 'rescan':
      return (
        <ConfirmDialog
          open
          onClose={onClose}
          title="Rescan vulnerabilities?"
          confirmLabel="Start rescan"
          onConfirm={async () => {
            const r = await api.rescanHostVulns(host.id)
            toast.success(
              r.started
                ? 'Rescan started for every host (a scan covers all hosts at once); new findings appear on the Vulnerabilities page'
                : 'A scan is already running; its results will include this host',
            )
          }}
        >
          <p>This will:</p>
          <ul className="effect-list">
            <li>Compare the software lists of all hosts, including {host.hostname}, with the vulnerability catalogs again now instead of at the next hourly scan.</li>
            <li>Update the findings on the Vulnerabilities page. It does not contact the host.</li>
          </ul>
        </ConfirmDialog>
      )
    case 'update-now':
      return (
        <ConfirmDialog
          open
          onClose={onClose}
          title={`Update the agent on ${host.hostname} now?`}
          confirmLabel="Update now"
          onConfirm={async () => {
            await updateNow.mutateAsync()
            toast.success('The agent updates when it next checks in')
          }}
        >
          <p>The agent installs its target version at its next check-in, outside the update window and staging.</p>
        </ConfirmDialog>
      )
    case 'decommission':
      return (
        <ConfirmDialog
          open
          onClose={onClose}
          title={`Decommission ${host.hostname}?`}
          confirmLabel="Decommission"
          onConfirm={async () => {
            await decommission.mutateAsync()
            toast.success(`${host.hostname} decommissioned`)
          }}
        >
          <p>The agent is hidden from host lists and counts now. It is restored automatically when it reconnects.</p>
        </ConfirmDialog>
      )
    case 'recommission':
      return (
        <ConfirmDialog
          open
          onClose={onClose}
          title={`Restore ${host.hostname}?`}
          confirmLabel="Restore"
          onConfirm={async () => {
            await recommission.mutateAsync()
            toast.success(`${host.hostname} restored`)
          }}
        >
          <p>The agent shows in host lists and counts again.</p>
        </ConfirmDialog>
      )
    case 'revoke':
      return (
        <ConfirmDialog
          open
          onClose={onClose}
          title={`Revoke ${host.hostname}?`}
          danger
          confirmLabel="Revoke agent"
          onConfirm={async () => {
            await api.revokeHost(host.id)
            refresh()
            toast.success(`${host.hostname} revoked`)
            navigate('/hosts')
          }}
        >
          <p>This will:</p>
          <ul className="effect-list">
            <li>Revoke the client certificate of {host.hostname}; it is rejected on its next connection.</li>
            <li>Stop event collection and response actions for this host. Stored events and alerts are kept.</li>
            <li>Leave the agent installed on the machine. To use it again, uninstall it and re-enroll with a new token.</li>
          </ul>
        </ConfirmDialog>
      )
    case 'remove':
      return <RemoveHostDialog host={host} open onClose={onClose} />
  }
}
