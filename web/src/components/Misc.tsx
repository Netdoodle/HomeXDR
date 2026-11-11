// Small shared widgets: expandable text, copy button, relative time, pager, tabs,
// label editor.

import { useEffect, useState, type KeyboardEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { formatDateTime, formatRelative, formatTimestamp } from '../lib/time'
import { formatNumber } from '../lib/format'
import { Icon, type IconName } from './Icon'

/** Monospace text that is clipped to `max` characters until expanded. */
export function ExpandableText({ text, max = 160, className = 'cmdline' }: { text?: string; max?: number; className?: string }) {
  const [open, setOpen] = useState(false)
  if (!text) return <span className="empty-cell">—</span>
  const long = text.length > max
  return (
    <span className="expandable">
      <span className={className}>{open || !long ? text : text.slice(0, max) + '…'}</span>
      {long ? (
        <button type="button" className="linklike toggle-more" onClick={() => setOpen(!open)}>
          {open ? 'less' : `more (${formatNumber(text.length)} chars)`}
        </button>
      ) : null}
    </span>
  )
}

export function CopyButton({ text, label = 'Copy', small }: { text: string; label?: string; small?: boolean }) {
  const [done, setDone] = useState(false)
  useEffect(() => {
    if (!done) return
    const t = setTimeout(() => setDone(false), 1500)
    return () => clearTimeout(t)
  }, [done])
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      // Clipboard API needs a secure context; fall back to a hidden textarea.
      const ta = document.createElement('textarea')
      ta.value = text
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      ta.remove()
    }
    setDone(true)
  }
  return (
    <button type="button" className={small ? 'btn sm' : 'btn'} onClick={copy} aria-live="polite">
      <Icon name={done ? 'check' : 'copy'} size={14} />
      {done ? 'Copied' : label}
    </button>
  )
}

/** Relative time with the absolute timestamp on hover. Re-renders every 30s. */
export function RelTime({ iso, absolute }: { iso?: string; absolute?: boolean }) {
  const [, tick] = useState(0)
  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 30_000)
    return () => clearInterval(t)
  }, [])
  if (!iso) return <span className="empty-cell">—</span>
  return (
    <time dateTime={iso} title={formatTimestamp(iso)} className="nowrap">
      {absolute ? formatDateTime(iso) : formatRelative(iso)}
    </time>
  )
}

export function Pager({
  offset,
  limit,
  total,
  shown,
  onChange,
}: {
  offset: number
  limit: number
  total?: number
  shown: number
  onChange: (offset: number) => void
}) {
  const end = offset + shown
  const hasNext = total !== undefined ? end < total : shown === limit
  return (
    <div className="pager">
      <span className="num">
        {shown === 0 ? 'No results' : `${formatNumber(offset + 1)}–${formatNumber(end)}`}
        {total !== undefined ? ` of ${formatNumber(total)}` : ''}
      </span>
      <span className="row">
        <button type="button" className="btn sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
          <Icon name="chevronLeft" size={12} /> Prev
        </button>
        <button type="button" className="btn sm" disabled={!hasNext} onClick={() => onChange(offset + limit)}>
          Next <Icon name="chevronRight" size={12} />
        </button>
      </span>
    </div>
  )
}

export interface TabDef {
  id: string
  label: ReactNode
  icon?: IconName
}

/** Tabs that are links (so they are bookmarkable). `href(id)` builds the URL. */
export function LinkTabs({ tabs, active, href }: { tabs: TabDef[]; active: string; href: (id: string) => string }) {
  return (
    <nav className="tabs" aria-label="Sections">
      {tabs.map((t) => (
        <Link key={t.id} to={href(t.id)} className={t.id === active ? 'active' : undefined} aria-current={t.id === active ? 'page' : undefined}>
          {t.icon ? <Icon name={t.icon} size={14} /> : null}
          {t.label}
        </Link>
      ))}
    </nav>
  )
}

export function ButtonTabs({ tabs, active, onChange }: { tabs: TabDef[]; active: string; onChange: (id: string) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={t.id === active}
          className={t.id === active ? 'active' : undefined}
          onClick={() => onChange(t.id)}
        >
          {t.icon ? <Icon name={t.icon} size={14} /> : null}
          {t.label}
        </button>
      ))}
    </div>
  )
}

/** Editable list of labels. Calls onSave with the new list; disabled when !canEdit. */
export function LabelEditor({
  labels,
  onSave,
  canEdit,
  saving,
  suggestions = [],
}: {
  labels: string[]
  onSave: (labels: string[]) => void
  canEdit: boolean
  saving?: boolean
  suggestions?: string[]
}) {
  const [draft, setDraft] = useState('')
  const add = () => {
    const v = draft.trim().toLowerCase()
    if (!v) return
    if (!/^[a-z0-9][a-z0-9_.:-]{0,62}$/.test(v)) return
    if (!labels.includes(v)) onSave([...labels, v])
    setDraft('')
  }
  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      add()
    }
  }
  const invalid = draft.trim() !== '' && !/^[a-z0-9][a-z0-9_.:-]{0,62}$/.test(draft.trim().toLowerCase())
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="tags">
        {labels.length === 0 ? <span className="muted small">No labels</span> : null}
        {labels.map((l) => (
          <span key={l} className="tag">
            {l}
            {canEdit ? (
              <button type="button" aria-label={`Remove label ${l}`} onClick={() => onSave(labels.filter((x) => x !== l))} disabled={saving}>
                ×
              </button>
            ) : null}
          </span>
        ))}
      </div>
      {canEdit ? (
        <div className="row">
          <input
            className={invalid ? 'input invalid' : 'input'}
            placeholder="Add label (e.g. server, dmz)"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKey}
            list="label-suggestions"
            disabled={saving}
            aria-label="New label"
            style={{ width: 220 }}
          />
          <datalist id="label-suggestions">
            {suggestions
              .filter((s) => !labels.includes(s))
              .map((s) => (
                <option key={s} value={s} />
              ))}
          </datalist>
          <button type="button" className="btn sm" onClick={add} disabled={saving || !draft.trim() || invalid}>
            <Icon name="plus" size={12} /> Add
          </button>
          {invalid ? <span className="xsmall danger-text">Lowercase letters, digits, - _ . : only</span> : null}
        </div>
      ) : null}
    </div>
  )
}

/** A KV row: label, value, and optionally the text its copy button copies. */
export type KVItem = [ReactNode, ReactNode] | [ReactNode, ReactNode, string | number | undefined | null]

/**
 * Label/value pairs. With copyable, every value that is plain text, or that names its text
 * as the row's third element, gets a copy button.
 */
export function KV({ items, copyable }: { items: KVItem[]; copyable?: boolean }) {
  return (
    <dl className="kv">
      {items.map((item, i) => {
        const [k, v] = item
        const empty = v === undefined || v === null || v === ''
        let text: string | undefined
        if (copyable && !empty) {
          const explicit = item.length > 2 ? item[2] : undefined
          if (explicit !== undefined && explicit !== null && explicit !== '') text = String(explicit)
          else if (item.length < 3 && (typeof v === 'string' || typeof v === 'number')) text = String(v)
        }
        return (
          <div key={i} style={{ display: 'contents' }}>
            <dt>{k}</dt>
            <dd className={text ? 'copy-cell' : undefined}>
              {empty ? <span className="empty-cell">—</span> : v}
              {text ? <CopyIcon text={text} label={typeof k === 'string' ? k : 'value'} /> : null}
            </dd>
          </div>
        )
      })}
    </dl>
  )
}

async function writeClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text)
  } catch {
    // Clipboard API needs a secure context; fall back to a hidden textarea.
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.opacity = '0'
    document.body.appendChild(ta)
    ta.select()
    document.execCommand('copy')
    ta.remove()
  }
}

/**
 * A small copy button for one value, shown when its row or cell is hovered or focused.
 * It never triggers the row's own click.
 */
export function CopyIcon({ text, label }: { text: string | undefined | null; label: string }) {
  const [done, setDone] = useState(false)
  useEffect(() => {
    if (!done) return
    const t = setTimeout(() => setDone(false), 1200)
    return () => clearTimeout(t)
  }, [done])
  if (text === undefined || text === null || text === '') return null
  return (
    <button
      type="button"
      className={done ? 'copy-icon done' : 'copy-icon'}
      title={done ? 'Copied' : `Copy ${label.toLowerCase()}`}
      aria-label={`Copy ${label.toLowerCase()}`}
      onClick={(e) => {
        e.stopPropagation()
        e.preventDefault()
        void writeClipboard(text).then(() => setDone(true))
      }}
    >
      <Icon name={done ? 'check' : 'copy'} size={12} />
    </button>
  )
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
}: {
  checked: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
  label: string
}) {
  return (
    <label className="toggle" title={label}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} aria-label={label} />
      <span />
    </label>
  )
}
