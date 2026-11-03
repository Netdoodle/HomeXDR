// Renders a JSON object (usually an Event) as a collapsible tree of dotted fields.
// Leaf values can be clicked to add `field:value` to a search query.

import { useState } from 'react'
import { Link } from 'react-router'
import { indicatorInField, investigateHref } from '../lib/intel'
import { Icon } from './Icon'

export interface FieldTreeProps {
  value: unknown
  /** Called with the dotted ECS path and the clicked leaf value. */
  onFilter?: (path: string, value: string | number | boolean, negate: boolean) => void
  /** Branches deeper than this start collapsed. */
  openDepth?: number
  /** Keys to sort first at the top level. */
  priority?: string[]
}

const DEFAULT_PRIORITY = ['@timestamp', 'id', 'message', 'event', 'host', 'process', 'user']

function sortKeys(keys: string[], priority: string[]): string[] {
  return [...keys].sort((a, b) => {
    const ia = priority.indexOf(a)
    const ib = priority.indexOf(b)
    if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
    return a.localeCompare(b)
  })
}

function isBranch(v: unknown): v is Record<string, unknown> | unknown[] {
  if (Array.isArray(v)) return v.some((x) => x !== null && typeof x === 'object')
  return v !== null && typeof v === 'object'
}

function Leaf({
  path,
  value,
  onFilter,
}: {
  path: string
  value: unknown
  onFilter?: FieldTreeProps['onFilter']
}) {
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="fval null">[]</span>
    return (
      <span className="fval">
        [
        {value.map((v, i) => (
          <span key={i}>
            {i > 0 ? ', ' : ''}
            <Leaf path={path} value={v} onFilter={onFilter} />
          </span>
        ))}
        ]
      </span>
    )
  }
  if (value === null || value === undefined) return <span className="fval null">null</span>
  const t = typeof value
  const cls = t === 'string' ? 'string' : t === 'number' ? 'number' : t === 'boolean' ? 'boolean' : ''
  const text = t === 'string' ? (value as string) : String(value)
  if (onFilter && (t === 'string' || t === 'number' || t === 'boolean')) {
    return (
      <button
        type="button"
        className={`fval ${cls}`}
        title={`Add ${path}:${text} to the query (Alt-click to exclude)`}
        onClick={(e) => onFilter(path, value as string | number | boolean, e.altKey)}
      >
        {text}
      </button>
    )
  }
  return <span className={`fval ${cls}`}>{text}</span>
}

function Branch({
  name,
  path,
  value,
  depth,
  openDepth,
  onFilter,
  priority,
}: {
  name: string
  path: string
  value: unknown
  depth: number
  openDepth: number
  onFilter?: FieldTreeProps['onFilter']
  priority: string[]
}) {
  const [open, setOpen] = useState(depth < openDepth)
  if (!isBranch(value)) {
    const leafValue = value
    return (
      <li>
        <div className="frow">
          <span className="fkey">
            <span className="caret" />
            {name}:
          </span>
          <Leaf path={path} value={leafValue} onFilter={onFilter} />
          {onFilter && leafValue !== null && typeof leafValue !== 'object' ? (
            <span className="factions">
              {indicatorInField(path, leafValue) ? (
                <Link to={investigateHref(indicatorInField(path, leafValue)!)} title="Investigate this indicator" aria-label={`Investigate ${String(leafValue)}`}>
                  <Icon name="radar" size={12} />
                </Link>
              ) : null}
              <button type="button" onClick={() => onFilter(path, leafValue as string, false)} title="Filter for value">
                +
              </button>
              <button type="button" onClick={() => onFilter(path, leafValue as string, true)} title="Filter out value">
                −
              </button>
            </span>
          ) : null}
        </div>
      </li>
    )
  }
  const entries: [string, unknown][] = Array.isArray(value)
    ? value.map((v, i) => [String(i), v])
    : sortKeys(Object.keys(value), depth === 0 ? priority : []).map((k) => [k, (value as Record<string, unknown>)[k]])
  const summary = Array.isArray(value) ? `[${value.length}]` : `{${entries.length}}`
  return (
    <li>
      <div className="frow">
        <span
          className="fkey branch"
          role="button"
          tabIndex={0}
          aria-expanded={open}
          onClick={() => setOpen(!open)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setOpen(!open)
            }
          }}
        >
          <span className={open ? 'caret open' : 'caret'}>
            <Icon name="chevronRight" size={10} />
          </span>
          {name}
        </span>
        {!open ? <span className="fmeta">{summary}</span> : null}
      </div>
      {open ? (
        <ul>
          {entries.map(([k, v]) => (
            <Branch
              key={k}
              name={k}
              // Array indices are not part of ECS paths.
              path={Array.isArray(value) ? path : `${path}.${k}`}
              value={v}
              depth={depth + 1}
              openDepth={openDepth}
              onFilter={onFilter}
              priority={priority}
            />
          ))}
        </ul>
      ) : null}
    </li>
  )
}

export function FieldTree({ value, onFilter, openDepth = 2, priority = DEFAULT_PRIORITY }: FieldTreeProps) {
  if (value === null || typeof value !== 'object') {
    return (
      <div className="ftree">
        <Leaf path="" value={value} />
      </div>
    )
  }
  const keys = sortKeys(Object.keys(value as Record<string, unknown>), priority)
  return (
    <div className="ftree">
      <ul>
        {keys.map((k) => (
          <Branch
            key={k}
            name={k}
            path={k}
            value={(value as Record<string, unknown>)[k]}
            depth={1}
            openDepth={openDepth}
            onFilter={onFilter}
            priority={priority}
          />
        ))}
      </ul>
    </div>
  )
}
