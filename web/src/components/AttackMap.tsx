// The attack origins map: solid country shapes, a red bubble per country sized by attempts,
// zoom (buttons, wheel) and drag to pan. Clicking a country or its bubble opens a card with its
// attempts and block rate.

import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react'
import { COUNTRY_CENTROIDS, countryName } from '../lib/countryCentroids'
import { formatNumber } from '../lib/format'
import { flagEmoji } from '../lib/intel'
import { COUNTRY_SHAPES, MAP_HEIGHT, MAP_LAT_TOP, MAP_WIDTH } from '../lib/worldShapes'
import { Icon } from './Icon'

export interface MapCountry {
  code: string
  attempts: number
  sources: number
  allowed: number
}

const K = MAP_WIDTH / 360
const project = (lat: number, lon: number) => ({ x: (lon + 180) * K, y: (MAP_LAT_TOP - lat) * K })
const MAX_ZOOM = 8

export function AttackMap({
  countries,
  selected,
  onSelect,
  details,
  onDrill,
}: {
  countries: MapCountry[]
  selected: string | null
  onSelect: (code: string | null) => void
  /** Extra lines for the selected country's card. */
  details?: (code: string) => ReactNode
  /** Opens the logs behind a number on the card. */
  onDrill?: (code: string, kind: 'all' | 'blocked' | 'allowed' | 'sources') => void
}) {
  const wrap = useRef<HTMLDivElement>(null)
  const svg = useRef<SVGSVGElement>(null)
  const [view, setView] = useState({ k: 1, x: 0, y: 0 }) // zoom and top-left corner, in map units
  const [card, setCard] = useState<{ code: string; px: number; py: number } | null>(null)
  const drag = useRef<{ sx: number; sy: number; x: number; y: number; moved: boolean } | null>(null)

  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c])), [countries])
  const max = Math.max(1, ...countries.map((c) => c.attempts))

  const clamp = (k: number, x: number, y: number) => {
    const w = MAP_WIDTH / k
    const h = MAP_HEIGHT / k
    return { k, x: Math.min(Math.max(0, x), MAP_WIDTH - w), y: Math.min(Math.max(0, y), MAP_HEIGHT - h) }
  }
  // Zoom around a point given as a fraction of the visible map (0..1).
  const zoomAt = (factor: number, fx = 0.5, fy = 0.5) =>
    setView((v) => {
      const k = Math.min(MAX_ZOOM, Math.max(1, v.k * factor))
      const cx = v.x + (MAP_WIDTH / v.k) * fx
      const cy = v.y + (MAP_HEIGHT / v.k) * fy
      return clamp(k, cx - (MAP_WIDTH / k) * fx, cy - (MAP_HEIGHT / k) * fy)
    })

  useEffect(() => {
    const el = svg.current
    if (!el) return
    const wheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      zoomAt(e.deltaY < 0 ? 1.25 : 0.8, (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height)
    }
    el.addEventListener('wheel', wheel, { passive: false })
    return () => el.removeEventListener('wheel', wheel)
  }, [])

  const onDown = (e: ReactPointerEvent) => {
    drag.current = { sx: e.clientX, sy: e.clientY, x: view.x, y: view.y, moved: false }
  }
  const onMove = (e: ReactPointerEvent) => {
    const d = drag.current
    const el = svg.current
    if (!d || !el) return
    const dx = e.clientX - d.sx
    const dy = e.clientY - d.sy
    if (!d.moved && Math.hypot(dx, dy) < 4) return
    if (!d.moved) el.setPointerCapture(e.pointerId)
    d.moved = true
    const scale = MAP_WIDTH / view.k / el.getBoundingClientRect().width
    setView((v) => clamp(v.k, d.x - dx * scale, d.y - dy * scale))
  }
  const onUp = () => {
    setTimeout(() => (drag.current = null), 0)
  }
  const pick = (code: string, e: React.MouseEvent) => {
    if (drag.current?.moved) return
    e.stopPropagation()
    const r = wrap.current!.getBoundingClientRect()
    if (!byCode.has(code)) {
      setCard(null)
      onSelect(null)
      return
    }
    setCard({ code, px: e.clientX - r.left, py: e.clientY - r.top })
    onSelect(code)
  }

  useEffect(() => {
    if (selected === null) setCard(null)
  }, [selected])

  const vb = `${view.x} ${view.y} ${MAP_WIDTH / view.k} ${MAP_HEIGHT / view.k}`
  const bubbleScale = 1 / Math.sqrt(view.k)
  const sel = card ? byCode.get(card.code) : undefined

  return (
    <div className="attack-map" ref={wrap}>
      <svg
        ref={svg}
        viewBox={vb}
        role="img"
        aria-label="Map of connection attempts by country"
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerLeave={onUp}
        onClick={() => {
          if (!drag.current?.moved) {
            setCard(null)
            onSelect(null)
          }
        }}
        className={view.k > 1 ? 'zoomed' : ''}
      >
        <rect className="ocean" x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} />
        {COUNTRY_SHAPES.map(([code, name, d], i) => {
          const c = byCode.get(code)
          const heat = c ? 0.12 + 0.4 * Math.sqrt(c.attempts / max) : 0
          return (
            <path
              key={i}
              d={d}
              className={['country', c ? 'hit' : '', selected === code ? 'selected' : ''].join(' ')}
              style={c ? { fillOpacity: 1, ['--heat' as string]: heat } : undefined}
              strokeWidth={0.4 / view.k}
              onClick={(e) => pick(code, e)}
            >
              <title>{c ? `${countryName(code)}: ${formatNumber(c.attempts)} attempts` : name}</title>
            </path>
          )
        })}
        {[...countries]
          .filter((c) => COUNTRY_CENTROIDS[c.code])
          .sort((a, b) => b.attempts - a.attempts)
          .map((c) => {
            const [lat, lon] = COUNTRY_CENTROIDS[c.code]
            const p = project(lat, lon)
            const r = (3 + 22 * Math.sqrt(c.attempts / max)) * bubbleScale
            return (
              <circle
                key={c.code}
                className={['bubble', c.allowed > 0 ? 'allowed' : '', selected === c.code ? 'selected' : ''].join(' ')}
                cx={p.x}
                cy={p.y}
                r={r}
                strokeWidth={1 / view.k}
                onClick={(e) => pick(c.code, e)}
                tabIndex={0}
                role="button"
                aria-label={`${countryName(c.code)}: ${formatNumber(c.attempts)} attempts`}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    const r2 = (e.target as Element).getBoundingClientRect()
                    const w = wrap.current!.getBoundingClientRect()
                    setCard({ code: c.code, px: r2.left - w.left + r2.width / 2, py: r2.top - w.top })
                    onSelect(c.code)
                  }
                }}
              />
            )
          })}
      </svg>

      <div className="map-zoom" onClick={(e) => e.stopPropagation()}>
        <button type="button" className="btn sm" onClick={() => zoomAt(1.6)} aria-label="Zoom in" disabled={view.k >= MAX_ZOOM}>
          <Icon name="plus" size={13} />
        </button>
        <button type="button" className="btn sm" onClick={() => zoomAt(1 / 1.6)} aria-label="Zoom out" disabled={view.k <= 1}>
          <span aria-hidden="true" style={{ fontWeight: 700, lineHeight: 1 }}>−</span>
        </button>
        <button type="button" className="btn sm" onClick={() => setView({ k: 1, x: 0, y: 0 })} aria-label="Reset the map" disabled={view.k === 1}>
          <Icon name="refresh" size={13} />
        </button>
      </div>

      {card && sel ? (
        <div
          className={card.py < 200 ? 'map-card below' : 'map-card'}
          style={{ left: Math.min(Math.max(card.px, 130), (wrap.current?.clientWidth ?? 600) - 130), top: card.py }}
          onClick={(e) => e.stopPropagation()}
          role="dialog"
          aria-label={`${countryName(card.code)} details`}
        >
          <div className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
            <strong>
              {flagEmoji(card.code)} {countryName(card.code)}
            </strong>
            <button type="button" className="btn ghost sm" aria-label="Close" onClick={() => onSelect(null)}>
              <Icon name="close" size={12} />
            </button>
          </div>
          <dl className="map-card-stats">
            <dt>Attempts</dt>
            <dd>
              <Num value={formatNumber(sel.attempts)} title="Show these connections" onClick={onDrill && (() => onDrill(card.code, 'all'))} />
            </dd>
            <dt>Blocked</dt>
            <dd className={sel.allowed ? 'danger-text' : 'ok-text'}>
              <Num
                value={`${(((sel.attempts - sel.allowed) / sel.attempts) * 100).toFixed(sel.allowed ? 2 : 0)}%`}
                title="Show the blocked connections"
                onClick={onDrill && (() => onDrill(card.code, 'blocked'))}
              />
            </dd>
            <dt>Sources</dt>
            <dd>
              <Num value={formatNumber(sel.sources)} title="Show the sources" onClick={onDrill && (() => onDrill(card.code, 'sources'))} />
            </dd>
            <dt>Let in</dt>
            <dd className={sel.allowed ? 'danger-text' : undefined}>
              <Num
                value={formatNumber(sel.allowed)}
                title="Show the connections let in"
                onClick={sel.allowed && onDrill ? () => onDrill(card.code, 'allowed') : undefined}
              />
            </dd>
          </dl>
          {details ? details(card.code) : null}
        </div>
      ) : null}
    </div>
  )
}

/** A number on the card that opens its logs when clicked. */
function Num({ value, title, onClick }: { value: string; title: string; onClick?: () => void }) {
  if (!onClick) return <>{value}</>
  return (
    <button type="button" className="map-num" title={title} onClick={onClick}>
      {value}
    </button>
  )
}
