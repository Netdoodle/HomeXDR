// The attack origins map: the world in the Natural Earth projection, one bubble per country
// sized by attempts and colored by the worst IDS severity seen from it, labels on the top five,
// a hover tooltip, zoom (buttons, wheel) and drag to pan. Clicking a country or its bubble
// opens a card. "Live" adds a pulse on countries active in the last five minutes and arcs
// from the busiest countries to home.

import { useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react'
import { COUNTRY_CENTROIDS, countryName } from '../lib/countryCentroids'
import { formatCount, formatNumber } from '../lib/format'
import { flagEmoji } from '../lib/intel'
import { COUNTRY_SHAPES, MAP_HEIGHT, MAP_WIDTH, project, WORLD_OUTLINE } from '../lib/worldShapes'
import { RelTime } from './Misc'
import { Icon } from './Icon'

export interface MapCountry {
  code: string
  attempts: number
  sources: number
  allowed: number
  /** Newest attempt, for the live pulse. */
  last?: string
  /** Worst IDS alert from the country, for the bubble color. */
  severity?: 'high' | 'medium' | 'low'
}

const MAX_ZOOM = 8
const LIVE_WINDOW_MS = 5 * 60_000
const SEVERITY_COLOR = { high: '#e5484d', medium: '#f08c3a', low: '#f5c542', none: '#8fa3bf' } as const
const LIVE_KEY = 'hx.threatmap.live'

function readLive(): boolean {
  try {
    return localStorage.getItem(LIVE_KEY) === '1'
  } catch {
    return false
  }
}

function writeLive(on: boolean) {
  try {
    localStorage.setItem(LIVE_KEY, on ? '1' : '0')
  } catch {
    // private window or blocked storage: the toggle just isn't remembered
  }
}

/** 950, 9.4K, 18K, 1.2M: short enough for a map label. */
function shortCount(n: number): string {
  if (n < 1000) return String(n)
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}K`
  return `${(n / 1_000_000).toFixed(1)}M`
}

/** A round number near v for the size legend. */
function niceStep(v: number): number {
  if (v <= 1) return 1
  const e = Math.pow(10, Math.floor(Math.log10(v)))
  const f = v / e
  return (f >= 5 ? 5 : f >= 2 ? 2 : 1) * e
}

export function AttackMap({
  countries,
  selected,
  onSelect,
  details,
  onDrill,
  slices,
  cardBody,
  unit = 'attempts',
  home,
}: {
  countries: MapCountry[]
  selected: string | null
  onSelect: (code: string | null) => void
  /** Extra lines for the selected country's card. */
  details?: (code: string) => ReactNode
  /** Pie slices per country (IDS mode): the bubble is split by category. */
  slices?: Map<string, { key: string; value: number; color: string }[]>
  /** Replaces the card's numbers (IDS mode). */
  cardBody?: (code: string) => ReactNode
  /** Opens the logs behind a number on the card. */
  onDrill?: (code: string, kind: 'all' | 'blocked' | 'allowed' | 'sources') => void
  /** What the bubbles count, for labels and the legend. */
  unit?: string
  /** Where the live arcs end: the country of the firewall's own address. */
  home?: string
}) {
  const wrap = useRef<HTMLDivElement>(null)
  const svg = useRef<SVGSVGElement>(null)
  const [view, setView] = useState({ k: 1, x: 0, y: 0 }) // zoom and top-left corner, in map units
  const [card, setCard] = useState<{ code: string; px: number; py: number } | null>(null)
  const [hover, setHover] = useState<{ code: string; px: number; py: number } | null>(null)
  const [live, setLive] = useState(readLive)
  const drag = useRef<{ sx: number; sy: number; x: number; y: number; moved: boolean } | null>(null)

  const byCode = useMemo(() => new Map(countries.map((c) => [c.code, c])), [countries])
  const placed = useMemo(
    () => countries.filter((c) => COUNTRY_CENTROIDS[c.code] && c.attempts > 0).sort((a, b) => b.attempts - a.attempts),
    [countries],
  )
  const max = Math.max(1, ...placed.map((c) => c.attempts))
  const radius = (n: number) => (1.4 + 16.6 * Math.sqrt(n / max)) / Math.sqrt(view.k)
  const point = (code: string) => {
    const [lat, lon] = COUNTRY_CENTROIDS[code]
    return project(lat, lon)
  }

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
    setHover(null)
    const scale = MAP_WIDTH / view.k / el.getBoundingClientRect().width
    setView((v) => clamp(v.k, d.x - dx * scale, d.y - dy * scale))
  }
  const onUp = () => {
    setTimeout(() => (drag.current = null), 0)
  }
  const local = (e: { clientX: number; clientY: number }) => {
    const r = wrap.current!.getBoundingClientRect()
    return { px: e.clientX - r.left, py: e.clientY - r.top }
  }
  const pick = (code: string, e: React.MouseEvent) => {
    if (drag.current?.moved) return
    e.stopPropagation()
    if (!byCode.has(code)) {
      setCard(null)
      onSelect(null)
      return
    }
    setHover(null)
    setCard({ code, ...local(e) })
    onSelect(code)
  }
  const hoverOn = (code: string, e: React.MouseEvent) => {
    if (drag.current?.moved || card) return
    setHover({ code, ...local(e) })
  }

  useEffect(() => {
    if (selected === null) setCard(null)
  }, [selected])

  const vb = `${view.x} ${view.y} ${MAP_WIDTH / view.k} ${MAP_HEIGHT / view.k}`
  const sel = card ? byCode.get(card.code) : undefined
  const hov = hover ? byCode.get(hover.code) : undefined
  const now = Date.now()
  // Labels for the top five, moved down when they would overlap one already placed.
  const labels: { code: string; text: string; x: number; y: number }[] = []
  {
    const fs = 9 / view.k
    const boxes: { x0: number; x1: number; y0: number; y1: number }[] = []
    for (const c of placed.slice(0, 5)) {
      const p = point(c.code)
      const text = `${c.code} ${shortCount(c.attempts)}`
      const x = p.x + radius(c.attempts) + 2 / view.k
      const w = text.length * fs * 0.6
      let y = p.y + fs / 3
      for (let tries = 0; tries < 6 && boxes.some((b) => x < b.x1 && x + w > b.x0 && y - fs < b.y1 && y > b.y0); tries++) y += fs * 1.15
      boxes.push({ x0: x, x1: x + w, y0: y - fs, y1: y })
      labels.push({ code: c.code, text, x, y })
    }
  }
  const homePoint = home && COUNTRY_CENTROIDS[home] ? point(home) : null
  const arcs = live && homePoint ? placed.filter((c) => c.code !== home).slice(0, 8) : []
  const legendSizes = [niceStep(max), niceStep(max / 10), niceStep(max / 100)].filter((v, i, a) => v >= 1 && a.indexOf(v) === i)
  const colorOf = (c: MapCountry) => SEVERITY_COLOR[c.severity ?? 'none']

  return (
    <div className="attack-map" ref={wrap}>
      <svg
        ref={svg}
        viewBox={vb}
        role="img"
        aria-label={`Map of ${unit} by country`}
        onPointerDown={onDown}
        onPointerMove={onMove}
        onPointerUp={onUp}
        onPointerLeave={() => {
          onUp()
          setHover(null)
        }}
        onClick={() => {
          if (!drag.current?.moved) {
            setCard(null)
            onSelect(null)
          }
        }}
        className={view.k > 1 ? 'zoomed' : ''}
      >
        <defs>
          <clipPath id="hx-world-clip">
            <path d={WORLD_OUTLINE} />
          </clipPath>
        </defs>
        <path className="ocean" d={WORLD_OUTLINE} />
        <g clipPath="url(#hx-world-clip)">
          {COUNTRY_SHAPES.map(([code, name, d], i) => (
            <path
              key={i}
              d={d}
              className={['country', byCode.has(code) ? 'hit' : '', selected === code ? 'selected' : ''].join(' ')}
              strokeWidth={0.45 / view.k}
              onClick={(e) => pick(code, e)}
              onMouseMove={(e) => (byCode.has(code) ? hoverOn(code, e) : setHover(null))}
            >
              {byCode.has(code) ? null : <title>{name}</title>}
            </path>
          ))}
        </g>
        <path className="outline" d={WORLD_OUTLINE} strokeWidth={0.8 / view.k} />

        {arcs.map((c) => {
          const a = point(c.code)
          const b = homePoint!
          const mx = (a.x + b.x) / 2
          const my = (a.y + b.y) / 2 - Math.hypot(b.x - a.x, b.y - a.y) * 0.25
          return (
            <path
              key={`arc-${c.code}`}
              className="arc"
              d={`M${a.x} ${a.y}Q${mx} ${my} ${b.x} ${b.y}`}
              stroke={colorOf(c)}
              strokeWidth={(0.6 + 1.6 * Math.sqrt(c.attempts / max)) / view.k}
            />
          )
        })}

        {placed.map((c) => {
          const p = point(c.code)
          const r = radius(c.attempts)
          const recent = live && c.last && now - new Date(c.last).getTime() < LIVE_WINDOW_MS
          const parts = slices?.get(c.code)
          const common = {
            onClick: (e: React.MouseEvent) => pick(c.code, e),
            onMouseMove: (e: React.MouseEvent) => hoverOn(c.code, e),
            onMouseLeave: () => setHover(null),
            tabIndex: 0,
            role: 'button' as const,
            'aria-label': `${countryName(c.code)}: ${formatNumber(c.attempts)} ${unit}`,
            onKeyDown: (e: React.KeyboardEvent) => {
              if (e.key === 'Enter') {
                const r2 = (e.target as Element).getBoundingClientRect()
                const w = wrap.current!.getBoundingClientRect()
                setCard({ code: c.code, px: r2.left - w.left + r2.width / 2, py: r2.top - w.top })
                onSelect(c.code)
              }
            },
          }
          return (
            <g key={c.code} className={['bubble-g', selected === c.code ? 'selected' : ''].join(' ')}>
              {recent ? (
                <circle className="pulse" cx={p.x} cy={p.y} r={r} fill={colorOf(c)}>
                  <animate attributeName="r" from={r} to={r * 2.6} dur="1.8s" repeatCount="indefinite" />
                  <animate attributeName="opacity" from="0.55" to="0" dur="1.8s" repeatCount="indefinite" />
                </circle>
              ) : null}
              {parts && parts.length ? (
                <g className="pie" {...common}>
                  {parts.length === 1 ? (
                    <circle cx={p.x} cy={p.y} r={r} fill={parts[0].color} strokeWidth={0.5 / view.k} />
                  ) : (
                    (() => {
                      const total = parts.reduce((n, s) => n + s.value, 0) || 1
                      let a0 = -Math.PI / 2
                      return parts.map((s) => {
                        const a1 = a0 + (s.value / total) * Math.PI * 2
                        const large = a1 - a0 > Math.PI ? 1 : 0
                        const d = `M${p.x} ${p.y}L${p.x + r * Math.cos(a0)} ${p.y + r * Math.sin(a0)}A${r} ${r} 0 ${large} 1 ${p.x + r * Math.cos(a1)} ${p.y + r * Math.sin(a1)}Z`
                        a0 = a1
                        return <path key={s.key} d={d} fill={s.color} strokeWidth={0.4 / view.k} />
                      })
                    })()
                  )}
                </g>
              ) : (
                <circle
                  className={['bubble', c.allowed > 0 ? 'allowed' : ''].join(' ')}
                  cx={p.x}
                  cy={p.y}
                  r={r}
                  fill={colorOf(c)}
                  strokeWidth={(c.allowed > 0 ? 1.4 : 0.5) / view.k}
                  {...common}
                />
              )}
            </g>
          )
        })}

        {labels.map((l) => (
          <text key={`label-${l.code}`} className="map-label" x={l.x} y={l.y} fontSize={9 / view.k} strokeWidth={2.4 / view.k}>
            {l.text}
          </text>
        ))}
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

      <button
        type="button"
        className={live ? 'btn sm map-live on' : 'btn sm map-live'}
        aria-pressed={live}
        title="Pulse countries active in the last 5 minutes and draw arcs from the busiest to home"
        onClick={(e) => {
          e.stopPropagation()
          setLive(!live)
          writeLive(!live)
        }}
      >
        <span className="live-dot" aria-hidden="true" /> Live
      </button>

      {hover && hov && !card ? (
        <div className="map-tip" style={{ left: hover.px, top: hover.py }}>
          <strong>
            {flagEmoji(hover.code)} {countryName(hover.code)}
          </strong>
          <div>
            {formatNumber(hov.attempts)} {unit}
            {unit === 'attempts' && hov.attempts ? ` · ${(((hov.attempts - hov.allowed) / hov.attempts) * 100).toFixed(hov.allowed ? 2 : 0)}% blocked` : ''}
          </div>
          <div className="muted">
            {formatNumber(hov.sources)} sources{hov.last ? <>, last <RelTime iso={hov.last} /></> : null}
          </div>
        </div>
      ) : null}

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
          {cardBody ? (
            cardBody(card.code)
          ) : (
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
          )}
          {details ? details(card.code) : null}
        </div>
      ) : null}

      <div className="map-legend" aria-label="Map legend">
        <span className="legend-group">
          {legendSizes.map((n) => {
            const r = 1.4 + 16.6 * Math.sqrt(n / max)
            const px = Math.max(4, r * 1.25)
            return (
              <span key={n} className="legend-size">
                <span className="legend-circle" style={{ width: px * 2, height: px * 2 }} />
                {formatCount(n)}
              </span>
            )
          })}
          <span className="muted">{unit}</span>
        </span>
        {slices ? null : (
          <span className="legend-group">
            <span>
              <span className="cat-dot" style={{ background: SEVERITY_COLOR.high }} />
              high-severity IDS alerts
            </span>
            <span>
              <span className="cat-dot" style={{ background: SEVERITY_COLOR.medium }} />
              medium
            </span>
            <span>
              <span className="cat-dot" style={{ background: SEVERITY_COLOR.low }} />
              low
            </span>
            <span>
              <span className="cat-dot" style={{ background: SEVERITY_COLOR.none }} />
              no IDS alerts
            </span>
            <span>
              <span className="cat-dot ring" />
              connections let in
            </span>
          </span>
        )}
      </div>
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
