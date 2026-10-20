// Hand-rolled SVG charts: a single-series column chart for hourly timelines and a
// horizontal bar list for rankings. Single series, so no legend: the panel title names it.

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { formatCount, formatNumber } from '../lib/format'
import { formatBucketLabel, formatDateTime } from '../lib/time'

/** Tracks an element's content width so the SVG can be drawn at 1:1 pixels. */
export function useWidth<T extends HTMLElement>(fallback: number) {
  const ref = useRef<T>(null)
  const [width, setWidth] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => setWidth(Math.max(120, Math.floor(el.getBoundingClientRect().width)))
    update()
    const ro = new ResizeObserver(update)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width] as const
}

export function niceMax(v: number): number {
  if (v <= 0) return 1
  const exp = Math.pow(10, Math.floor(Math.log10(v)))
  const f = v / exp
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10
  return nice * exp
}

export function ColumnChart({
  data,
  height = 150,
  unit,
  alt,
}: {
  data: { t: string; count: number }[]
  height?: number
  unit: string
  alt?: boolean
}) {
  const [wrapRef, width] = useWidth<HTMLDivElement>(600)
  const [hover, setHover] = useState<number | null>(null)
  const padL = 34
  const padR = 6
  const padT = 8
  const padB = 20
  const max = useMemo(() => niceMax(Math.max(0, ...data.map((d) => d.count))), [data])
  const plotW = width - padL - padR
  const plotH = height - padT - padB
  const n = Math.max(data.length, 1)
  const slot = plotW / n
  const barW = Math.max(1, Math.min(24, slot - 2)) // 2px surface gap between bars
  const ticks = [0, max / 2, max]
  const spanHours = data.length
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(plotW / 64))))

  const y = (v: number) => padT + plotH - (v / max) * plotH

  const tooltipLeft = hover !== null ? padL + slot * hover + slot / 2 : 0
  const tooltipTop = hover !== null ? y(data[hover]?.count ?? 0) : 0

  return (
    <div className="chart" ref={wrapRef}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${unit} per hour`}>
        <g className="axis">
          {ticks.map((t) => (
            <g key={t}>
              <line className="gridline" x1={padL} x2={width - padR} y1={y(t)} y2={y(t)}  />
              <text x={padL - 6} y={y(t) + 3.5} textAnchor="end">
                {formatCount(t)}
              </text>
            </g>
          ))}
          {data.map((d, i) =>
            i % labelEvery === 0 ? (
              <text key={d.t} x={padL + slot * i + slot / 2} y={height - 5} textAnchor="middle">
                {formatBucketLabel(d.t, spanHours)}
              </text>
            ) : null,
          )}
        </g>
        <line className="baseline" x1={padL} x2={width - padR} y1={y(0)} y2={y(0)}  />
        {data.map((d, i) => {
          const h = Math.max(d.count > 0 ? 1.5 : 0, (d.count / max) * plotH)
          const x = padL + slot * i + (slot - barW) / 2
          const r = Math.min(3, barW / 2, h)
          const top = padT + plotH - h
          // rounded data-end, square baseline
          const path =
            h <= 0
              ? ''
              : `M${x},${padT + plotH}V${top + r}Q${x},${top} ${x + r},${top}H${x + barW - r}Q${x + barW},${top} ${x + barW},${top + r}V${padT + plotH}Z`
          return (
            <g key={d.t}>
              {path ? <path d={path} className={`bar${alt ? ' alt' : ''}${hover === i ? ' hover' : ''}`} /> : null}
              <rect
                className="hit"
                x={padL + slot * i}
                y={padT}
                width={slot}
                height={plotH}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover((h2) => (h2 === i ? null : h2))}
              >
                <title>{`${formatDateTime(d.t)}: ${formatNumber(d.count)} ${unit}`}</title>
              </rect>
            </g>
          )
        })}
      </svg>
      {hover !== null && data[hover] ? (
        <div className="chart-tooltip" style={{ left: Math.min(Math.max(tooltipLeft, 60), width - 60), top: tooltipTop }}>
          <div className="muted">{formatDateTime(data[hover].t).slice(0, -3)}</div>
          <strong>{formatNumber(data[hover].count)}</strong> {unit}
        </div>
      ) : null}
    </div>
  )
}

export interface BarListItem {
  key: string
  label: ReactNode
  value: number
  href?: string
  title?: string
  color?: string
}

export function BarList({ items, max }: { items: BarListItem[]; max?: number }) {
  const top = max ?? Math.max(1, ...items.map((i) => i.value))
  return (
    <div className="barlist">
      {items.map((it) => {
        const inner = (
          <>
            <span className="bl-label" title={it.title}>
              {it.label}
            </span>
            <span className="bl-value">{formatNumber(it.value)}</span>
            <span className="bl-track" aria-hidden="true">
              <span
                className="bl-fill"
                style={{ display: 'block', width: `${(it.value / top) * 100}%`, background: it.color }}
              />
            </span>
          </>
        )
        return it.href ? (
          <Link key={it.key} to={it.href} className="bl-row">
            {inner}
          </Link>
        ) : (
          <div key={it.key} className="bl-row">
            {inner}
          </div>
        )
      })}
    </div>
  )
}
