// Search charts: the event histogram above results, and the multi-series time chart for
// timechart results. Hand-rolled SVG like Charts.tsx. Series take --series-1..8 in fixed
// order (OTHER is neutral gray); a legend is shown for two or more series, and every value
// is also in the Statistics table.

import { useMemo, useState } from 'react'
import { formatCount, formatNumber } from '../lib/format'
import { formatDateTime } from '../lib/time'
import { niceMax, useWidth } from './Charts'

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const pad = (n: number) => String(n).padStart(2, '0')

/** Axis label for a bucket start: "14:05" within a day, "Oct 19" for day buckets. */
export function bucketLabel(iso: string, spanSec: number, rangeSec: number): string {
  const d = new Date(iso)
  if (spanSec >= 86400) return `${MONTHS[d.getMonth()]} ${d.getDate()}`
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`
  if (rangeSec > 86400 && d.getHours() === 0 && d.getMinutes() === 0) return `${MONTHS[d.getMonth()]} ${d.getDate()}`
  return spanSec < 60 ? `${hm}:${pad(d.getSeconds())}` : hm
}

/** "Oct 19 14:05 – 14:10" for a bucket. */
export function bucketRange(iso: string, spanSec: number): string {
  const start = formatDateTime(iso).slice(0, spanSec < 60 ? undefined : -3)
  const end = new Date(Date.parse(iso) + spanSec * 1000)
  if (spanSec >= 86400) return `${start.slice(0, 6)} – ${MONTHS[end.getMonth()]} ${pad(end.getDate())}`
  return `${start} – ${pad(end.getHours())}:${pad(end.getMinutes())}${spanSec < 60 ? ':' + pad(end.getSeconds()) : ''}`
}

/** Rounded-top column path, square at the baseline. */
function columnPath(x: number, top: number, w: number, bottom: number, round: boolean): string {
  const h = bottom - top
  if (h <= 0) return ''
  const r = round ? Math.min(4, w / 2, h) : 0
  return `M${x},${bottom}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${bottom}Z`
}

/** Event counts over time. Clicking a bar calls onSelect with its index (zoom in). */
export function Histogram({
  data,
  spanSec,
  height = 96,
  onSelect,
}: {
  data: { t: string; count: number }[]
  spanSec: number
  height?: number
  onSelect?: (i: number) => void
}) {
  const [wrapRef, width] = useWidth<HTMLDivElement>(800)
  const [hover, setHover] = useState<number | null>(null)
  const padL = 40
  const padR = 4
  const padT = 6
  const padB = 18
  const max = niceMax(Math.max(0, ...data.map((d) => d.count)))
  const plotW = width - padL - padR
  const plotH = height - padT - padB
  const n = Math.max(1, data.length)
  const slot = plotW / n
  const barW = Math.max(1, Math.min(24, slot - 2))
  const y = (v: number) => padT + plotH - (v / max) * plotH
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(plotW / 70))))
  const rangeSec = n * spanSec
  return (
    <div className="chart" ref={wrapRef}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Matching events over time">
        <g className="axis">
          {[0, max].map((t) => (
            <g key={t}>
              <line className="gridline" x1={padL} x2={width - padR} y1={y(t)} y2={y(t)} />
              <text x={padL - 6} y={y(t) + 3.5} textAnchor="end">
                {formatCount(t)}
              </text>
            </g>
          ))}
          {data.map((d, i) =>
            i % labelEvery === 0 ? (
              <text key={d.t} x={padL + slot * i + slot / 2} y={height - 4} textAnchor="middle">
                {bucketLabel(d.t, spanSec, rangeSec)}
              </text>
            ) : null,
          )}
        </g>
        <line className="baseline" x1={padL} x2={width - padR} y1={y(0)} y2={y(0)} />
        {data.map((d, i) => {
          const h = d.count > 0 ? Math.max(1.5, (d.count / max) * plotH) : 0
          const x = padL + slot * i + (slot - barW) / 2
          return (
            <g key={d.t}>
              {h > 0 ? <path d={columnPath(x, padT + plotH - h, barW, padT + plotH, true)} className={hover === i ? 'bar hover' : 'bar'} /> : null}
              <rect
                className={onSelect && d.count > 0 ? 'hit zoomable' : 'hit'}
                x={padL + slot * i}
                y={padT}
                width={slot}
                height={plotH}
                tabIndex={onSelect && d.count > 0 ? 0 : undefined}
                aria-label={`${bucketRange(d.t, spanSec)}: ${formatNumber(d.count)} events`}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover((h2) => (h2 === i ? null : h2))}
                onFocus={() => setHover(i)}
                onBlur={() => setHover((h2) => (h2 === i ? null : h2))}
                onClick={() => d.count > 0 && onSelect?.(i)}
                onKeyDown={(e) => {
                  if ((e.key === 'Enter' || e.key === ' ') && d.count > 0) {
                    e.preventDefault()
                    onSelect?.(i)
                  }
                }}
              />
            </g>
          )
        })}
      </svg>
      {hover !== null && data[hover] ? (
        <div className="chart-tooltip" style={{ left: Math.min(Math.max(padL + slot * hover + slot / 2, 90), width - 90), top: y(data[hover].count) }}>
          <div className="muted">{bucketRange(data[hover].t, spanSec)}</div>
          <strong>{formatNumber(data[hover].count)}</strong> events{onSelect && data[hover].count > 0 ? <span className="faint"> · click to zoom</span> : null}
        </div>
      ) : null}
    </div>
  )
}

export interface Series {
  name: string
  values: (number | null)[]
  color: string
}

/** Colors series in fixed order; OTHER is gray. At most 8 colored series are drawn. */
export function colorSeries(names: string[], values: (number | null)[][]): { series: Series[]; hidden: number } {
  const series: Series[] = []
  let slot = 0
  let hidden = 0
  names.forEach((name, i) => {
    if (name === 'OTHER') {
      series.push({ name, values: values[i], color: 'var(--series-other)' })
    } else if (slot < 8) {
      series.push({ name, values: values[i], color: `var(--series-${++slot})` })
    } else {
      hidden++
    }
  })
  return { series, hidden }
}

export function Legend({ series, kind }: { series: Series[]; kind: 'column' | 'line' }) {
  return (
    <ul className="chart-legend" aria-label="Legend">
      {series.map((s) => (
        <li key={s.name} title={s.name}>
          <span className={kind === 'line' ? 'key line' : 'key'} style={{ background: s.color }} aria-hidden="true" />
          <span className="truncate-inline">{s.name}</span>
        </li>
      ))}
    </ul>
  )
}

/** Multi-series values over time, as stacked columns or lines. */
export function TimeSeriesChart({
  times,
  series,
  spanSec,
  kind,
  height = 260,
}: {
  times: string[]
  series: Series[]
  spanSec: number
  kind: 'column' | 'line'
  height?: number
}) {
  const [wrapRef, width] = useWidth<HTMLDivElement>(800)
  const [hover, setHover] = useState<number | null>(null)
  const padL = 48
  const padR = 8
  const padT = 10
  const padB = 22
  const plotW = width - padL - padR
  const plotH = height - padT - padB
  const n = Math.max(1, times.length)
  const slot = plotW / n
  const barW = Math.max(1, Math.min(24, slot - 2))
  const { lo, hi } = useMemo(() => {
    let lo = 0
    let hi = 0
    for (let i = 0; i < times.length; i++) {
      let stack = 0
      for (const s of series) {
        const v = s.values[i] ?? 0
        if (kind === 'column') stack += Math.max(0, v)
        else {
          hi = Math.max(hi, v)
          lo = Math.min(lo, v)
        }
      }
      hi = Math.max(hi, stack)
    }
    return { lo: lo < 0 ? -niceMax(-lo) : 0, hi: niceMax(hi) }
  }, [times, series, kind])
  const y = (v: number) => padT + plotH - ((v - lo) / (hi - lo)) * plotH
  const cx = (i: number) => padL + slot * i + slot / 2
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(plotW / 70))))
  const ticks = lo < 0 ? [lo, 0, hi] : [0, hi / 2, hi]
  const rangeSec = n * spanSec

  const linePath = (s: Series) => {
    let d = ''
    let pen = false
    s.values.forEach((v, i) => {
      if (v === null || v === undefined) {
        pen = false
        return
      }
      d += `${pen ? 'L' : 'M'}${cx(i).toFixed(1)},${y(v).toFixed(1)}`
      pen = true
    })
    return d
  }

  return (
    <div className="chart" ref={wrapRef}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Time chart">
        <g className="axis">
          {ticks.map((t) => (
            <g key={t}>
              <line className="gridline" x1={padL} x2={width - padR} y1={y(t)} y2={y(t)} />
              <text x={padL - 6} y={y(t) + 3.5} textAnchor="end">
                {formatCount(t)}
              </text>
            </g>
          ))}
          {times.map((t, i) =>
            i % labelEvery === 0 ? (
              <text key={t} x={cx(i)} y={height - 6} textAnchor="middle">
                {bucketLabel(t, spanSec, rangeSec)}
              </text>
            ) : null,
          )}
        </g>
        <line className="baseline" x1={padL} x2={width - padR} y1={y(0)} y2={y(0)} />
        {kind === 'column'
          ? times.map((t, i) => {
              const x = cx(i) - barW / 2
              const segs = series.map((s) => ({ s, v: Math.max(0, s.values[i] ?? 0) })).filter((p) => p.v > 0)
              let cum = 0
              return (
                <g key={t} className={hover === i ? 'stack hover' : 'stack'}>
                  {segs.map((p, k) => {
                    const bottom = y(cum)
                    cum += p.v
                    const top = y(cum)
                    const last = k === segs.length - 1
                    // a 2px surface gap separates each segment from the one above it
                    const path = columnPath(x, last ? Math.min(top, bottom - 1.5) : Math.min(top + 2, bottom), barW, bottom, last)
                    return path ? <path key={p.s.name} d={path} style={{ fill: p.s.color }} /> : null
                  })}
                </g>
              )
            })
          : series.map((s) => <path key={s.name} d={linePath(s)} className="series-line" style={{ stroke: s.color }} />)}
        {hover !== null ? (
          <g pointerEvents="none">
            <line className="crosshair" x1={cx(hover)} x2={cx(hover)} y1={padT} y2={padT + plotH} />
            {kind === 'line'
              ? series.map((s) =>
                  s.values[hover] !== null && s.values[hover] !== undefined ? (
                    <circle key={s.name} cx={cx(hover)} cy={y(s.values[hover]!)} r={4} className="marker" style={{ fill: s.color }} />
                  ) : null,
                )
              : null}
          </g>
        ) : null}
        {times.map((t, i) => (
          <rect
            key={t}
            className="hit"
            x={padL + slot * i}
            y={padT}
            width={slot}
            height={plotH}
            tabIndex={0}
            aria-label={`${bucketRange(t, spanSec)}: ${series.map((s) => `${s.name} ${s.values[i] === null ? 'no value' : formatNumber(s.values[i])}`).join(', ')}`}
            onMouseEnter={() => setHover(i)}
            onMouseLeave={() => setHover((h) => (h === i ? null : h))}
            onFocus={() => setHover(i)}
            onBlur={() => setHover((h) => (h === i ? null : h))}
          />
        ))}
      </svg>
      {hover !== null && times[hover] ? (
        <div
          className="chart-tooltip series-tooltip"
          style={{ left: Math.min(Math.max(cx(hover), 110), width - 110), top: padT + 4, transform: 'translate(-50%, 0)' }}
        >
          <div className="muted">{bucketRange(times[hover], spanSec)}</div>
          {series.map((s) => (
            <div key={s.name} className="tt-row">
              <span className="tt-key" style={{ background: s.color }} aria-hidden="true" />
              <strong>{s.values[hover] === null || s.values[hover] === undefined ? '—' : formatNumber(s.values[hover])}</strong>
              <span className="muted truncate-inline">{s.name}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}
