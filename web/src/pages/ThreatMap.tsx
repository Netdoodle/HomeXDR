// Threat map: who on the internet is trying to reach the firewall, from where, and at which ports.

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import { getInbound, getInboundEvents, inboundKeys, type InboundCountry, type InboundKind, type InboundSource, type InboundView } from '../api/inbound'
import { EventTable } from '../components/EventTable'
import { AttackMap } from '../components/AttackMap'
import { Icon } from '../components/Icon'
import { BarList, niceMax, useWidth } from '../components/Charts'
import { PageHeader } from '../components/Layout'
import { CopyIcon, RelTime } from '../components/Misc'
import { EmptyState, ErrorState, Loading } from '../components/States'
import { countryName } from '../lib/countryCentroids'
import { formatCount, formatNumber } from '../lib/format'
import { flagEmoji, investigateHref } from '../lib/intel'
import { formatDateTime } from '../lib/time'

const RANGES = [
  { hours: 1, label: '1 hour' },
  { hours: 24, label: '24 hours' },
  { hours: 168, label: '7 days' },
  { hours: 720, label: '30 days' },
]

/** Well-known services, for the port list. */
const SERVICES: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 81: 'HTTP alt', 110: 'POP3', 111: 'RPC',
  123: 'NTP', 135: 'MS RPC', 137: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS',
  445: 'SMB', 465: 'SMTPS', 502: 'Modbus', 554: 'RTSP', 587: 'SMTP submit', 631: 'IPP', 853: 'DNS over TLS', 993: 'IMAPS',
  995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MS SQL', 1521: 'Oracle', 1723: 'PPTP', 1883: 'MQTT',
  1900: 'SSDP', 2049: 'NFS', 2222: 'SSH alt', 2375: 'Docker API', 2376: 'Docker TLS', 3000: 'Web app', 3128: 'Proxy',
  3306: 'MySQL', 3389: 'RDP', 4443: 'HTTPS alt', 5000: 'Web app', 5060: 'SIP', 5432: 'PostgreSQL', 5555: 'ADB',
  5900: 'VNC', 5985: 'WinRM', 6379: 'Redis', 6443: 'Kubernetes', 7547: 'TR-069', 8000: 'HTTP alt', 8080: 'HTTP alt',
  8081: 'HTTP alt', 8443: 'HTTPS alt', 8888: 'HTTP alt', 9000: 'Web app', 9090: 'Web app', 9200: 'Elasticsearch',
  10000: 'Webmin', 11211: 'Memcached', 27017: 'MongoDB', 32400: 'Plex', 51820: 'WireGuard',
}

export function ThreatMapPage() {
  const [hours, setHours] = useState(24)
  const q = useQuery({ queryKey: inboundKeys.view(hours), queryFn: () => getInbound(hours), refetchInterval: 60_000 })
  return (
    <>
      <PageHeader
        title="Threat map"
        subtitle="Connections from the internet trying to reach your firewall, by country, network and port"
        actions={
          <div className="btn-group" role="group" aria-label="Time range">
            {RANGES.map((r) => (
              <button key={r.hours} type="button" className={hours === r.hours ? 'btn sm active' : 'btn sm'} aria-pressed={hours === r.hours} onClick={() => setHours(r.hours)}>
                {r.label}
              </button>
            ))}
          </div>
        }
      />
      {q.isPending ? <Loading /> : q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : <ThreatMapBody v={q.data} />}
    </>
  )
}

function ThreatMapBody({ v }: { v: InboundView }) {
  const [view, setView] = useState<'map' | 'table'>('map')
  const [country, setCountry] = useState<string | null>(null)
  const [drill, setDrill] = useState<{ country: string; kind: InboundKind } | null>(null)
  const openLogs = (code: string, kind: InboundKind | 'sources') => {
    setCountry(code)
    if (kind === 'sources') {
      setDrill(null)
      document.getElementById('top-sources')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
      return
    }
    setDrill({ country: code, kind })
    setTimeout(() => document.getElementById('threat-logs')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50)
  }
  if (v.attempts === 0) {
    return (
      <EmptyState title="No connections from the internet in this window">
        The threat map reads the firewall log (OPNsense filterlog). Check that the firewall sends it: Settings → Integrations.
      </EmptyState>
    )
  }
  const sources = country === null ? v.top_sources : v.top_sources.filter((s) => (s.country ?? '') === country)
  const blockedPct = v.attempts ? Math.round((v.blocked / v.attempts) * 1000) / 10 : 0
  return (
    <div className="stack">
      {v.no_geo ? (
        <div className="callout small">
          Countries and networks need the offline IP network list. Turn it on under <Link to="/settings/lists">Settings → Offline lists</Link>.
        </div>
      ) : null}
      <div className="stats">
        <div className="stat">
          <span className="label">Attempts</span>
          <span className="value">{formatCount(v.attempts)}</span>
          <span className="sub">{formatNumber(Math.round(v.attempts / v.hours))} per hour</span>
        </div>
        <div className="stat">
          <span className="label">Blocked</span>
          <span className="value">{blockedPct}%</span>
          <span className="sub">{formatNumber(v.blocked)} connections</span>
        </div>
        <div className="stat">
          <span className="label">Sources</span>
          <span className="value">{formatNumber(v.sources)}</span>
          <span className="sub">unique internet addresses</span>
        </div>
        <div className="stat">
          <span className="label">Countries</span>
          <span className="value">{formatNumber(v.countries.filter((c) => c.code).length)}</span>
          <span className="sub">{v.countries[0]?.code ? `most from ${countryName(v.countries[0].code)}` : ' '}</span>
        </div>
      </div>

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2 className="grow">Attempts trend</h2>
            <span className="small muted">{formatNumber(Math.round(v.attempts / v.hours))} per hour, {blockedPct}% blocked</span>
          </div>
          <div className="panel-body">
            <LineChart points={v.timeline.map((p) => ({ t: p.t, value: p.blocked + p.allowed }))} unit="attempts" tone="attempts" spanSec={v.span_sec} />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2 className="grow">Attackers trend</h2>
            <span className="small muted">unique internet addresses per {bucketLabel(v.span_sec)}</span>
          </div>
          <div className="panel-body">
            <LineChart points={v.timeline.map((p) => ({ t: p.t, value: p.sources }))} unit="sources" tone="sources" spanSec={v.span_sec} />
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2 className="grow">Attack origins</h2>
          {country !== null ? (
            <button type="button" className="btn sm" onClick={() => setCountry(null)}>
              {flagEmoji(country)} {countryName(country)} ✕
            </button>
          ) : null}
          <div className="btn-group" role="group" aria-label="View">
            <button type="button" className={view === 'map' ? 'btn sm active' : 'btn sm'} aria-pressed={view === 'map'} onClick={() => setView('map')}>
              Map
            </button>
            <button type="button" className={view === 'table' ? 'btn sm active' : 'btn sm'} aria-pressed={view === 'table'} onClick={() => setView('table')}>
              Table
            </button>
          </div>
        </div>
        <div className="panel-body">
          {view === 'map' ? (
            <AttackMap
              countries={v.countries}
              selected={country}
              onSelect={setCountry}
              onDrill={openLogs}
              details={(code) => {
                const top = v.top_sources.filter((s) => (s.country ?? '') === code).slice(0, 3)
                return top.length ? (
                  <div className="xsmall" style={{ marginTop: 6 }}>
                    <div className="muted">Top sources</div>
                    {top.map((s) => (
                      <div key={s.ip} className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
                        <Link className="mono" to={investigateHref(s.ip)}>
                          {s.ip}
                        </Link>
                        <span>{formatNumber(s.attempts)}</span>
                      </div>
                    ))}
                  </div>
                ) : null
              }}
            />
          ) : (
            <CountryTable countries={v.countries} total={v.attempts} onSelect={setCountry} onDrill={openLogs} />
          )}
          <p className="xsmall muted" style={{ margin: '6px 0 0' }}>
            Bubble size and shading follow the number of attempts; red-ringed bubbles had connections let in. Click a country for its numbers and click a
            number for its logs. Scroll or use the buttons to zoom, drag to move.
          </p>
        </div>
      </section>

      {drill ? <ThreatLogs hours={v.hours} country={drill.country} kind={drill.kind} onClose={() => setDrill(null)} /> : null}

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2>Top countries</h2>
          </div>
          <div className="panel-body">
            <BarList
              items={v.countries.slice(0, 10).map((c) => ({
                key: c.code || 'unknown',
                label: (
                  <span>
                    {flagEmoji(c.code)} {countryName(c.code)}
                  </span>
                ),
                value: c.attempts,
                title: `${formatNumber(c.sources)} sources`,
              }))}
            />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Targeted ports</h2>
          </div>
          <div className="panel-body">
            <BarList
              items={v.ports.slice(0, 12).map((p) => ({
                key: `${p.port}/${p.transport}`,
                label: (
                  <span>
                    <span className="mono">
                      {p.port}/{p.transport}
                    </span>{' '}
                    <span className="muted">{SERVICES[p.port] ?? ''}</span>
                  </span>
                ),
                value: p.attempts,
                title: `${formatNumber(p.sources)} sources`,
                href: `/search?q=${encodeURIComponent(`event.dataset:opnsense.filterlog network.direction:inbound destination.port:${p.port}`)}`,
              }))}
            />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Top networks</h2>
          </div>
          <div className="panel-body">
            <BarList
              items={v.networks.slice(0, 12).map((n) => ({
                key: String(n.asn),
                label: (
                  <span>
                    {flagEmoji(n.country)} {n.name || 'AS' + n.asn} <span className="muted xsmall">AS{n.asn}</span>
                  </span>
                ),
                value: n.attempts,
                title: `${formatNumber(n.sources)} sources`,
              }))}
            />
          </div>
        </section>
      </div>

      {v.allowed_sources.length > 0 ? (
        <section className="panel">
          <div className="panel-header">
            <h2 className="grow">Let in from the internet</h2>
            <span className="small muted">Connections your firewall passed or forwarded: your exposed services</span>
          </div>
          <SourceTable rows={v.allowed_sources} showAllowed />
        </section>
      ) : null}

      <section className="panel">
        <div className="panel-header">
          <h2 className="grow" id="top-sources">Top sources{country !== null ? ` from ${countryName(country)}` : ''}</h2>
          {v.truncated ? <span className="small muted">The rarest sources are left out</span> : null}
        </div>
        {sources.length ? <SourceTable rows={sources} /> : <EmptyState title="No sources in the top 50 from this country" compact />}
      </section>
    </div>
  )
}

function CountryTable({
  countries,
  total,
  onSelect,
  onDrill,
}: {
  countries: InboundCountry[]
  total: number
  onSelect: (c: string) => void
  onDrill: (c: string, kind: InboundKind) => void
}) {
  const num = (n: number, code: string, kind: InboundKind, title: string) => (
    <button
      type="button"
      className="num-link"
      title={title}
      onClick={(e) => {
        e.stopPropagation()
        onDrill(code, kind)
      }}
    >
      {formatNumber(n)}
    </button>
  )
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Country</th>
            <th className="right">Attempts</th>
            <th className="right">Share</th>
            <th className="right">Sources</th>
            <th className="right">Let in</th>
          </tr>
        </thead>
        <tbody>
          {countries.map((c) => (
            <tr key={c.code || 'unknown'} className="clickable" onClick={() => onSelect(c.code)}>
              <td>
                {flagEmoji(c.code)} {countryName(c.code)} <span className="muted xsmall mono">{c.code}</span>
              </td>
              <td className="right num">{num(c.attempts, c.code, 'all', 'Show these connections')}</td>
              <td className="right num">{((c.attempts / total) * 100).toFixed(1)}%</td>
              <td className="right num">{formatNumber(c.sources)}</td>
              <td className={c.allowed ? 'right num danger-text' : 'right num muted'}>
                {c.allowed ? num(c.allowed, c.code, 'allowed', 'Show the connections let in') : formatNumber(0)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SourceTable({ rows, showAllowed }: { rows: InboundSource[]; showAllowed?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Source</th>
            <th>Country</th>
            <th>Network</th>
            <th className="right">{showAllowed ? 'Let in' : 'Attempts'}</th>
            <th className="right">Ports tried</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((s) => (
            <tr key={s.ip}>
              <td className="copy-cell">
                <CopyIcon text={s.ip} label="Address" />
                <Link className="mono" to={investigateHref(s.ip)}>
                  {s.ip}
                </Link>
              </td>
              <td>
                {flagEmoji(s.country)} {countryName(s.country)}
              </td>
              <td className="truncate copy-cell" title={s.as_name}>
                <CopyIcon text={s.as_name} label="Network" />
                {s.as_name ?? <span className="empty-cell">—</span>} {s.asn ? <span className="muted xsmall">AS{s.asn}</span> : null}
              </td>
              <td className="right num">{formatNumber(showAllowed ? s.allowed : s.attempts)}</td>
              <td className="right num">{formatNumber(s.ports)}</td>
              <td>
                <RelTime iso={s.last} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function rangeLabel(hours: number): string {
  return RANGES.find((r) => r.hours === hours)?.label ?? `${hours} hours`
}

function bucketLabel(sec: number): string {
  if (sec >= 86400) return 'day'
  if (sec >= 3600) return sec === 3600 ? 'hour' : `${sec / 3600} hours`
  return `${sec / 60} minutes`
}

function LineChart({ points, unit, tone, spanSec }: { points: { t: string; value: number }[]; unit: string; tone: 'attempts' | 'sources'; spanSec: number }) {
  const [ref, width] = useWidth<HTMLDivElement>(500)
  const [hover, setHover] = useState<number | null>(null)
  const height = 180
  const pad = { l: 40, r: 10, t: 14, b: 22 }
  if (points.length === 0) return <EmptyState title="No data in this window" compact />
  const max = niceMax(Math.max(1, ...points.map((p) => p.value)))
  const w = width - pad.l - pad.r
  const h = height - pad.t - pad.b
  const x = (i: number) => pad.l + (points.length === 1 ? w / 2 : (i / (points.length - 1)) * w)
  const y = (val: number) => pad.t + h - (val / max) * h
  const line = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(p.value).toFixed(1)}`).join('')
  const area = `${line}L${x(points.length - 1).toFixed(1)} ${pad.t + h}L${x(0).toFixed(1)} ${pad.t + h}Z`
  const peak = points.reduce((m, p, i) => (p.value > points[m].value ? i : m), 0)
  const labelEvery = Math.max(1, Math.ceil(points.length / Math.max(2, Math.floor(w / 90))))
  return (
    <div ref={ref} className={`line-chart ${tone}`} style={{ position: 'relative' }}>
      <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${unit} over time`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect()
          const i = Math.round(((e.clientX - r.left - pad.l) / w) * (points.length - 1))
          setHover(i >= 0 && i < points.length ? i : null)
        }}
      >
        {[0, max / 2, max].map((t) => (
          <g key={t} className="axis">
            <line className="gridline" x1={pad.l} x2={width - pad.r} y1={y(t)} y2={y(t)} />
            <text x={pad.l - 6} y={y(t) + 3.5} textAnchor="end">
              {formatCount(t)}
            </text>
          </g>
        ))}
        {points.map((p, i) =>
          i % labelEvery === 0 ? (
            <text key={i} className="axis-x" x={x(i)} y={height - 6} textAnchor="middle">
              {axisLabel(p.t, spanSec)}
            </text>
          ) : null,
        )}
        <path className="area" d={area} />
        <path className="line" d={line} />
        <text className="peak" x={x(peak)} y={y(points[peak].value) - 6} textAnchor="middle">
          {formatCount(points[peak].value)}
        </text>
        {hover !== null ? (
          <>
            <line className="cursor" x1={x(hover)} x2={x(hover)} y1={pad.t} y2={pad.t + h} />
            <circle className="dot" cx={x(hover)} cy={y(points[hover].value)} r={3.5} />
          </>
        ) : null}
      </svg>
      {hover !== null ? (
        <div className="chart-tooltip" style={{ left: Math.min(Math.max(x(hover), 60), width - 60), top: y(points[hover].value) }}>
          <div className="muted">{formatDateTime(points[hover].t).slice(0, -3)}</div>
          <strong>{formatNumber(points[hover].value)}</strong> {unit}
        </div>
      ) : null}
    </div>
  )
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
const two = (n: number) => String(n).padStart(2, '0')

/** An x-axis label: the time of day for short buckets, the date for daily ones. */
function axisLabel(iso: string, spanSec: number): string {
  const d = new Date(iso)
  if (spanSec >= 6 * 3600) return `${MONTHS[d.getMonth()]} ${d.getDate()}`
  return `${two(d.getHours())}:${two(d.getMinutes())}`
}

const KIND_LABEL: Record<InboundKind, string> = { all: 'all connections', blocked: 'blocked', allowed: 'let in' }

/** The firewall log entries behind a number on the map or the country table. */
function ThreatLogs({ hours, country, kind, onClose }: { hours: number; country: string; kind: InboundKind; onClose: () => void }) {
  const [offset, setOffset] = useState(0)
  const q = useQuery({
    queryKey: ['stats', 'inbound', 'events', hours, country, kind, offset],
    queryFn: () => getInboundEvents(hours, country, kind, offset),
  })
  const d = q.data
  return (
    <section className="panel" id="threat-logs">
      <div className="panel-header">
        <h2 className="grow">
          Logs: {flagEmoji(country)} {countryName(country)} · {KIND_LABEL[kind]} · {rangeLabel(hours)}
        </h2>
        {d?.query ? (
          <Link className="btn sm" to={`/search?q=${encodeURIComponent(d.query)}`}>
            <Icon name="search" size={12} /> Open in Search
          </Link>
        ) : null}
        <button type="button" className="btn ghost sm" aria-label="Close the logs" onClick={onClose}>
          <Icon name="close" size={12} />
        </button>
      </div>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} />
      ) : d && d.total > 0 ? (
        <>
          <div className="panel-body small muted" style={{ paddingBottom: 0 }}>
            {formatNumber(d.total)} {d.total === 1 ? 'entry' : 'entries'} from {formatNumber(d.sources)} {d.sources === 1 ? 'address' : 'addresses'}, newest
            first.{d.query ? null : ' Too many addresses for a Search link; they are all shown here.'}
          </div>
          <EventTable events={d.events} processLinks={false} />
          {d.total > 100 ? (
            <div className="panel-body row" style={{ gap: 8 }}>
              <button type="button" className="btn sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>
                Newer
              </button>
              <span className="small muted">
                {formatNumber(offset + 1)}–{formatNumber(Math.min(offset + 100, d.total))} of {formatNumber(d.total)}
              </span>
              <button type="button" className="btn sm" disabled={offset + 100 >= d.total || offset + 100 > 10000} onClick={() => setOffset(offset + 100)}>
                Older
              </button>
            </div>
          ) : null}
        </>
      ) : (
        <EmptyState title="No log entries for this selection" compact />
      )}
    </section>
  )
}
