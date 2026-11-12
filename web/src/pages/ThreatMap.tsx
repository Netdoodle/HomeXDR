// Threat map: who on the internet is trying to reach the firewall, from where, and at which ports.

import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { getInbound, inboundKeys, type InboundCountry, type InboundSource, type InboundView } from '../api/inbound'
import { BarList, ColumnChart } from '../components/Charts'
import { PageHeader } from '../components/Layout'
import { CopyIcon, RelTime } from '../components/Misc'
import { EmptyState, ErrorState, Loading } from '../components/States'
import { countryName, COUNTRY_CENTROIDS } from '../lib/countryCentroids'
import { formatCount, formatNumber } from '../lib/format'
import { flagEmoji, investigateHref, worldDotsPath, worldPoint } from '../lib/intel'

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

      <section className="panel">
        <div className="panel-header">
          <h2 className="grow">Attempts by country</h2>
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
            <AttackMap countries={v.countries} selected={country} onSelect={setCountry} />
          ) : (
            <CountryTable countries={v.countries} total={v.attempts} onSelect={setCountry} />
          )}
          <p className="xsmall muted" style={{ margin: '6px 0 0' }}>
            Bubble size is the number of attempts; red bubbles had connections let in. Click a country to filter the sources below.
          </p>
        </div>
      </section>

      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2>Attempts over time</h2>
          </div>
          <div className="panel-body">
            <ColumnChart data={v.timeline.map((p) => ({ t: p.t, count: p.blocked + p.allowed }))} unit="attempts" />
          </div>
        </section>
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
          <h2 className="grow">Top sources{country !== null ? ` from ${countryName(country)}` : ''}</h2>
          {v.truncated ? <span className="small muted">The rarest sources are left out</span> : null}
        </div>
        {sources.length ? <SourceTable rows={sources} /> : <EmptyState title="No sources in the top 50 from this country" compact />}
      </section>
    </div>
  )
}

function AttackMap({ countries, selected, onSelect }: { countries: InboundCountry[]; selected: string | null; onSelect: (c: string) => void }) {
  const { path, width, height } = useMemo(worldDotsPath, [])
  const placed = countries.filter((c) => COUNTRY_CENTROIDS[c.code])
  const max = Math.max(1, ...placed.map((c) => c.attempts))
  return (
    <svg className="world-map threat-map" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Map of attempts by country">
      <path className="land" d={path} />
      {[...placed].reverse().map((c) => {
        const [lat, lon] = COUNTRY_CENTROIDS[c.code]
        const p = worldPoint(lat, lon)
        const r = 0.9 + 6 * Math.sqrt(c.attempts / max)
        const cls = ['bubble', c.allowed > 0 ? 'allowed' : '', selected === c.code ? 'selected' : ''].join(' ')
        return (
          <circle key={c.code} className={cls} cx={p.x} cy={p.y} r={r} onClick={() => onSelect(c.code)} tabIndex={0} role="button"
            onKeyDown={(e) => (e.key === 'Enter' ? onSelect(c.code) : null)}>
            <title>{`${countryName(c.code)}: ${formatNumber(c.attempts)} attempts from ${formatNumber(c.sources)} sources${c.allowed ? `, ${formatNumber(c.allowed)} let in` : ''}`}</title>
          </circle>
        )
      })}
    </svg>
  )
}

function CountryTable({ countries, total, onSelect }: { countries: InboundCountry[]; total: number; onSelect: (c: string) => void }) {
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
              <td className="right num">{formatNumber(c.attempts)}</td>
              <td className="right num">{((c.attempts / total) * 100).toFixed(1)}%</td>
              <td className="right num">{formatNumber(c.sources)}</td>
              <td className={c.allowed ? 'right num danger-text' : 'right num muted'}>{formatNumber(c.allowed)}</td>
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
