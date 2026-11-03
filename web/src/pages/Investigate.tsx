// Investigate: look up an IP, domain, URL or file hash in threat intelligence services and
// in this server's own events.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api, queryKeys, type IntelGeo, type IntelResult, type IntelSightings, type IntelView, type IntelWhois } from '../api'
import { ApiError, errorMessage } from '../api/client'
import { useCan } from '../components/Auth'
import { SeverityBadge } from '../components/Badges'
import { EventTable } from '../components/EventTable'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { CopyButton, KV, RelTime } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { formatNumber } from '../lib/format'
import { useDocumentTitle, useUrlState } from '../lib/hooks'
import { coverageLine, flagEmoji, investigateHref, KIND_LABEL, SIGHTING_WINDOWS, sortedResults, STATE_LABEL, VERDICT_LABEL, worldDotsPath, worldPoint } from '../lib/intel'
import { formatDateTime } from '../lib/time'

export function InvestigatePage() {
  const [sp, patch] = useUrlState()
  const q = sp.get('q') ?? ''
  useDocumentTitle(q ? `Investigate ${q}` : 'Investigate')
  const [text, setText] = useState(q)
  useEffect(() => setText(q), [q])
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (text.trim()) patch({ q: text.trim() })
  }
  return (
    <>
      <PageHeader title="Investigate" subtitle="Look up an IP address, domain, URL or file hash in threat intelligence services and in your own events" />
      <form className="investigate-search" onSubmit={submit} role="search">
        <Icon name="search" size={16} />
        <input
          className="grow mono"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="8.8.8.8, evil[.]example.com, hxxps://…, or an MD5, SHA-1 or SHA-256 hash"
          aria-label="Indicator to investigate"
          autoFocus={!q}
          spellCheck={false}
        />
        <button type="submit" className="btn primary" disabled={!text.trim()}>
          Investigate
        </button>
      </form>
      {q ? <Result key={q} indicator={q} /> : <RecentLookups />}
    </>
  )
}

function RecentLookups() {
  const list = useQuery({ queryKey: queryKeys.intelHistory, queryFn: () => api.intelHistory(20) })
  const canLookup = useCan('analyst')
  if (list.isPending) return <Loading />
  if (list.isError) return <ErrorState error={list.error} onRetry={() => list.refetch()} />
  return (
    <div className="stack">
      {list.data.length ? (
        <section className="panel">
          <div className="panel-header">
            <h2>Recent lookups</h2>
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Verdict</th>
                  <th className="right">Score</th>
                  <th>Checked</th>
                  <th>By</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((l) => (
                  <tr key={l.indicator}>
                    <td className="mono small" style={{ overflowWrap: 'anywhere' }}>
                      <Link to={investigateHref(l.indicator)}>{l.indicator}</Link>
                    </td>
                    <td className="small">{KIND_LABEL[l.kind]}</td>
                    <td className="small">
                      <span className={`verdict-dot ${l.verdict}`} aria-hidden="true" /> {VERDICT_LABEL[l.verdict]}
                    </td>
                    <td className="right num">{l.score ?? <span className="empty-cell">—</span>}</td>
                    <td className="small">
                      <RelTime iso={l.updated_at} />
                    </td>
                    <td className="small muted">{l.updated_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}
      <section className="panel">
        <div className="panel-body small muted stack" style={{ gap: 6 }}>
          <span>
            A lookup sends the indicator to the services listed in <Link to="/settings/intel">Settings → Threat intel</Link>; the indicator itself is never
            contacted. Private addresses and internal names stay on this server, and only your own events are searched for them.
          </span>
          <span>Defanged indicators work as pasted, such as hxxps://evil[.]example[.]com.{canLookup ? '' : ' Your role can read earlier lookups; an analyst can start new ones.'}</span>
        </div>
      </section>
    </div>
  )
}

function Result({ indicator }: { indicator: string }) {
  const qc = useQueryClient()
  const canLookup = useCan('analyst')
  const key = queryKeys.intel(indicator)
  const start = useMutation({
    mutationFn: (refresh: boolean) => api.startIntelLookup(indicator, refresh),
    onSuccess: (v) => {
      qc.setQueryData(key, v)
      qc.invalidateQueries({ queryKey: queryKeys.intelHistory })
    },
  })
  // Opening the page looks the indicator up: answers still fresh are reused without asking anyone.
  const { mutate } = start
  useEffect(() => {
    if (canLookup) mutate(false)
  }, [canLookup, mutate])
  const view = useQuery({
    queryKey: key,
    queryFn: () => api.getIntelLookup(indicator),
    enabled: !canLookup || start.isSuccess,
    refetchInterval: (query) => (query.state.data?.running ? 1200 : false),
    retry: false,
  })

  if (start.isError) {
    return (
      <div className="callout danger" role="alert">
        <Icon name="warning" size={14} />
        <span>{errorMessage(start.error)}</span>
      </div>
    )
  }
  if (view.isError) {
    if (view.error instanceof ApiError && view.error.status === 404) {
      return (
        <div className="callout info">
          <Icon name="info" size={14} />
          <span>Nobody has looked this up yet. Your role can read lookups; an analyst or admin can start one.</span>
        </div>
      )
    }
    return <ErrorState error={view.error} onRetry={() => view.refetch()} />
  }
  if (!view.data) return <Loading label="Starting the lookup…" />
  const v = view.data
  return (
    <div className="stack">
      <SummaryPanel view={v} canLookup={canLookup} onRefresh={() => start.mutate(true)} refreshing={start.isPending} />
      <SightingsPanel indicator={indicator} />
      {v.summary.geo || v.summary.whois ? <NetworkPanels geo={v.summary.geo} whois={v.summary.whois} /> : null}
      {v.results.length ? <SourcesPanel results={v.results} coverage={v.summary.coverage} /> : null}
      {sortedResults(v.results).length ? (
        <div className="intel-cards">
          {sortedResults(v.results).map((r) => (
            <SourceCard key={r.source} result={r} />
          ))}
        </div>
      ) : null}
    </div>
  )
}

function ScoreRing({ score, verdict }: { score?: number; verdict: string }) {
  const r = 34
  const c = 2 * Math.PI * r
  const shown = score ?? 0
  return (
    <svg className={`score-ring ${verdict}`} viewBox="0 0 84 84" width="96" height="96" role="img" aria-label={score === undefined ? 'No score' : `Risk score ${score} of 100`}>
      <circle className="track" cx="42" cy="42" r={r} />
      <circle className="value" cx="42" cy="42" r={r} strokeDasharray={`${(c * shown) / 100} ${c}`} transform="rotate(-90 42 42)" />
      <text x="42" y="40" textAnchor="middle" className="n">
        {score ?? '—'}
      </text>
      <text x="42" y="55" textAnchor="middle" className="of">
        / 100
      </text>
    </svg>
  )
}

function SummaryPanel({ view: v, canLookup, onRefresh, refreshing }: { view: IntelView; canLookup: boolean; onRefresh: () => void; refreshing: boolean }) {
  const s = v.summary
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="row grow" style={{ gap: 8, minWidth: 0 }}>
          <span className="mono truncate-inline" title={v.indicator.value}>
            {v.indicator.value}
          </span>
          <span className="badge">{v.indicator.hash_type ? v.indicator.hash_type.toUpperCase() : KIND_LABEL[v.indicator.kind]}</span>
        </h2>
        <span className="row" style={{ gap: 6 }}>
          {v.running ? <Spinner small /> : null}
          <CopyButton text={v.indicator.value} small />
          {canLookup && !v.indicator.private ? (
            <button type="button" className="btn sm" disabled={v.running || refreshing} onClick={onRefresh} title="Ask every source again, ignoring saved answers">
              <Icon name="refresh" size={12} /> Re-check
            </button>
          ) : null}
        </span>
      </div>
      <div className="panel-body intel-summary">
        <ScoreRing score={s.score} verdict={s.verdict} />
        <div className="stack grow" style={{ gap: 8, minWidth: 0 }}>
          <div>
            <div className="intel-verdict">
              <span className={`verdict-dot ${s.verdict}`} aria-hidden="true" /> {VERDICT_LABEL[s.verdict]}
              {v.running ? <span className="muted small"> · still checking</span> : null}
            </div>
            <div className="small muted">{s.basis}</div>
          </div>
          {s.brief.map((p, i) => (
            <p key={i} className="intel-brief">
              {p}
            </p>
          ))}
          {v.updated_at ? (
            <span className="xsmall muted">
              Last checked <RelTime iso={v.updated_at} /> by {v.updated_by}. Saved answers are reused for the time set in <Link to="/settings/intel">Settings</Link>.
            </span>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function SightingsPanel({ indicator }: { indicator: string }) {
  const [days, setDays] = useState(30)
  const q = useQuery({ queryKey: queryKeys.intelSightings(indicator, days), queryFn: () => api.intelSightings(indicator, days) })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="grow">In your environment</h2>
        <select className="select sm" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="How far back to search">
          {SIGHTING_WINDOWS.map((d) => (
            <option key={d} value={d}>
              Last {d} days
            </option>
          ))}
        </select>
      </div>
      <div className="panel-body">
        {q.isPending ? <Loading compact label="Searching your events…" /> : q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : <SightingsBody s={q.data} />}
      </div>
    </section>
  )
}

function SightingsBody({ s }: { s: IntelSightings }) {
  const search = `/search?q=${encodeURIComponent(s.query)}&range=custom&from=${encodeURIComponent(new Date(Date.now() - s.days * 86400000).toISOString())}&to=${encodeURIComponent(new Date().toISOString())}`
  return (
    <div className="stack" style={{ gap: 12 }}>
      {s.own_hosts.map((h) => (
        <div key={h.id ?? h.name} className="callout info">
          <Icon name="hosts" size={14} />
          <span>
            This is the address of your host{' '}
            <Link to={`/hosts/${encodeURIComponent(h.id ?? '')}`}>
              <strong>{h.name}</strong>
            </Link>
            .
          </span>
        </div>
      ))}
      {s.note ? <span className="small muted">{s.note}</span> : null}
      {s.events === 0 ? (
        <span className="small">
          Not seen in the last {s.days} days. <span className="muted">No endpoint, firewall or DNS event mentions it.</span>
        </span>
      ) : (
        <>
          <div className="row" style={{ gap: 18, flexWrap: 'wrap' }}>
            <span>
              <strong className="num">{formatNumber(s.events)}</strong> <span className="muted small">{s.events === 1 ? 'event' : 'events'}</span>
            </span>
            <span>
              <strong className="num">{s.hosts.length}</strong> <span className="muted small">{s.hosts.length === 1 ? 'host' : 'hosts'}</span>
            </span>
            {s.alerts.length ? (
              <span>
                <strong className="num">{s.alerts.length}</strong> <span className="muted small">{s.alerts.length === 1 ? 'alert' : 'alerts'}</span>
              </span>
            ) : null}
            {s.first ? (
              <span className="small muted">
                first {formatDateTime(s.first)} · last {s.last ? formatDateTime(s.last) : '—'}
              </span>
            ) : null}
            <Link className="small" to={search}>
              Open in Search →
            </Link>
          </div>
          <div className="intel-sight-grid">
            {s.hosts.length ? (
              <div>
                <div className="label">Hosts</div>
                {s.hosts.map((h) => (
                  <div key={h.id ?? h.name} className="row small" style={{ justifyContent: 'space-between', gap: 8 }}>
                    {h.id ? <Link to={`/hosts/${encodeURIComponent(h.id)}`}>{h.name || h.id}</Link> : <span>{h.name}</span>}
                    <span className="num muted">{formatNumber(h.count)}</span>
                  </div>
                ))}
              </div>
            ) : null}
            {s.processes.length ? (
              <div>
                <div className="label">Processes</div>
                {s.processes.map((p) => (
                  <div key={p.name} className="row small" style={{ justifyContent: 'space-between', gap: 8 }}>
                    <span className="mono truncate-inline">{p.name}</span>
                    <span className="num muted">{formatNumber(p.count)}</span>
                  </div>
                ))}
              </div>
            ) : null}
            {s.alerts.length ? (
              <div>
                <div className="label">Alerts</div>
                {s.alerts.map((a) => (
                  <div key={a.id} className="row small" style={{ gap: 8 }}>
                    <SeverityBadge severity={a.severity} />
                    <Link className="truncate-inline" to={`/alerts/${encodeURIComponent(a.id)}`} title={a.rule.title}>
                      {a.rule.title}
                    </Link>
                  </div>
                ))}
              </div>
            ) : null}
          </div>
          {s.recent.length ? (
            <div>
              <div className="label" style={{ marginBottom: 6 }}>
                Latest events
              </div>
              <EventTable events={s.recent} showHost dense />
            </div>
          ) : null}
        </>
      )}
    </div>
  )
}

function WorldMap({ geo }: { geo: IntelGeo }) {
  const { path, width, height } = useMemo(worldDotsPath, [])
  const p = worldPoint(geo.lat, geo.lon)
  const place = [geo.city, geo.country_code].filter(Boolean).join(', ')
  return (
    <svg className="world-map" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Map marking ${place}`}>
      <path className="land" d={path} />
      <circle className="pulse" cx={p.x} cy={p.y} r="3" />
      <circle className="pin" cx={p.x} cy={p.y} r="1.2" />
    </svg>
  )
}

function NetworkPanels({ geo, whois }: { geo?: IntelGeo; whois?: IntelWhois }) {
  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <section className="panel">
        <div className="panel-header">
          <h2>Whois and network</h2>
        </div>
        <div className="panel-body">
          <KV
            items={[
              ['Registrant', whois?.registrant],
              ['Registrar', whois?.registrar],
              ['Net name', whois?.net_name],
              ['Range', whois?.range],
              ['Created', whois?.created],
              ['Updated', whois?.updated],
              ['Expires', whois?.expires],
              ['Name servers', whois?.name_servers?.join(', ')],
              [
                'Abuse',
                whois?.abuse ? (
                  <a key="a" href={`mailto:${whois.abuse}`}>
                    {whois.abuse}
                  </a>
                ) : undefined,
              ],
              [
                'Location',
                geo ? (
                  <span key="l">
                    {flagEmoji(geo.country_code)} {[geo.city, geo.region, geo.country].filter(Boolean).join(', ')}
                  </span>
                ) : undefined,
              ],
              ['ASN', geo?.asn],
              ['Org', geo?.org],
              ['ISP', geo?.isp],
              ['Time zone', geo?.timezone],
            ].filter(([, v]) => v) as [string, React.ReactNode][]}
          />
        </div>
      </section>
      {geo ? (
        <section className="panel">
          <div className="panel-header">
            <h2 className="grow">Location</h2>
            <span className="small muted">{[geo.city, geo.country].filter(Boolean).join(', ')}</span>
          </div>
          <div className="panel-body">
            <WorldMap geo={geo} />
            <span className="xsmall muted">IP locations are approximate and often show the network owner rather than the machine.</span>
          </div>
        </section>
      ) : null}
    </div>
  )
}

function SourcesPanel({ results, coverage }: { results: IntelResult[]; coverage: IntelView['summary']['coverage'] }) {
  const problems = results.filter((r) => r.state === 'error' || r.state === 'quota')
  const needKey = results.some((r) => r.state === 'needs_key')
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Sources</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 8 }}>
        <span className="small">{coverageLine(coverage)}</span>
        <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          {results.map((r) => (
            <span key={r.source} className={`source-chip ${r.state}`} title={`${STATE_LABEL[r.state]}${r.message ? `: ${r.message}` : ''}`}>
              {r.state === 'pending' ? <Spinner small /> : null}
              {r.name}
            </span>
          ))}
        </div>
        {problems.map((r) => (
          <span key={r.source} className="xsmall muted">
            {r.name}: {r.message}
          </span>
        ))}
        {needKey ? (
          <span className="small">
            <Link to="/settings/intel">Add free API keys</Link> <span className="muted">to get a firmer verdict.</span>
          </span>
        ) : null}
      </div>
    </section>
  )
}

function SourceCard({ result: r }: { result: IntelResult }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="grow">{r.name}</h2>
        {r.risk !== undefined ? (
          <span className={`risk-pill ${r.risk >= 75 ? 'high' : r.risk >= 45 ? 'mid' : r.risk >= 20 ? 'low' : 'none'}`} title="This source's risk signal, 0 to 100">
            {r.risk}
          </span>
        ) : null}
      </div>
      <div className="panel-body stack" style={{ gap: 8 }}>
        {r.headline ? <strong className="small">{r.headline}</strong> : null}
        {r.fields?.length ? (
          <dl className="intel-fields">
            {r.fields.map((f) => (
              <div key={f.label}>
                <dt>{f.label}</dt>
                <dd>
                  {/^https:\/\//.test(f.value) ? (
                    <a href={f.value} target="_blank" rel="noreferrer noopener">
                      {f.value}
                    </a>
                  ) : (
                    f.value
                  )}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
        {r.tags?.length ? (
          <div className="row" style={{ gap: 4, flexWrap: 'wrap' }}>
            {r.tags.slice(0, 12).map((t) => (
              <span key={t} className="tag">
                {t}
              </span>
            ))}
          </div>
        ) : null}
        {r.link ? (
          <a className="small" href={r.link} target="_blank" rel="noreferrer noopener">
            Open in {r.name} →
          </a>
        ) : null}
        <span className="xsmall muted">
          Checked <RelTime iso={r.checked_at} />
        </span>
      </div>
    </section>
  )
}

