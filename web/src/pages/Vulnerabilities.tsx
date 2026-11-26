// Vulnerability management: findings from your hosts' software lists, scored by risk.
// This page does its own alerting (the "New findings" panel); findings are not in the Alerts queue.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { errorMessage } from '../api/client'
import { acceptVuln, getVulns, refreshVulns, setOSV, vulnKey, type VulnBand, type VulnFinding, type VulnHost, type VulnReport } from '../api/vuln'
import { useCan } from '../components/Auth'
import { BarList } from '../components/Charts'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { KV, Pager, RelTime, Toggle } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { type Series, Legend, TimeSeriesChart } from '../components/SearchCharts'
import { EmptyState, QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber, plural } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { formatDate } from '../lib/time'
import {
  activeTile, BANDS, BAND_LABEL, coverageText, defaultFilters, tileFilters, epssText, exposureCounts, filterFindings, hostsByRisk, newFindings, packageLabel, scoreText, sortFindings, sourceProblems, weeklyHistory,
  type SortDir, type SortKey, type TileKey, type VulnFilters,
} from '../lib/vuln'

const PAGE = 100

export function VulnerabilitiesPage() {
  useDocumentTitle('Vulnerabilities')
  const qc = useQueryClient()
  const toast = useToast()
  const isAdmin = useCan('admin')
  const q = useQuery({ queryKey: vulnKey, queryFn: getVulns, refetchInterval: (query) => (query.state.data?.running ? 2000 : 60_000) })
  const refresh = useMutation({
    mutationFn: refreshVulns,
    onSuccess: (r) => qc.setQueryData(vulnKey, r),
    onError: (e) => toast.error(errorMessage(e)),
  })
  const busy = refresh.isPending || q.data?.running
  const problems = q.data ? sourceProblems(q.data.sources, q.data.hosts) : []
  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        subtitle={
          q.data ? (
            <>
              {q.data.last_run ? (
                <>
                  Last scan <RelTime iso={q.data.last_run} />
                </>
              ) : (
                'Not scanned yet'
              )}
              {problems.length ? ` · ${plural(problems.length, 'source problem')}` : ''}
            </>
          ) : (
            'Known flaws in software on your hosts, ranked by risk'
          )
        }
        actions={
          isAdmin ? (
            <button type="button" className="btn" disabled={!!busy} onClick={() => refresh.mutate()}>
              {busy ? <Spinner /> : <Icon name="refresh" size={14} />} Refresh
            </button>
          ) : null
        }
      />
      <QueryView query={q}>{(d) => <Body report={d} isAdmin={isAdmin} problems={problems} />}</QueryView>
    </>
  )
}

function Body({ report: r, isAdmin, problems }: { report: VulnReport; isAdmin: boolean; problems: string[] }) {
  const [openId, setOpenId] = useState<string | null>(null)
  const [filters, setFilters] = useState<VulnFilters>(defaultFilters)
  const [sort, setSort] = useState<{ key: SortKey; dir: SortDir }>({ key: 'risk', dir: 'desc' })
  const [offset, setOffset] = useState(0)
  const patch = (p: Partial<VulnFilters>) => {
    setFilters((f) => ({ ...f, ...p }))
    setOffset(0)
  }
  const fresh = useMemo(() => newFindings(r.findings), [r.findings])
  const hostOS = useMemo(() => Object.fromEntries(r.hosts.map((h) => [h.host_id, h.os])), [r.hosts])
  const rows = useMemo(() => sortFindings(filterFindings(r.findings, filters, { hostOS }), sort.key, sort.dir), [r.findings, filters, sort, hostOS])
  const page = rows.slice(offset, offset + PAGE)
  const s = r.summary

  const showFinding = (f: VulnFinding) => {
    setFilters({ ...defaultFilters, status: 'all', text: f.cve, host: f.host_id })
    setOffset(0)
    setOpenId(f.id)
    requestAnimationFrame(() => document.getElementById('vuln-table')?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  }
  const tile = activeTile(filters)
  // A tile lists what it counts; clicking the active one again clears it. The search text stays.
  const pickTile = (k: TileKey) => {
    setFilters((f) => ({ ...(tile === k && k !== 'open' ? defaultFilters : tileFilters(k)), text: f.text }))
    setOffset(0)
    setOpenId(null)
    requestAnimationFrame(() => document.getElementById('vuln-table')?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  }
  const tileProps = (k: TileKey) => ({ active: tile === k, onClick: () => pickTile(k) })
  const sortBy = (key: SortKey) => {
    setSort((c) => (c.key === key ? { key, dir: c.dir === 'desc' ? 'asc' : 'desc' } : { key, dir: key === 'host' ? 'asc' : 'desc' }))
    setOffset(0)
  }

  return (
    <div className="stack">
      {problems.length ? (
        <section className="panel">
          <div className="panel-header">
            <h2>What this page still needs</h2>
          </div>
          <div className="panel-body">
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {problems.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
            <div className="small" style={{ marginTop: 8 }}>
              See <Link to="/health">Data health</Link> and <Link to="/settings/lists">Settings → Offline lists</Link>.
            </div>
          </div>
        </section>
      ) : null}

      <div className="stats">
        <Tile label="Open" value={s.open} {...tileProps('open')} />
        <Tile label="Critical" value={s.critical} color="var(--sev-critical)" {...tileProps('critical')} />
        <Tile label="High" value={s.high} color="var(--sev-high)" {...tileProps('high')} />
        <Tile label="Internet-exposed" value={s.internet_exposed} sub="on hosts reachable from the internet" {...tileProps('internet')} />
        <Tile label="Actively exploited" value={s.kev} sub="on CISA’s known-exploited list" {...tileProps('kev')} />
        <Tile label="No fix yet" value={s.no_fix} sub="no patched version released" {...tileProps('nofix')} />
        <div className="stat">
          <span className="label">New / fixed this week</span>
          <span className="value">
            <button type="button" className="stat-link" aria-pressed={tile === 'new7d'} title="Show findings first seen this week" onClick={() => pickTile('new7d')}>
              {formatNumber(s.new_7d)}
            </button>
            {' / '}
            <button type="button" className="stat-link" aria-pressed={tile === 'fixed7d'} title="Show findings fixed this week" onClick={() => pickTile('fixed7d')}>
              {formatNumber(s.fixed_7d)}
            </button>
          </span>
        </div>
      </div>

      <section className="panel">
        <div className="panel-header">
          <h2>New findings</h2>
          <span className="small muted">Critical and high, first seen in the last 7 days</span>
        </div>
        {fresh.length ? (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {fresh.map((f) => (
              <li key={f.id} style={{ borderTop: '1px solid var(--border)' }}>
                <button
                  type="button"
                  onClick={() => showFinding(f)}
                  style={{ display: 'flex', gap: 10, alignItems: 'center', width: '100%', padding: '8px 14px', background: 'none', border: 0, color: 'inherit', font: 'inherit', textAlign: 'left', cursor: 'pointer' }}
                >
                  <BandBadge band={f.band} risk={f.risk} />
                  <span className="mono small">{f.cve}</span>
                  <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {f.title} <span className="muted">on {f.hostname}</span>
                  </span>
                  {f.kev ? <span className="badge warn">KEV</span> : null}
                  <span className="small muted nowrap">
                    <RelTime iso={f.first_seen} />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="No new critical or high findings" compact>
            Nothing serious has appeared in the last 7 days.
          </EmptyState>
        )}
      </section>

      <Charts report={r} />

      <section className="panel" id="vuln-table">
        <div className="panel-header">
          <h2>Findings</h2>
          <span className="small muted">
            {formatNumber(rows.length)} matching
            {filters.since ? ` · ${filters.since === 'new7d' ? 'first seen' : 'fixed'} in the last 7 days` : ''}
            {filters.since || filters.noFix ? (
              <>
                {' '}
                <button type="button" className="btn small ghost" onClick={() => patch({ since: '', noFix: false })}>
                  Clear
                </button>
              </>
            ) : null}
          </span>
        </div>
        <div className="panel-body" style={{ paddingBottom: 0 }}>
          <div className="filters" style={{ marginBottom: 0 }}>
            <input
              type="search"
              className="input"
              style={{ minWidth: 300 }}
              placeholder="Search: CVE, app, OS, title, cvss>=7…"
              title={SEARCH_HELP}
              value={filters.text}
              onChange={(e) => patch({ text: e.target.value })}
              aria-label="Search findings"
            />
            <select className="select" value={filters.status} onChange={(e) => patch({ status: e.target.value as VulnFilters['status'] })} aria-label="Status">
              <option value="open">Open</option>
              <option value="accepted">Accepted</option>
              <option value="fixed">Fixed</option>
              <option value="all">All statuses</option>
            </select>
            <select className="select" value={filters.band} onChange={(e) => patch({ band: e.target.value as VulnBand | '' })} aria-label="Band">
              <option value="">All bands</option>
              {BANDS.map((b) => (
                <option key={b} value={b}>
                  {BAND_LABEL[b]}
                </option>
              ))}
            </select>
            <select className="select" value={filters.host} onChange={(e) => patch({ host: e.target.value })} aria-label="Host">
              <option value="">All hosts</option>
              {r.hosts.map((h) => (
                <option key={h.host_id} value={h.host_id}>
                  {h.hostname}
                </option>
              ))}
            </select>
            <select className="select" value={filters.exposure} onChange={(e) => patch({ exposure: e.target.value as VulnFilters['exposure'] })} aria-label="Exposure">
              <option value="">Any exposure</option>
              <option value="internet">Internet</option>
              <option value="lan">LAN only</option>
            </select>
            <div className="chips" role="group" aria-label="Quick filters">
              <button type="button" className="chip" aria-pressed={filters.kevOnly} onClick={() => patch({ kevOnly: !filters.kevOnly })}>
                KEV only
              </button>
              <button type="button" className="chip" aria-pressed={filters.hasFix} onClick={() => patch({ hasFix: !filters.hasFix, noFix: false })}>
                Has fix
              </button>
              <button type="button" className="chip" aria-pressed={filters.noFix} onClick={() => patch({ noFix: !filters.noFix, hasFix: false })}>
                No fix yet
              </button>
            </div>
          </div>
          <div className="xsmall muted" style={{ marginTop: 6 }}>
            Words match the CVE, software, version, host, OS and title. Narrow with <span className="mono">app:openssl</span>, <span className="mono">os:debian</span>,{' '}
            <span className="mono">host:web01</span>, <span className="mono">title:"remote code"</span>, <span className="mono">cvss&gt;=9</span>, <span className="mono">risk&gt;7</span>,{' '}
            <span className="mono">epss&gt;10%</span>; put <span className="mono">-</span> before a word to leave it out.
          </div>
        </div>
        {rows.length ? (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <SortTh label="Risk" k="risk" sort={sort} onSort={sortBy} />
                    <th>CVE</th>
                    <SortTh label="Host" k="host" sort={sort} onSort={sortBy} />
                    <th>Package</th>
                    <SortTh label="CVSS" k="cvss" sort={sort} onSort={sortBy} />
                    <SortTh label="Likelihood" k="likelihood" sort={sort} onSort={sortBy} />
                    <SortTh label="EPSS" k="epss" sort={sort} onSort={sortBy} />
                    <th>Exposure</th>
                    <th>KEV</th>
                    <SortTh label="First seen" k="first_seen" sort={sort} onSort={sortBy} />
                  </tr>
                </thead>
                <tbody>
                  {page.map((f) => (
                    <Fragment key={f.id}>
                      <tr onClick={() => setOpenId(openId === f.id ? null : f.id)} style={{ cursor: 'pointer', opacity: f.status === 'open' ? 1 : 0.7 }} aria-expanded={openId === f.id}>
                        <td>
                          <BandBadge band={f.band} risk={f.risk} />
                          {f.status !== 'open' ? <span className="badge status false_positive" style={{ marginLeft: 6 }}>{f.status === 'fixed' ? 'Fixed' : 'Accepted'}</span> : null}
                        </td>
                        <td className="nowrap" onClick={(e) => e.stopPropagation()}>
                          <a className="mono small" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}`} target="_blank" rel="noopener noreferrer">
                            {f.cve}
                          </a>
                        </td>
                        <td>{f.hostname}</td>
                        <td style={{ whiteSpace: 'normal', minWidth: 200 }}>
                          <div className="mono small">{packageLabel(f)}</div>
                          <div className="xsmall muted">
                            {f.version || '—'} → {f.fixed_version || <strong>no fix yet</strong>}
                          </div>
                        </td>
                        <td className="num">{f.cvss === null ? '—' : f.cvss.toFixed(1)}</td>
                        <td className="num">{f.likelihood.toFixed(1)}</td>
                        <td className="num">{epssText(f.epss)}</td>
                        <td>{f.exposure === 'internet' ? <span className="badge warn">Internet</span> : <span className="small muted">LAN</span>}</td>
                        <td>{f.kev ? <span className="badge status new">KEV</span> : <span className="empty-cell">—</span>}</td>
                        <td className="nowrap small">{formatDate(f.first_seen)}</td>
                      </tr>
                      {openId === f.id ? (
                        <tr className="detail-row">
                          <td colSpan={10}>
                            <Detail f={f} isAdmin={isAdmin} />
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={PAGE} total={rows.length} shown={page.length} onChange={setOffset} />
          </>
        ) : (
          <EmptyState title="No findings match" compact>
            {r.findings.length ? 'Change or clear the filters.' : 'Nothing has been found yet.'}
          </EmptyState>
        )}
      </section>

      <HostsPanel hosts={r.hosts} />
      <SourcesPanel report={r} isAdmin={isAdmin} />
    </div>
  )
}

const SEARCH_HELP =
  'Words match the CVE, software, version, host, OS and title. Fields: app:, os:, host:, cve:, title:, type:. Numbers: cvss>=9, risk>7, epss>10%, likelihood<3. -word leaves it out.'

/** A summary tile that filters the findings table to what it counts. */
function Tile({ label, value, sub, color, active, onClick }: { label: string; value: number; sub?: string; color?: string; active: boolean; onClick: () => void }) {
  return (
    <button type="button" className="stat stat-button" aria-pressed={active} title={`Show these findings: ${label.toLowerCase()}`} onClick={onClick}>
      <span className="label">{label}</span>
      <span className="value" style={color ? { color } : undefined}>
        {formatNumber(value)}
      </span>
      {sub ? <span className="sub">{sub}</span> : null}
    </button>
  )
}

function BandBadge({ band, risk }: { band: VulnBand; risk: number }) {
  return (
    <span className={`badge sev ${band}`} title={`${BAND_LABEL[band]} risk`}>
      <span className="num">{risk.toFixed(1)}</span> {BAND_LABEL[band]}
    </span>
  )
}

function SortTh({ label, k, sort, onSort }: { label: string; k: SortKey; sort: { key: SortKey; dir: SortDir }; onSort: (k: SortKey) => void }) {
  const on = sort.key === k
  return (
    <th aria-sort={on ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'} style={{ padding: 0 }}>
      <button type="button" className="th-sort" onClick={() => onSort(k)} style={{ whiteSpace: 'nowrap' }}>
        {label}
        <span aria-hidden="true">{on ? (sort.dir === 'asc' ? '▲' : '▼') : ''}</span>
      </button>
    </th>
  )
}

function Charts({ report: r }: { report: VulnReport }) {
  const h = r.history
  const enough = h.length >= 2
  const times = h.map((p) => `${p.date}T00:00:00Z`)
  const bandSeries: Series[] = [
    { name: 'Low', values: h.map((p) => p.low), color: 'var(--sev-low)' },
    { name: 'Medium', values: h.map((p) => p.medium), color: 'var(--sev-medium)' },
    { name: 'High', values: h.map((p) => p.high), color: 'var(--sev-high)' },
    { name: 'Critical', values: h.map((p) => p.critical), color: 'var(--sev-critical)' },
  ]
  const weeks = weeklyHistory(h)
  const weekSeries: Series[] = [
    { name: 'New', values: weeks.map((w) => w.new), color: 'var(--sev-high)' },
    { name: 'Fixed', values: weeks.map((w) => w.fixed), color: 'var(--ok)' },
  ]
  const hosts = hostsByRisk(r.hosts).slice(0, 8)
  const ex = exposureCounts(r.findings)
  const empty = (
    <EmptyState title="Not enough history yet" compact>
      Charts need at least two daily snapshots. They fill in as scans run.
    </EmptyState>
  )
  return (
    <div className="grid grid-2">
      <section className="panel">
        <div className="panel-header">
          <h2>Open findings over time</h2>
        </div>
        <div className="viz">
          {enough ? (
            <>
              <TimeSeriesChart times={times} series={bandSeries} spanSec={86400} kind="column" height={200} />
              <Legend series={[...bandSeries].reverse()} kind="column" />
            </>
          ) : (
            empty
          )}
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>New and fixed per week</h2>
        </div>
        <div className="viz">
          {enough ? (
            <>
              <TimeSeriesChart times={weeks.map((w) => `${w.week}T00:00:00Z`)} series={weekSeries} spanSec={7 * 86400} kind="column" height={200} />
              <Legend series={weekSeries} kind="column" />
            </>
          ) : (
            empty
          )}
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Risk by host</h2>
          <span className="small muted">open findings, worst first</span>
        </div>
        <div className="panel-body">
          {hosts.length ? (
            <BarList
              items={hosts.map((x) => ({
                key: x.host_id,
                label: `${x.hostname} · highest risk ${x.max_risk.toFixed(1)}`,
                value: x.open,
                color: `var(--sev-${x.max_risk >= 8 ? 'critical' : x.max_risk >= 6 ? 'high' : x.max_risk >= 3 ? 'medium' : 'low'})`,
              }))}
            />
          ) : (
            <span className="small muted">No host has open findings.</span>
          )}
        </div>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Exposure</h2>
          <span className="small muted">open findings by where the host can be reached from</span>
        </div>
        <div className="panel-body">
          <BarList
            items={[
              { key: 'internet', label: 'Internet', value: ex.internet, color: 'var(--sev-high)' },
              { key: 'lan', label: 'LAN only', value: ex.lan, color: 'var(--sev-low)' },
            ]}
          />
        </div>
      </section>
    </div>
  )
}

function Detail({ f, isAdmin }: { f: VulnFinding; isAdmin: boolean }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [note, setNote] = useState(f.accepted_note)
  const save = useMutation({
    mutationFn: (accepted: boolean) => acceptVuln({ host_id: f.host_id, package: f.package, cve: f.cve, accepted, note: accepted ? note.trim() : '' }),
    onSuccess: (d) => qc.setQueryData(vulnKey, d),
    onError: (e) => toast.error(errorMessage(e)),
  })
  return (
    <div className="stack" style={{ padding: '6px 4px' }}>
      <div>
        <strong>{f.title}</strong>
        {f.summary ? <p className="small" style={{ margin: '4px 0 0' }}>{f.summary}</p> : null}
      </div>
      <div>
        <div className="small muted">How the score was worked out</div>
        <div className="mono small">{scoreText(f)}</div>
        {f.likelihood_reasons.length ? (
          <ul className="small" style={{ margin: '4px 0 0', paddingLeft: 18 }}>
            {f.likelihood_reasons.map((x) => (
              <li key={x}>{x}</li>
            ))}
          </ul>
        ) : null}
      </div>
      <KV
        items={[
          ['CVSS vector', f.cvss_vector ? <span className="mono small">{f.cvss_vector}</span> : '—'],
          ['Severity source', f.severity_source === 'estimated' ? 'Estimated (no published score)' : f.severity_source.toUpperCase()],
          ['EPSS', f.epss === null ? '—' : `${epssText(f.epss)} chance of exploitation in 30 days${f.epss_percentile === null ? '' : ` (percentile ${Math.round(f.epss_percentile * 100)})`}`],
          ['CISA KEV', f.kev ? `Yes${f.kev_due_date ? `, fix due ${f.kev_due_date}` : ''}${f.ransomware ? ', used by ransomware groups' : ''}` : 'No'],
          ['Exposure', f.exposure === 'internet' ? `Internet${f.exposed_ports.length ? `, ports ${f.exposed_ports.join(', ')}` : ''}` : `LAN only${f.exposed_ports.length ? `, ports ${f.exposed_ports.join(', ')}` : ''}`],
          ['Attack vector', f.attack_vector || '—'],
          ['Confidence', f.confidence === 'confirmed' ? 'Confirmed' : 'Possible: the name matches, the version was not checked'],
          ['Installed', <span className="mono small">{f.version || '—'}</span>],
          ['Fixed in', f.fixed_version ? <span className="mono small">{f.fixed_version}</span> : 'No fix released yet'],
          ['First / last seen', `${formatDate(f.first_seen)} / ${formatDate(f.last_seen)}`],
          ...(f.fixed_at ? ([['Fixed', formatDate(f.fixed_at)]] as [string, string][]) : []),
          ...(f.status === 'accepted' ? ([['Accepted note', f.accepted_note || '—']] as [string, string][]) : []),
        ]}
      />
      {isAdmin && f.status !== 'fixed' ? (
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          {f.status === 'open' ? (
            <>
              <input className="input" style={{ minWidth: 260 }} placeholder="Why is this risk acceptable?" value={note} onChange={(e) => setNote(e.target.value)} aria-label="Note" />
              <button type="button" className="btn" disabled={save.isPending} onClick={() => save.mutate(true)}>
                Accept risk
              </button>
            </>
          ) : (
            <button type="button" className="btn" disabled={save.isPending} onClick={() => save.mutate(false)}>
              Undo
            </button>
          )}
        </div>
      ) : null}
    </div>
  )
}

function snapshotAge(h: VulnHost): React.ReactNode {
  return h.snapshot_at ? <RelTime iso={h.snapshot_at} /> : <span className="empty-cell">—</span>
}

function HostsPanel({ hosts }: { hosts: VulnHost[] }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Hosts</h2>
      </div>
      {hosts.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Coverage</th>
                <th>Packages</th>
                <th>Software list</th>
                <th>Exposure</th>
                <th>Open</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.host_id}>
                  <td>
                    <Link to={`/hosts/${encodeURIComponent(h.host_id)}`}>{h.hostname}</Link>
                    <div className="xsmall muted">{h.os}</div>
                  </td>
                  <td style={{ whiteSpace: 'normal', minWidth: 260 }}>
                    <span className="small">{coverageText(h.coverage)}</span>
                    {h.note ? <div className="xsmall muted">{h.note}</div> : null}
                  </td>
                  <td className="num">{formatNumber(h.packages)}</td>
                  <td>{snapshotAge(h)}</td>
                  <td className="small">{h.exposure === 'internet' ? `Internet${h.exposed_ports.length ? ` (${h.exposed_ports.join(', ')})` : ''}` : 'LAN only'}</td>
                  <td className="num">{formatNumber(h.open)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="No hosts" compact>
          Software lists come from endpoint agents.
        </EmptyState>
      )}
    </section>
  )
}

function SourcesPanel({ report: r, isAdmin }: { report: VulnReport; isAdmin: boolean }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [confirming, setConfirming] = useState(false)
  const save = useMutation({
    mutationFn: setOSV,
    onSuccess: (d) => qc.setQueryData(vulnKey, d),
    onError: (e) => toast.error(errorMessage(e)),
  })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Sources</h2>
      </div>
      <div className="table-wrap">
        <table className="table compact">
          <thead>
            <tr>
              <th>Source</th>
              <th>Entries</th>
              <th>Updated</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {r.sources.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td>
                <td className="num">{formatNumber(s.entries)}</td>
                <td>
                  <RelTime iso={s.last_update} />
                </td>
                <td className="small" style={s.error ? { color: 'var(--danger)', whiteSpace: 'normal' } : undefined}>
                  {s.error ? s.error : s.enabled ? 'OK' : 'Off'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="panel-body stack" style={{ gap: 6, borderTop: '1px solid var(--border)' }}>
        <Toggle
          checked={r.osv_api.enabled}
          disabled={!isAdmin || save.isPending}
          label="Ask OSV about possible matches (optional)"
          onChange={(on) => (on ? setConfirming(true) : save.mutate(false))}
        />
        <p className="small muted" style={{ margin: 0 }}>
          Off by default. When on, the names and versions of possibly matching packages are sent to api.osv.dev, an outside service run by Google. For Unraid hosts, the OS name and version are sent to the U.S. National Vulnerability Database (services.nvd.nist.gov), which settles which CVEs apply to that release. Nothing else about your hosts is sent.
        </p>
        {r.osv_api.error ? (
          <div className="small" style={{ color: 'var(--danger)' }}>
            Last error: {r.osv_api.error}
          </div>
        ) : null}
      </div>
      <ConfirmDialog
        open={confirming}
        title="Send package names to OSV?"
        confirmLabel="Turn on"
        onClose={() => setConfirming(false)}
        onConfirm={() => {
          setConfirming(false)
          save.mutate(true)
        }}
      >
        The names and versions of possibly matching packages will be sent to api.osv.dev, an outside service, and an Unraid host's OS version to services.nvd.nist.gov. This tells them some of what you run.
      </ConfirmDialog>
    </section>
  )
}
