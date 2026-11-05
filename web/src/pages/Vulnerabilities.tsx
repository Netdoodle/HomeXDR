// Known-exploited software: what your agents report, compared with CISA's catalog.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import { errorMessage } from '../api/client'
import { getVulns, refreshVulns, setOSV, vulnKey, type VulnMatch, type VulnReport } from '../api/vuln'
import { useCan } from '../components/Auth'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { RelTime, Toggle } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { EmptyState, QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { missingData, packageLabel } from '../lib/vuln'

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
  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        subtitle="Software on your hosts that CISA lists as being exploited"
        actions={
          isAdmin ? (
            <button type="button" className="btn" disabled={refresh.isPending || q.data?.running} onClick={() => refresh.mutate()}>
              {refresh.isPending || q.data?.running ? <Spinner /> : <Icon name="refresh" size={14} />} Check now
            </button>
          ) : null
        }
      />
      <QueryView query={q}>{(d) => <Body report={d} isAdmin={isAdmin} />}</QueryView>
    </>
  )
}

function Body({ report: r, isAdmin }: { report: VulnReport; isAdmin: boolean }) {
  const needs = missingData(r)
  return (
    <div className="stack">
      <p className="small muted" style={{ margin: 0 }}>
        CISA’s catalog names products, not version ranges. So a <strong>possible match</strong> only means the name is the same, and your version may well be fine. A match is <strong>confirmed</strong>{' '}
        only when a version check agrees, and only confirmed matches raise an alert.
      </p>
      {needs.length ? (
        <section className="panel">
          <div className="panel-header">
            <h2>What this page still needs</h2>
          </div>
          <div className="panel-body">
            <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
              {needs.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
            <div className="small" style={{ marginTop: 8 }}>
              See <Link to="/health">Data health</Link> and <Link to="/settings/lists">Settings → Offline lists</Link>.
            </div>
          </div>
        </section>
      ) : null}
      <section className="panel">
        <div className="panel-header">
          <h2>
            {formatNumber(r.confirmed)} confirmed, {formatNumber(r.possible)} possible
          </h2>
          <span className="small muted">
            {r.kev.version ? `Catalog ${r.kev.version}. ` : ''}
            {r.last_run ? (
              <>
                Checked <RelTime iso={r.last_run} />
              </>
            ) : null}
          </span>
        </div>
        {r.matches.length ? (
          <MatchTable matches={r.matches} />
        ) : (
          <EmptyState title={needs.length ? 'Nothing to compare yet' : 'No known-exploited software found'}>
            {needs.length
              ? 'This page compares each host’s newest software list with CISA’s catalog, so it needs both.'
              : 'None of the software your agents report matches CISA’s catalog.'}
          </EmptyState>
        )}
      </section>
      <OSVPanel report={r} isAdmin={isAdmin} />
    </div>
  )
}

function MatchTable({ matches }: { matches: VulnMatch[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Host</th>
            <th>Package</th>
            <th>Version</th>
            <th>CVE</th>
            <th>Added to the catalog</th>
            <th>CISA deadline</th>
            <th>Ransomware</th>
            <th>Confidence</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((m) => (
            <tr key={`${m.host_id}/${m.package}/${m.cve}`}>
              <td>
                <Link to={`/hosts/${encodeURIComponent(m.host_id)}`}>{m.hostname}</Link>
              </td>
              <td className="mono small">{packageLabel(m)}</td>
              <td className="mono small">{m.version || '—'}</td>
              <td style={{ whiteSpace: 'normal', minWidth: 220 }}>
                <a className="mono small" href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(m.cve)}`} target="_blank" rel="noreferrer">
                  {m.cve}
                </a>
                <div className="xsmall muted">{m.title}</div>
              </td>
              <td className="nowrap">{m.kev_date}</td>
              <td className="nowrap">{m.due_date}</td>
              <td>{m.ransomware ? <span className="badge status new">Known use</span> : <span className="empty-cell">—</span>}</td>
              <td style={{ whiteSpace: 'normal', minWidth: 220 }}>
                <span className={`badge status ${m.confidence === 'confirmed' ? 'new' : 'false_positive'}`}>{m.confidence === 'confirmed' ? 'Confirmed' : 'Possible match'}</span>
                <div className="xsmall muted">{m.reason}</div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function OSVPanel({ report: r, isAdmin }: { report: VulnReport; isAdmin: boolean }) {
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
        <h2>Version check with OSV (optional)</h2>
        <Toggle
          checked={r.osv.enabled}
          disabled={!isAdmin || save.isPending}
          label="Ask OSV about possible matches"
          onChange={(on) => (on ? setConfirming(true) : save.mutate(false))}
        />
      </div>
      <div className="panel-body stack" style={{ gap: 6 }}>
        <p className="small" style={{ margin: 0 }}>
          Off by default. When on, the names and versions of possibly matching packages are sent to api.osv.dev, an outside service run by Google, and nothing else about your hosts. If OSV lists that
          version as affected, the match becomes confirmed. It knows Debian, Ubuntu and Alpine packages, not Slackware or Unraid packages or Docker images.
        </p>
        {r.osv.error ? (
          <div className="small" style={{ color: 'var(--danger)' }}>
            Last error: {r.osv.error}
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
        The names and versions of possibly matching packages will be sent to api.osv.dev, an outside service. This tells them some of what you run.
      </ConfirmDialog>
    </section>
  )
}
