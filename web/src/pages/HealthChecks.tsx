// Data health → Doctor and Self-check tabs.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { errorMessage } from '../api/client'
import { doctorKey, getDoctor, getSelfCheck, selfCheckKey, startSelfCheck, type CheckResult, type CheckStatus, type SelfCheckCoverage, type SelfCheckResult } from '../api/health'
import { Icon } from '../components/Icon'
import { RelTime } from '../components/Misc'
import { EmptyState, QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { rateDelta } from '../lib/health'

const CHECK_LABEL: Record<CheckStatus, string> = { ok: 'OK', warn: 'Attention', fail: 'Failed', skip: 'Not used' }
const CHECK_BADGE: Record<CheckStatus, string> = { ok: 'resolved', warn: 'in_progress', fail: 'new', skip: 'false_positive' }
const CHECK_ORDER: CheckStatus[] = ['fail', 'warn', 'ok', 'skip']

export function DoctorTab() {
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: doctorKey, queryFn: () => getDoctor() })
  const refresh = useMutation({
    mutationFn: () => getDoctor(true),
    onSuccess: (r) => qc.setQueryData(doctorKey, r),
    onError: (e) => toast.error(errorMessage(e)),
  })
  return (
    <div className="stack">
      <p className="small muted" style={{ margin: 0 }}>
        Plain checks on whether this install is working, each with a suggested fix. The same checks run from the command line with <code>homexdr-server doctor</code>. No secrets appear in the
        results.
      </p>
      <section className="panel">
        <div className="panel-header">
          <h2>Checks</h2>
          <button type="button" className="btn" onClick={() => refresh.mutate()} disabled={refresh.isPending}>
            {refresh.isPending ? <Spinner /> : <Icon name="refresh" size={14} />} Run again
          </button>
        </div>
        <QueryView query={q}>
          {(d) => (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Check</th>
                    <th>Result</th>
                    <th>What it found</th>
                  </tr>
                </thead>
                <tbody>
                  {[...d.results].sort((a, b) => CHECK_ORDER.indexOf(a.status) - CHECK_ORDER.indexOf(b.status)).map((r) => (
                    <CheckRow key={r.id} r={r} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>
    </div>
  )
}

function CheckRow({ r }: { r: CheckResult }) {
  return (
    <tr>
      <td className="nowrap">{r.name}</td>
      <td>
        <span className={`badge status ${CHECK_BADGE[r.status]}`}>{CHECK_LABEL[r.status]}</span>
      </td>
      <td style={{ whiteSpace: 'normal' }}>
        <div className="small">{r.message}</div>
        {r.fix ? <div className="xsmall muted">Fix: {r.fix}</div> : null}
      </td>
    </tr>
  )
}

export function SelfCheckTab() {
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({
    queryKey: selfCheckKey,
    queryFn: getSelfCheck,
    refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
  })
  const run = useMutation({
    mutationFn: startSelfCheck,
    onSuccess: (s) => qc.setQueryData(selfCheckKey, s),
    onError: (e) => toast.error(errorMessage(e)),
  })
  const running = q.data?.running || run.isPending
  return (
    <div className="stack">
      <p className="small muted" style={{ margin: 0 }}>
        Measures whether your loaded rules can actually fire. It writes nothing to your events and creates no real alerts. The same check runs with <code>homexdr-server selfcheck</code>, which exits
        with an error when the result gets worse.
      </p>
      <div>
        <button type="button" className="btn primary" onClick={() => run.mutate()} disabled={running}>
          {running ? <Spinner /> : <Icon name="refresh" size={14} />} {running ? 'Running…' : 'Run self-check'}
        </button>
      </div>
      <QueryView query={q}>
        {(d) =>
          d.last ? (
            <Result r={d.last} />
          ) : (
            <section className="panel">
              <EmptyState title="Not run yet">Run the self-check to see how many of your rules can fire on this install.</EmptyState>
            </section>
          )
        }
      </QueryView>
    </div>
  )
}

function Result({ r }: { r: SelfCheckResult }) {
  return (
    <>
      {r.regression ? (
        <section className="panel">
          <div className="panel-body small" style={{ color: 'var(--danger)' }}>
            Worse than the previous run. {r.reason}
          </div>
        </section>
      ) : null}
      <section className="panel">
        <div className="panel-header">
          <h2>Rule logic</h2>
          <span className="small muted">
            Run <RelTime iso={r.at} />
          </span>
        </div>
        <div className="panel-body stack">
          <div>
            <strong style={{ fontSize: 24 }}>{r.rate.toFixed(1)}%</strong>{' '}
            <span className="small muted">
              {formatNumber(r.fired)} of {formatNumber(r.rules)} enabled rules fired on an event built from their own selection.
              {r.previous ? ` ${rateDelta(r.rate, r.previous.rate)}` : ''}
            </span>
          </div>
          <div className="small">
            <span className={`badge status ${r.pipeline.passed ? 'resolved' : 'new'}`}>{r.pipeline.passed ? 'Pipeline OK' : 'Pipeline failed'}</span> {r.pipeline.message}
          </div>
          {r.failures.length ? (
            <details>
              <summary className="small">
                {formatNumber(r.failed)} {r.failed === 1 ? 'rule' : 'rules'} did not fire
              </summary>
              <ul className="small" style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {r.failures.map((f) => (
                  <li key={f.rule_id}>
                    {f.title}: <span className="muted">{f.reason}</span>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </div>
      </section>
      {r.coverage ? <Coverage c={r.coverage} /> : null}
    </>
  )
}

function Coverage({ c }: { c: SelfCheckCoverage }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Can they fire on your data?</h2>
      </div>
      <div className="panel-body stack">
        {c.events > 0 ? (
          <div>
            <strong style={{ fontSize: 24 }}>{formatNumber(c.cannot_fire)}</strong>{' '}
            <span className="small muted">
              of {formatNumber(c.rules)} rules cannot fire on this install, because no event of that kind has been seen in the last {c.days} days, or those events lack a field the rule needs. Based on{' '}
              {formatNumber(c.events)} events sampled from {c.sources} sources, so a rare field can be missed. Rules for Windows cannot fire on a Linux and firewall install: that is expected, and you
              may want to turn them off.
            </span>
          </div>
        ) : null}
        {c.note ? <div className="small muted">{c.note}</div> : null}
      </div>
      {c.groups.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Log source</th>
                <th className="num">Rules</th>
                <th className="num">Can fire</th>
                <th className="num">No such events</th>
                <th className="num">Missing a field</th>
                <th>Fields missing</th>
              </tr>
            </thead>
            <tbody>
              {c.groups.map((g) => (
                <tr key={g.logsource}>
                  <td className="mono small">{g.logsource}</td>
                  <td className="num">{formatNumber(g.rules)}</td>
                  <td className="num">{formatNumber(g.can_fire)}</td>
                  <td className="num">{formatNumber(g.no_events)}</td>
                  <td className="num">{formatNumber(g.missing_field)}</td>
                  <td className="small muted" style={{ whiteSpace: 'normal' }}>
                    {g.missing?.map((f) => `${f.field} (${f.rules})`).join(', ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  )
}
