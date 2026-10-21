// The AI analyst's triage report on an alert, and its verdict badge for lists.
// Everything the model wrote is shown as plain text: it was produced from data that can
// contain attacker-controlled strings, so nothing in it is rendered as HTML or links,
// except event IDs, which are turned into search links by the console itself.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef } from 'react'
import { Link } from 'react-router'
import { api, queryKeys, type AITriage, type AITriageSummary } from '../api'
import { eventSearchHref, formatTokens, TRIAGE_STATUS_LABEL, VERDICT_LABEL } from '../lib/ai'
import { formatNumber } from '../lib/format'
import { formatDateTime } from '../lib/time'
import { useCan } from './Auth'
import { SeverityBadge } from './Badges'
import { Icon } from './Icon'
import { KV, RelTime } from './Misc'
import { ErrorState, Loading, Spinner } from './States'
import { useToast } from './Toast'

/** Verdict (or progress) badge for alert lists. */
export function AIVerdictBadge({ triage }: { triage?: AITriageSummary }) {
  if (!triage) return null
  if (triage.status === 'done' && triage.verdict) {
    const title = `AI verdict: ${VERDICT_LABEL[triage.verdict]}${triage.confidence ? ` (${triage.confidence} confidence)` : ''}`
    return (
      <span className={`badge ai ${triage.verdict}`} title={title}>
        <Icon name="sparkle" size={10} />
        {VERDICT_LABEL[triage.verdict]}
      </span>
    )
  }
  const pending = triage.status === 'queued' || triage.status === 'running'
  return (
    <span className={`badge ai ${pending ? 'pending' : 'failed'}`} title={`AI analyst: ${TRIAGE_STATUS_LABEL[triage.status]}`}>
      <Icon name="sparkle" size={10} />
      {TRIAGE_STATUS_LABEL[triage.status]}
    </span>
  )
}

const inProgress = (t?: AITriage | null) => t?.status === 'queued' || t?.status === 'running'

export function AITriagePanel({ alertId }: { alertId: string }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canRequest = useCan('analyst')
  const isAdmin = useCan('admin')
  const q = useQuery({
    queryKey: queryKeys.alertTriage(alertId),
    queryFn: () => api.getAlertTriage(alertId),
    refetchInterval: (query) => (inProgress(query.state.data?.triage) ? 3000 : false),
  })
  const request = useMutation({
    mutationFn: () => api.requestAlertTriage(alertId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: queryKeys.alertTriage(alertId) })
      qc.invalidateQueries({ queryKey: queryKeys.alerts() })
    },
    onError: (e) => toast.error(e),
  })
  const t = q.data?.triage ?? null
  const finished = t?.status === 'done' && t.verdict
  // Refresh the alert list's badge when an investigation we watched finishes.
  const wasRunning = useRef(false)
  useEffect(() => {
    if (inProgress(t)) wasRunning.current = true
    else if (wasRunning.current) {
      wasRunning.current = false
      qc.invalidateQueries({ queryKey: queryKeys.alerts() })
    }
  }, [t, qc])
  const runButton =
    canRequest && q.data?.available && !inProgress(t) ? (
      <button type="button" className="btn sm" onClick={() => request.mutate()} disabled={request.isPending}>
        <Icon name={t ? 'refresh' : 'sparkle'} size={12} /> {t ? 'Investigate again' : 'Investigate with AI'}
      </button>
    ) : null

  return (
    <section className="panel" aria-label="AI analyst">
      <div className="panel-header">
        <h2 className="row" style={{ gap: 8 }}>
          <Icon name="sparkle" size={14} /> AI analyst
          {finished ? <AIVerdictBadge triage={t} /> : null}
        </h2>
        <span className="row">
          {q.isFetching || request.isPending ? <Spinner small /> : null}
          {runButton}
        </span>
      </div>
      <div className="panel-body">
        {q.isPending ? (
          <Loading label="Loading…" />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : !t ? (
          <p className="muted small" style={{ margin: 0 }}>
            {q.data.available ? (
              'Not investigated. Alerts at or above the configured severity are investigated automatically.'
            ) : (
              <>
                The AI analyst is not set up: {q.data.reason}.{' '}
                {isAdmin ? <Link to="/settings/ai">Configure it</Link> : 'Ask an admin to configure it.'}
              </>
            )}
          </p>
        ) : inProgress(t) ? (
          <p className="row small" style={{ margin: 0 }}>
            <Spinner small />
            {t.status === 'queued' ? (
              <span>{t.engine === 'mcp' ? 'Waiting for an MCP client (the MCP runner or your AI tool)…' : 'Queued for investigation…'}</span>
            ) : (
              <span>
                {t.engine === 'mcp' ? 'An MCP client is investigating' : 'Investigating'}
                {t.started_at ? (
                  <>
                    {' '}
                    since <RelTime iso={t.started_at} />
                  </>
                ) : null}
                …
              </span>
            )}
          </p>
        ) : t.status !== 'done' ? (
          <div className="callout warn">
            <Icon name="warning" size={14} />
            <div>
              <strong>{TRIAGE_STATUS_LABEL[t.status]}.</strong> {t.error}
            </div>
          </div>
        ) : t.report ? (
          <ReportView triage={t} />
        ) : null}
      </div>
    </section>
  )
}

function ReportView({ triage: t }: { triage: AITriage }) {
  const r = t.report!
  return (
    <div className="stack" style={{ gap: 14 }}>
      <p className="ai-text" style={{ fontWeight: 600 }}>
        {r.summary}
      </p>
      <KV
        items={[
          ['Verdict', <AIVerdictBadge key="v" triage={{ status: 'done', verdict: r.verdict, confidence: r.confidence }} />],
          ['Confidence', r.confidence],
          ['AI severity view', <SeverityBadge key="s" severity={r.severity_assessment} />],
        ]}
      />
      <div>
        <h3 className="small muted" style={{ margin: '0 0 4px' }}>
          Analysis
        </h3>
        <p className="ai-text small">{r.analysis}</p>
      </div>
      {r.evidence.length > 0 ? (
        <div>
          <h3 className="small muted" style={{ margin: '0 0 4px' }}>
            Evidence
          </h3>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {r.evidence.map((e, i) => (
              <li key={i}>
                <Link className="mono xsmall" to={eventSearchHref(e.event_id, t.created_at)}>
                  {e.event_id}
                </Link>{' '}
                <span className="ai-text">{e.observation}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {r.mitre.length > 0 ? (
        <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          {r.mitre.map((m) => (
            <span key={m.technique_id} className="tag mono xsmall" title={m.name}>
              {m.technique_id} {m.name}
            </span>
          ))}
        </div>
      ) : null}
      {r.recommended_actions.length > 0 ? (
        <div>
          <h3 className="small muted" style={{ margin: '0 0 4px' }}>
            Recommended actions (for you to decide)
          </h3>
          <ol className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {r.recommended_actions.map((a, i) => (
              <li key={i}>
                <span className="ai-text" style={{ fontWeight: 600 }}>
                  {a.action}
                </span>
                {a.reason ? <span className="ai-text muted"> — {a.reason}</span> : null}
              </li>
            ))}
          </ol>
        </div>
      ) : null}
      {r.open_questions.length > 0 ? (
        <div>
          <h3 className="small muted" style={{ margin: '0 0 4px' }}>
            Open questions
          </h3>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {r.open_questions.map((qn, i) => (
              <li key={i} className="ai-text">
                {qn}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <TranscriptView triage={t} />
      <p className="xsmall faint" style={{ margin: 0 }}>
        {t.model ? `Written by ${t.model}` : 'Written by the AI analyst'}
        {t.engine === 'mcp' ? ' through MCP' : ''}
        {t.finished_at ? ` on ${formatDateTime(t.finished_at)}` : ''} · {t.trigger === 'manual' ? `requested by ${t.requested_by}` : 'automatic'} ·{' '}
        {t.engine === 'mcp'
          ? `${t.tool_calls} tool calls, on the client's own subscription.`
          : `${formatTokens(t.usage.input_tokens + t.usage.cache_read_tokens)} tokens in, ${formatTokens(t.usage.output_tokens)} out.`}{' '}
        AI output can be wrong,
        and it worked from data that may contain attacker-written text.
      </p>
    </div>
  )
}

function TranscriptView({ triage: t }: { triage: AITriage }) {
  const calls = (t.transcript ?? []).filter((c) => c.tool !== 'submit_triage')
  if (calls.length === 0) return null
  return (
    <details>
      <summary className="small" style={{ cursor: 'pointer' }}>
        Investigation steps ({formatNumber(calls.length)} {calls.length === 1 ? 'tool call' : 'tool calls'})
      </summary>
      <ol className="small" style={{ margin: '6px 0 0', paddingLeft: 18 }}>
        {calls.map((c, i) => (
          <li key={i} style={{ marginBottom: 6 }}>
            <span className="mono xsmall">{c.tool}</span> <span className="faint xsmall">{c.ms} ms</span>
            {c.error ? <span className="badge ai failed" style={{ marginLeft: 6 }}>error</span> : null}
            <pre className="codeblock wrap xsmall" style={{ margin: '4px 0 0' }}>
              {JSON.stringify(c.input)}
            </pre>
            <pre className="codeblock wrap xsmall faint" style={{ margin: '2px 0 0', maxHeight: 120, overflow: 'auto' }}>
              {c.output}
            </pre>
          </li>
        ))}
      </ol>
    </details>
  )
}
