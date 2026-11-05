// Settings > Suppressions: what is being hidden, how often it fired, and when it stops.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { queryKeys } from '../api'
import { deleteSuppression, getNoiseSettings, listSuppressions, noiseKeys, patchSuppression, putNoiseSettings, type Suppression } from '../api/noise'
import { useCan } from '../components/Auth'
import { Icon } from '../components/Icon'
import { RelTime } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { EmptyState, QueryView, Spinner } from '../components/States'
import { SuppressDialog } from '../components/SuppressDialog'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { describeOp, EMPTY_SUPPRESS_FORM, isExpired, type SuppressForm } from '../lib/suppressions'
import { formatDate } from '../lib/time'

export function SuppressionsTab() {
  const canEdit = useCan('admin')
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: noiseKeys.suppressions, queryFn: listSuppressions })
  const [creating, setCreating] = useState<SuppressForm | null>(null)
  const [deleting, setDeleting] = useState<Suppression | null>(null)
  const toggle = useMutation({
    mutationFn: (s: Suppression) => patchSuppression(s.id, { enabled: !s.enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: noiseKeys.suppressions }),
    onError: (e) => toast.error(e),
  })
  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Suppressions</h2>
          <span className="row">
            <Link className="btn sm" to="/alerts?status=suppressed">
              See suppressed alerts
            </Link>
            {canEdit ? (
              <button type="button" className="btn sm primary" onClick={() => setCreating(EMPTY_SUPPRESS_FORM)}>
                <Icon name="plus" size={12} /> New
              </button>
            ) : null}
          </span>
        </div>
        <QueryView
          query={q}
          isEmpty={(d) => d.suppressions.length === 0}
          empty={<EmptyState title="No suppressions">Use Suppress similar on an alert when something harmless keeps firing.</EmptyState>}
        >
          {(d) => (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>What it matches</th>
                    <th>Reason</th>
                    <th className="right">Hits</th>
                    <th>Expires</th>
                    {canEdit ? <th>Enabled</th> : null}
                    {canEdit ? <th /> : null}
                  </tr>
                </thead>
                <tbody>
                  {d.suppressions.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <Scope s={s} />
                      </td>
                      <td style={{ maxWidth: 280 }}>
                        {s.reason}
                        <div className="xsmall faint">
                          by {s.created_by}, <RelTime iso={s.created_at} />
                        </div>
                      </td>
                      <td className="right">
                        {formatNumber(s.hit_count)}
                        {s.last_hit_at ? (
                          <div className="xsmall faint">
                            last <RelTime iso={s.last_hit_at} />
                          </div>
                        ) : null}
                        {s.override_count > 0 ? (
                          <div
                            className="xsmall"
                            style={{ color: 'var(--sev-high)' }}
                            title="Hits that matched but were kept as alerts, because they were critical or on the must-alert list"
                          >
                            {formatNumber(s.override_count)} kept as alerts
                          </div>
                        ) : null}
                      </td>
                      <td>
                        {!s.expires_at ? (
                          'Never'
                        ) : isExpired(s) ? (
                          <span className="badge status resolved">Expired {formatDate(s.expires_at)}</span>
                        ) : (
                          formatDate(s.expires_at)
                        )}
                      </td>
                      {canEdit ? (
                        <td>
                          <input
                            type="checkbox"
                            aria-label={s.enabled ? 'Disable this suppression' : 'Enable this suppression'}
                            checked={s.enabled}
                            disabled={toggle.isPending}
                            onChange={() => toggle.mutate(s)}
                          />
                        </td>
                      ) : null}
                      {canEdit ? (
                        <td className="right">
                          <button type="button" className="btn ghost icon sm" aria-label="Delete suppression" onClick={() => setDeleting(s)}>
                            <Icon name="trash" size={14} />
                          </button>
                        </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>

      <MustAlertPanel canEdit={canEdit} />

      <SuppressDialog initial={creating} onClose={() => setCreating(null)} />
      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title="Delete this suppression?"
        confirmLabel="Delete"
        danger
        onConfirm={async () => {
          if (!deleting) return
          await deleteSuppression(deleting.id)
          qc.invalidateQueries({ queryKey: noiseKeys.suppressions })
          qc.invalidateQueries({ queryKey: queryKeys.alerts() })
        }}
      >
        <p style={{ margin: 0 }}>Matching hits will alert again. Alerts it already closed stay closed.</p>
      </ConfirmDialog>
    </div>
  )
}

function Scope({ s }: { s: Suppression }) {
  return (
    <div className="stack" style={{ gap: 2 }}>
      <div className="small">
        {s.rule_id ? <strong title={s.rule_id}>{s.rule_title || s.rule_id}</strong> : <span className="muted">Any rule</span>}
        <span className="muted"> on {s.host_id ? s.hostname || s.host_id : 'any host'}</span>
      </div>
      {s.conditions.map((c, i) => (
        <div key={i} className="xsmall" style={{ overflowWrap: 'anywhere' }}>
          <span className="mono">{c.field}</span> <span className="muted">{describeOp(c.op)}</span> <span className="mono">{c.value}</span>
        </div>
      ))}
    </div>
  )
}

function MustAlertPanel({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: noiseKeys.settings, queryFn: getNoiseSettings })
  const [text, setText] = useState('')
  useEffect(() => {
    if (q.data) setText(q.data.must_alert_rules.join('\n'))
  }, [q.data])
  const save = useMutation({
    mutationFn: () => putNoiseSettings({ must_alert_rules: text.split('\n').map((l) => l.trim()).filter(Boolean) }),
    onSuccess: (saved) => {
      qc.setQueryData(noiseKeys.settings, saved)
      toast.success('Must-alert list saved.')
    },
    onError: (e) => toast.error(e),
  })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Must alert</h2>
        <span className="hint">These always alert, whatever a suppression says</span>
      </div>
      <div className="panel-body stack" style={{ gap: 8 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Critical alerts are never suppressed. Add the IDs of other rules that must never be hidden, one per line. When a suppression matches one of these,
          the alert is kept, it says so on the alert, and the audit log records it.
        </p>
        <textarea
          className="input mono small"
          rows={4}
          aria-label="Rule IDs that must always alert"
          placeholder="health:feed-silent"
          disabled={!canEdit}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        {canEdit ? (
          <div>
            <button type="button" className="btn sm primary" disabled={save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? <Spinner small /> : null} Save
            </button>
          </div>
        ) : null}
      </div>
    </section>
  )
}
