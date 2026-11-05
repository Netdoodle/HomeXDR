// The dialog behind "Suppress similar": a suppression pre-filled from an alert, with a live
// count of the open alerts it would match.

import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { errorMessage, queryKeys } from '../api'
import { createSuppression, noiseKeys, previewSuppression, type SuppressionCondition } from '../api/noise'
import { formatNumber, plural } from '../lib/format'
import { useDebounced } from '../lib/hooks'
import { expiryFields, hasScope, isBroad, specFromForm, SUPPRESSION_FIELDS, SUPPRESSION_OPS, type ExpiryChoice, type SuppressForm } from '../lib/suppressions'
import { SeverityBadge } from './Badges'
import { Icon } from './Icon'
import { Modal } from './Modal'
import { Spinner } from './States'
import { useToast } from './Toast'

export function SuppressDialog({ initial, onClose }: { initial: SuppressForm | null; onClose: () => void }) {
  return (
    <Modal open={!!initial} onClose={onClose} title="Suppress similar alerts" wide>
      {initial ? <SuppressFormBody key={JSON.stringify(initial)} initial={initial} onClose={onClose} /> : null}
    </Modal>
  )
}

function SuppressFormBody({ initial, onClose }: { initial: SuppressForm; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [form, setForm] = useState(initial)
  const [reason, setReason] = useState('')
  const [expiry, setExpiry] = useState<ExpiryChoice>('90')
  const [closeOpen, setCloseOpen] = useState(true)
  const [confirmBroad, setConfirmBroad] = useState(false)

  // Memoized: useDebounced restarts its timer whenever this object changes identity.
  const spec = useMemo(() => specFromForm(form), [form])
  const broad = isBroad(spec)
  const scoped = hasScope(spec)
  useEffect(() => {
    if (!broad) setConfirmBroad(false)
  }, [broad])

  const debounced = useDebounced(spec, 400)
  const previewQ = useQuery({
    queryKey: noiseKeys.preview(debounced),
    queryFn: () => previewSuppression(debounced),
    enabled: hasScope(debounced),
    placeholderData: keepPreviousData,
  })
  const preview = previewQ.data

  const create = useMutation({
    mutationFn: () =>
      createSuppression({ ...spec, ...expiryFields(expiry), reason: reason.trim(), confirm_broad: confirmBroad, apply: closeOpen }),
    onSuccess: (res) => {
      toast.success(closeOpen ? `Suppression created. ${plural(res.closed, 'open alert')} closed.` : 'Suppression created.')
      qc.invalidateQueries({ queryKey: noiseKeys.suppressions })
      qc.invalidateQueries({ queryKey: queryKeys.alerts() })
      qc.invalidateQueries({ queryKey: ['alert'] })
      qc.invalidateQueries({ queryKey: ['overview'] })
      onClose()
    },
    onError: (e) => toast.error(e),
  })

  const setCondition = (i: number, patch: Partial<SuppressionCondition>) =>
    setForm({ ...form, conditions: form.conditions.map((c, j) => (j === i ? { ...c, ...patch } : c)) })

  const canSave = scoped && reason.trim() !== '' && (!broad || confirmBroad) && !create.isPending

  return (
    <div className="stack" style={{ gap: 14 }}>
      <p className="small muted" style={{ margin: 0 }}>
        New hits that match are closed as they arrive. They are not sent to the AI analyst or to notifications. Critical alerts
        always get through.
      </p>

      <div className="stack" style={{ gap: 6 }}>
        <label className="row small">
          <input type="checkbox" checked={form.useRule} disabled={!form.ruleId} onChange={(e) => setForm({ ...form, useRule: e.target.checked })} />
          <span>
            Only this rule:{' '}
            {form.ruleId ? <strong title={form.ruleId}>{form.ruleTitle || form.ruleId}</strong> : <span className="muted">none picked</span>}
          </span>
        </label>
        <label className="row small">
          <input type="checkbox" checked={form.useHost} disabled={!form.hostId} onChange={(e) => setForm({ ...form, useHost: e.target.checked })} />
          <span>
            Only this host: {form.hostId ? <strong>{form.hostname || form.hostId}</strong> : <span className="muted">none picked</span>}
          </span>
        </label>
      </div>

      <div className="field">
        <label>And every one of these is true</label>
        <div className="stack" style={{ gap: 6 }}>
          {form.conditions.map((c, i) => (
            <div key={i} className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
              <input
                className="input mono small"
                style={{ flex: '1 1 200px' }}
                list="suppress-fields"
                aria-label="Field"
                value={c.field}
                onChange={(e) => setCondition(i, { field: e.target.value })}
              />
              <select
                className="select"
                aria-label="Comparison"
                value={c.op}
                onChange={(e) => setCondition(i, { op: e.target.value as SuppressionCondition['op'] })}
              >
                {SUPPRESSION_OPS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
              <input
                className="input mono small"
                style={{ flex: '2 1 260px' }}
                aria-label="Value"
                value={c.value}
                onChange={(e) => setCondition(i, { value: e.target.value })}
              />
              <button
                type="button"
                className="btn ghost icon sm"
                aria-label="Remove condition"
                onClick={() => setForm({ ...form, conditions: form.conditions.filter((_, j) => j !== i) })}
              >
                <Icon name="close" size={12} />
              </button>
            </div>
          ))}
          <datalist id="suppress-fields">
            {SUPPRESSION_FIELDS.map((f) => (
              <option key={f} value={f} />
            ))}
          </datalist>
          <div>
            <button
              type="button"
              className="btn sm"
              onClick={() => setForm({ ...form, conditions: [...form.conditions, { field: 'process.parent.command_line', op: 'contains', value: '' }] })}
            >
              <Icon name="plus" size={12} /> Add condition
            </button>
          </div>
        </div>
        <span className="help">Values must match exactly, including upper and lower case. An event without the field does not match.</span>
      </div>

      <div className="form-grid">
        <div className="field">
          <label htmlFor="suppress-reason">Why is this safe to hide? (required)</label>
          <input
            id="suppress-reason"
            className="input"
            placeholder="e.g. Unraid User Scripts plugin check, runs every few minutes"
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="suppress-expiry">Expires</label>
          <select id="suppress-expiry" className="select" value={expiry} onChange={(e) => setExpiry(e.target.value as ExpiryChoice)}>
            <option value="30">in 30 days</option>
            <option value="90">in 90 days</option>
            <option value="365">in 1 year</option>
            <option value="never">never</option>
          </select>
        </div>
      </div>

      {!scoped ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>A suppression needs a rule or at least one condition. A host alone would hide everything on that host.</span>
        </div>
      ) : null}
      {broad ? (
        <div className="callout warn" role="alert">
          <Icon name="warning" size={14} />
          <label className="row small">
            <input type="checkbox" checked={confirmBroad} onChange={(e) => setConfirmBroad(e.target.checked)} />
            <span>This hides every hit of this rule on every host. Tick to confirm that is what you want.</span>
          </label>
        </div>
      ) : null}

      <section className="panel" aria-live="polite">
        <div className="panel-header">
          <h3 className="small" style={{ margin: 0 }}>
            Open alerts this matches
          </h3>
          {previewQ.isFetching ? <Spinner small /> : null}
        </div>
        <div className="panel-body small">
          {previewQ.isError ? (
            <span className="muted">{errorMessage(previewQ.error)}</span>
          ) : !preview ? (
            <span className="muted">{scoped ? 'Counting…' : 'Nothing to count yet.'}</span>
          ) : (
            <div className="stack" style={{ gap: 8 }}>
              <div>
                <strong>{plural(preview.matches, 'open alert')}</strong> ({plural(preview.hits, 'hit')}).
                {preview.kept > 0 ? ` ${formatNumber(preview.kept)} more match but stay open, because they are critical or on the must-alert list.` : ''}
              </div>
              {preview.sample.length > 0 ? (
                <ul style={{ margin: 0, paddingLeft: 0, listStyle: 'none' }} className="stack xsmall">
                  {preview.sample.map((a) => (
                    <li key={a.id} className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                      <SeverityBadge severity={a.severity} />
                      <Link to={`/alerts/${encodeURIComponent(a.id)}`}>{a.rule_title}</Link>
                      <span className="muted">on {a.hostname}</span>
                      {a.command_line ? (
                        <span className="mono faint" style={{ overflowWrap: 'anywhere' }}>
                          {a.command_line.slice(0, 120)}
                        </span>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          )}
        </div>
      </section>

      <label className="row small">
        <input type="checkbox" checked={closeOpen} onChange={(e) => setCloseOpen(e.target.checked)} />
        <span>
          Also close the {preview ? formatNumber(preview.matches) : ''} matching open {preview?.matches === 1 ? 'alert' : 'alerts'}. You can still find them
          with the Suppressed filter.
        </span>
      </label>

      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <button type="button" className="btn" onClick={onClose} disabled={create.isPending}>
          Cancel
        </button>
        <button type="button" className="btn primary" disabled={!canSave} onClick={() => create.mutate()}>
          {create.isPending ? <Spinner small /> : null} Create suppression
        </button>
      </div>
    </div>
  )
}
