// Data retention: how much event history is kept, how full the disk is, when the oldest
// events fall off, and changing the limits behind two confirmation steps.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { errorMessage } from '../api'
import {
  getRetention,
  previewRetention,
  putRetention,
  RETENTION_CONFIRM_PHRASE,
  retentionKeys,
  type RetentionPreview,
  type RetentionSettings,
  type RetentionStatus,
} from '../api/retention'
import { useCan } from '../components/Auth'
import { PageHeader } from '../components/Layout'
import { KV } from '../components/Misc'
import { Modal } from '../components/Modal'
import { ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { formatBytes, formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { BackupSection } from './RetentionBackup'

const GiB = 1024 ** 3
const TiB = 1024 ** 4

const fmtDate = (iso?: string) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }) : '—'
const daysLabel = (d: number) => (d > 0 ? `${formatNumber(d)} days` : 'No time limit')
const capLabel = (b: number) => (b > 0 ? formatBytes(b) : 'No size cap')

export function RetentionPage() {
  useDocumentTitle('Data retention')
  const q = useQuery({ queryKey: retentionKeys.status, queryFn: getRetention, refetchInterval: 60_000 })
  return (
    <>
      <PageHeader title="Data retention" subtitle="How much event history HomeXDR keeps, and when the oldest events are removed" />
      {q.isPending ? <Loading /> : q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : <Body st={q.data} />}
    </>
  )
}

function Bar({ used, total, label }: { used: number; total: number; label: string }) {
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0
  const tone = pct >= 95 ? 'var(--sev-critical, #d33)' : pct >= 80 ? 'var(--sev-medium, #d90)' : 'var(--accent, #3a7)'
  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <span className="small">{label}</span>
        <span className="small mono">
          {formatBytes(used)} / {formatBytes(total)} ({pct.toFixed(1)}%)
        </span>
      </div>
      <div style={{ height: 10, borderRadius: 5, background: 'var(--border, #ddd)', overflow: 'hidden' }} role="progressbar" aria-valuenow={Math.round(pct)}>
        <div style={{ width: `${pct}%`, height: '100%', background: tone }} />
      </div>
    </div>
  )
}

function Body({ st }: { st: RetentionStatus }) {
  const s = st.settings
  const diskUsed = st.disk_total > 0 ? st.disk_total - st.disk_free : 0
  return (
    <div className="stack" style={{ maxWidth: 1000 }}>
      <div className="grid grid-2" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2>Next falloff</h2>
          </div>
          <div className="panel-body stack" style={{ gap: 8 }}>
            {st.next_falloff ? (
              <>
                <div style={{ fontSize: 28, fontWeight: 600 }}>{fmtDate(st.next_falloff)}</div>
                <p className="small muted" style={{ margin: 0 }}>
                  Events from <b>{fmtDate(st.next_removes_day)}</b> (the oldest day kept) are removed then,{' '}
                  {st.next_reason === 'time'
                    ? `when they pass the ${s.days}-day limit.`
                    : `when the store reaches its ${formatBytes(s.max_bytes)} cap at the current rate of ${formatBytes(st.daily_avg_bytes)} a day (an estimate).`}
                </p>
                {st.next_removes_archived === false ? (
                  <div className="callout warn small">That day has no cloud archive yet: once removed it cannot be imported back.</div>
                ) : st.next_removes_archived ? (
                  <div className="callout ok small">That day is archived in cloud storage and can be imported back.</div>
                ) : null}
              </>
            ) : (
              <p className="muted" style={{ margin: 0 }}>
                {s.days === 0 && s.max_bytes === 0 ? 'Nothing is scheduled to be removed: there is no time limit and no size cap.' : 'Not enough history yet to estimate.'}
              </p>
            )}
            <KV
              items={[
                ['Time limit falls off', st.time_falloff ? fmtDate(st.time_falloff) : '—'],
                ['Size cap falls off', st.size_falloff ? `${fmtDate(st.size_falloff)} (estimate)` : '—'],
              ]}
            />
          </div>
        </section>
        <section className="panel">
          <div className="panel-header">
            <h2>Storage</h2>
          </div>
          <div className="panel-body stack" style={{ gap: 12 }}>
            {s.max_bytes > 0 ? <Bar used={st.stored_bytes} total={s.max_bytes} label="Events against the size cap" /> : null}
            {st.disk_total > 0 ? (
              <Bar used={diskUsed} total={st.disk_total} label="Disk holding the events" />
            ) : (
              <p className="small muted" style={{ margin: 0 }}>The event store did not report its disk.</p>
            )}
            <KV
              items={[
                ['Events stored', `${formatNumber(st.stored_events)} (${formatBytes(st.stored_bytes)})`],
                ['Oldest event day', fmtDate(st.oldest)],
                ['Average per day', st.daily_avg_bytes ? `${formatBytes(st.daily_avg_bytes)} (last 7 full days)` : '—'],
                ['History the cap holds', st.coverage_days ? `about ${Math.floor(st.coverage_days)} days at that rate` : '—'],
                ['Disk free', st.disk_total > 0 ? formatBytes(st.disk_free) : '—'],
              ]}
            />
          </div>
        </section>
      </div>
      <Settings st={st} />
      <BackupSection retention={st} />
    </div>
  )
}

type CapUnit = 'GiB' | 'TiB'

function Settings({ st }: { st: RetentionStatus }) {
  const isAdmin = useCan('admin')
  const qc = useQueryClient()
  const toast = useToast()
  const s = st.settings
  const initUnit: CapUnit = s.max_bytes >= TiB && s.max_bytes % (TiB / 1024) === 0 ? 'TiB' : 'GiB'
  const [days, setDays] = useState(String(s.days))
  const [cap, setCap] = useState(s.max_bytes > 0 ? String(+(s.max_bytes / (initUnit === 'TiB' ? TiB : GiB)).toFixed(2)) : '0')
  const [unit, setUnit] = useState<CapUnit>(initUnit)
  const [step, setStep] = useState<0 | 1 | 2>(0)
  const [ack, setAck] = useState(false)
  const [phrase, setPhrase] = useState('')
  const [preview, setPreview] = useState<RetentionPreview | null>(null)

  const proposed: RetentionSettings = {
    days: Math.max(0, Math.floor(Number(days) || 0)),
    max_bytes: Math.max(0, Math.round((Number(cap) || 0) * (unit === 'TiB' ? TiB : GiB))),
  }
  const changed = proposed.days !== s.days || proposed.max_bytes !== s.max_bytes
  const destructive = !!preview && (preview.reduction || preview.removes_events > 0)

  const review = useMutation({
    mutationFn: () => previewRetention(proposed),
    onSuccess: (p) => {
      setPreview(p)
      setAck(false)
      setPhrase('')
      setStep(1)
    },
  })
  const apply = useMutation({
    mutationFn: () => putRetention({ ...proposed, acknowledge: ack, confirm_phrase: destructive ? phrase : undefined }),
    onSuccess: (next) => {
      qc.setQueryData(retentionKeys.status, next)
      setStep(0)
      toast.success('Retention settings saved')
    },
  })
  const close = () => setStep(0)

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Retention settings</h2>
        <span className="xsmall faint">{st.source === 'console' ? 'set in the console' : 'from the server environment (HOMEXDR_RETENTION_*)'}</span>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Events are removed by whichever limit is reached first, a whole day at a time, oldest first. Today's events are never removed. A change made here is
          stored and overrides the environment settings.
        </p>
        <div className="grid grid-2" style={{ gap: 14 }}>
          <label className="field">
            <span className="label">Keep events for (days)</span>
            <input className="input" type="number" min={0} max={36500} value={days} disabled={!isAdmin} onChange={(e) => setDays(e.target.value)} />
            <span className="help">0 = no time limit. Now: {daysLabel(s.days)}.</span>
          </label>
          <label className="field">
            <span className="label">Size cap</span>
            <div className="row" style={{ gap: 8 }}>
              <input className="input grow" type="number" min={0} step="any" value={cap} disabled={!isAdmin} onChange={(e) => setCap(e.target.value)} />
              <select className="input" style={{ width: 90 }} value={unit} disabled={!isAdmin} onChange={(e) => setUnit(e.target.value as CapUnit)}>
                <option value="GiB">GB</option>
                <option value="TiB">TB</option>
              </select>
            </div>
            <span className="help">0 = no cap; at least 1 GB otherwise. Now: {capLabel(s.max_bytes)}.</span>
          </label>
        </div>
        {review.isError ? <div className="callout danger small">{errorMessage(review.error)}</div> : null}
        {isAdmin ? (
          <div>
            <button className="btn primary" type="button" disabled={!changed || review.isPending} onClick={() => review.mutate()}>
              Review changes…
            </button>
          </div>
        ) : (
          <p className="small muted" style={{ margin: 0 }}>
            Only administrators can change retention.
          </p>
        )}
      </div>

      {/* Step 1: what changes, what gets deleted, and an acknowledgement. */}
      <Modal
        open={step === 1 && !!preview}
        onClose={close}
        title="Step 1 of 2: Review the retention change"
        danger={destructive}
        wide
        footer={
          <>
            <button className="btn" type="button" onClick={close}>
              Cancel
            </button>
            <button className={`btn ${destructive ? 'danger' : 'primary'}`} type="button" disabled={!ack} onClick={() => setStep(2)}>
              Continue to final confirmation
            </button>
          </>
        }
      >
        {preview ? (
          <div className="stack" style={{ gap: 12 }}>
            <table className="table">
              <thead>
                <tr>
                  <th />
                  <th>Now</th>
                  <th>After the change</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Time limit</td>
                  <td>{daysLabel(preview.current.days)}</td>
                  <td>
                    <b>{daysLabel(preview.proposed.days)}</b>
                  </td>
                </tr>
                <tr>
                  <td>Size cap</td>
                  <td>{capLabel(preview.current.max_bytes)}</td>
                  <td>
                    <b>{capLabel(preview.proposed.max_bytes)}</b>
                  </td>
                </tr>
                <tr>
                  <td>Next falloff</td>
                  <td>{fmtDate(st.next_falloff)}</td>
                  <td>{fmtDate(preview.next_falloff)}</td>
                </tr>
              </tbody>
            </table>
            {preview.removes_events > 0 ? (
              <div className="callout danger">
                <b>
                  {formatNumber(preview.removes_events)} events ({formatBytes(preview.removes_bytes)}) will be deleted
                </b>
                : everything from {fmtDate(preview.removes_from)} through {fmtDate(preview.removes_until && new Date(Date.parse(preview.removes_until) - 86_400_000).toISOString())}.
                History will start on {fmtDate(preview.keeps_from)}.
              </div>
            ) : (
              <div className="callout ok small">No events are deleted by this change.</div>
            )}
            {preview.warnings.length ? (
              <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                {preview.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            ) : null}
            <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
              <span className="small">
                {destructive
                  ? 'I understand that this reduces how much history HomeXDR keeps, that the events listed above are permanently deleted, and that this cannot be undone.'
                  : 'I have reviewed the new retention settings.'}
              </span>
            </label>
          </div>
        ) : null}
      </Modal>

      {/* Step 2: final confirmation; a reduction needs the phrase typed. */}
      <Modal
        open={step === 2 && !!preview}
        onClose={close}
        title="Step 2 of 2: Confirm"
        danger={destructive}
        footer={
          <>
            <button className="btn" type="button" onClick={() => setStep(1)}>
              Back
            </button>
            <button
              className={`btn ${destructive ? 'danger' : 'primary'}`}
              type="button"
              disabled={apply.isPending || (destructive && phrase !== RETENTION_CONFIRM_PHRASE)}
              onClick={() => apply.mutate()}
            >
              {destructive ? 'Reduce retention' : 'Save retention settings'}
            </button>
          </>
        }
      >
        {preview ? (
          <div className="stack" style={{ gap: 12 }}>
            <p style={{ margin: 0 }}>
              New settings: <b>{daysLabel(preview.proposed.days)}</b>, <b>{capLabel(preview.proposed.max_bytes)}</b>.
            </p>
            {destructive ? (
              <>
                <div className="callout danger small">
                  {preview.removes_events > 0
                    ? `${formatNumber(preview.removes_events)} events (${formatBytes(preview.removes_bytes)}) are deleted within about 10 minutes. HomeXDR keeps no backup.`
                    : 'Less history is kept from now on: older events fall off sooner than they do today.'}
                </div>
                <label className="field">
                  <span className="label">
                    Type <span className="mono">{RETENTION_CONFIRM_PHRASE}</span> to confirm
                  </span>
                  <input className="input mono" value={phrase} onChange={(e) => setPhrase(e.target.value)} autoComplete="off" spellCheck={false} />
                </label>
              </>
            ) : (
              <p className="small muted" style={{ margin: 0 }}>
                Nothing is deleted. The change applies right away.
              </p>
            )}
            {apply.isError ? <div className="callout danger small">{errorMessage(apply.error)}</div> : null}
          </div>
        ) : null}
      </Modal>
    </section>
  )
}
