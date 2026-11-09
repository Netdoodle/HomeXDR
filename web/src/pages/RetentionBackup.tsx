// Data retention → Cloud backup: cold archives of events in S3-compatible storage, and
// importing an archived day back.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { errorMessage } from '../api'
import {
  backupKeys,
  getBackup,
  importArchive,
  listArchives,
  PROVIDERS,
  putBackup,
  runBackup,
  testBackup,
  type BackupInput,
  type BackupView,
} from '../api/backup'
import { retentionKeys, type RetentionStatus } from '../api/retention'
import { useCan } from '../components/Auth'
import { KV, RelTime, Toggle } from '../components/Misc'
import { Modal } from '../components/Modal'
import { ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { formatBytes, formatNumber } from '../lib/format'

export function BackupSection({ retention }: { retention: RetentionStatus }) {
  const isAdmin = useCan('admin')
  const q = useQuery({ queryKey: backupKeys.view, queryFn: getBackup, enabled: isAdmin, refetchInterval: 15_000 })
  if (!isAdmin) return null
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return (
    <>
      <BackupForm key={JSON.stringify({ ...q.data, activity: undefined, pending: undefined, recent: undefined })} view={q.data} />
      <Archives view={q.data} retention={retention} />
    </>
  )
}

function BackupForm({ view }: { view: BackupView }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [s, setS] = useState<BackupInput>({ ...view, skip_modules: view.skip_modules ?? [] })
  const [secret, setSecret] = useState('')
  const [skip, setSkip] = useState((view.skip_modules ?? []).join(', '))
  const set = (p: Partial<BackupInput>) => setS((x) => ({ ...x, ...p }))
  const input = (): BackupInput => ({ ...s, secret: secret || undefined, skip_modules: skip.split(/[\s,]+/).filter(Boolean) })
  const provider = PROVIDERS.find((p) => p.id === s.provider) ?? PROVIDERS[0]
  const save = useMutation({
    mutationFn: () => putBackup(input()),
    onSuccess: (v) => {
      qc.setQueryData(backupKeys.view, v)
      qc.invalidateQueries({ queryKey: retentionKeys.status })
      setSecret('')
      toast.success(v.enabled ? 'Backup settings saved. Completed days are archived after the run hour.' : 'Backup settings saved')
    },
  })
  const test = useMutation({ mutationFn: () => testBackup(input()) })
  const run = useMutation({
    mutationFn: runBackup,
    onSuccess: () => {
      toast.success('Backup started')
      qc.invalidateQueries({ queryKey: backupKeys.view })
    },
    onError: (e) => toast.error(e),
  })
  const pickProvider = (id: string) => {
    const p = PROVIDERS.find((x) => x.id === id)!
    set({ provider: id, endpoint: p.endpoint.replace('{region}', p.region), region: p.region, path_style: p.pathStyle, storage_class: id === 'aws' ? s.storage_class : '' })
  }
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate()
  }
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>Cloud backup (cold storage)</h2>
        {view.activity ? <span className="xsmall">{view.activity}…</span> : null}
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Each completed day of events is compressed (zstd, newline-delimited JSON) and uploaded to an S3-compatible bucket you own, with a manifest. Archives are
          cold storage: HomeXDR does not search them where they are. To look at an archived day again, import it below and it returns to search, hunts and
          investigations. Today is archived tomorrow; nothing local is deleted by backups (retention does that).
        </p>
        <KV
          items={[
            ['Archived', `${formatNumber(view.archived_days)} days, ${formatBytes(view.archived_bytes)}`],
            ['Waiting to be archived', view.pending.length ? `${view.pending.length} days (oldest ${view.pending[0]})` : 'none'],
            ['Last run', view.last_run ? <RelTime iso={view.last_run} /> : '—'],
            ['Last success', view.last_success ? <RelTime iso={view.last_success} /> : '—'],
          ]}
        />
        {view.last_error ? <div className="callout danger small">{view.last_error}</div> : null}
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <Toggle checked={s.enabled} onChange={(v) => set({ enabled: v })} label="Back up events" />
          <span>Back up completed days to object storage</span>
        </div>
        <div className="grid grid-2" style={{ gap: 14 }}>
          <label className="field">
            <span className="label">Provider</span>
            <select className="input" value={provider.id} onChange={(e) => pickProvider(e.target.value)}>
              {PROVIDERS.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
            <span className="help">{provider.note}</span>
          </label>
          <label className="field">
            <span className="label">Endpoint</span>
            <input className="input mono" value={s.endpoint} onChange={(e) => set({ endpoint: e.target.value })} spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Bucket</span>
            <input className="input mono" value={s.bucket} onChange={(e) => set({ bucket: e.target.value })} spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Region</span>
            <input className="input mono" value={s.region} onChange={(e) => set({ region: e.target.value })} spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Access key ID</span>
            <input className="input mono" value={s.access_key_id} onChange={(e) => set({ access_key_id: e.target.value })} autoComplete="off" spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Secret key</span>
            <input className="input" type="password" autoComplete="new-password" value={secret} onChange={(e) => setSecret(e.target.value)} placeholder={view.secret_set ? 'Saved; type to replace' : ''} />
          </label>
          <label className="field">
            <span className="label">Folder (prefix)</span>
            <input className="input mono" value={s.prefix} onChange={(e) => set({ prefix: e.target.value })} placeholder="homexdr" spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Storage class</span>
            <select className="input" value={s.storage_class} onChange={(e) => set({ storage_class: e.target.value })}>
              <option value="">Provider default</option>
              <option value="STANDARD_IA">AWS Standard-IA</option>
              <option value="GLACIER_IR">AWS Glacier Instant Retrieval (cold, imports directly)</option>
              <option value="GLACIER">AWS Glacier Flexible (restore before import)</option>
              <option value="DEEP_ARCHIVE">AWS Glacier Deep Archive (cheapest; restore before import, takes hours)</option>
            </select>
          </label>
          <label className="field">
            <span className="label">Leave out these sources</span>
            <input className="input mono" value={skip} onChange={(e) => setSkip(e.target.value)} placeholder="netflow" spellCheck={false} />
            <span className="help">Event modules not archived, e.g. netflow (high volume). Empty: everything.</span>
          </label>
          <label className="field">
            <span className="label">Archive after (local hour)</span>
            <input className="input" type="number" min={0} max={23} value={s.run_hour} onChange={(e) => set({ run_hour: Number(e.target.value) })} />
          </label>
        </div>
        <div className="row" style={{ gap: 16, flexWrap: 'wrap' }}>
          <label className="row" style={{ gap: 6 }}>
            <input type="checkbox" checked={s.path_style} onChange={(e) => set({ path_style: e.target.checked })} />
            <span className="small">Path-style URLs (MinIO, R2)</span>
          </label>
          <label className="row" style={{ gap: 6 }}>
            <input type="checkbox" checked={s.backfill} onChange={(e) => set({ backfill: e.target.checked })} />
            <span className="small">Also archive the days already stored</span>
          </label>
        </div>
        {test.data ? <div className={`callout small ${test.data.ok ? 'ok' : 'danger'}`}>{test.data.message}</div> : null}
        {test.isError ? <div className="callout danger small">{errorMessage(test.error)}</div> : null}
        {save.isError ? <div className="callout danger small">{errorMessage(save.error)}</div> : null}
        <div className="row" style={{ gap: 8 }}>
          <button className="btn primary" type="submit" disabled={save.isPending}>
            Save
          </button>
          <button className="btn" type="button" disabled={test.isPending} onClick={() => test.mutate()}>
            Test bucket
          </button>
          <button className="btn" type="button" disabled={!view.enabled || !!view.activity || run.isPending} onClick={() => run.mutate()}>
            Back up now
          </button>
        </div>
      </div>
    </form>
  )
}

function Archives({ view, retention }: { view: BackupView; retention: RetentionStatus }) {
  const qc = useQueryClient()
  const toast = useToast()
  const q = useQuery({ queryKey: backupKeys.archives, queryFn: listArchives, enabled: !!view.bucket && view.secret_set })
  const [day, setDay] = useState<string | null>(null)
  const [ack, setAck] = useState(false)
  const imp = useMutation({
    mutationFn: (d: string) => importArchive(d),
    onSuccess: () => {
      setDay(null)
      toast.success('Import started: the day reappears in search as it loads')
      qc.invalidateQueries({ queryKey: backupKeys.view })
    },
  })
  if (!view.bucket || !view.secret_set) return null
  const limit = retention.settings.days
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Archived days</h2>
        <button className="btn small" type="button" onClick={() => q.refetch()}>
          Refresh
        </button>
      </div>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <div className="panel-body callout danger small">{errorMessage(q.error)}</div>
      ) : q.data.length === 0 ? (
        <div className="panel-body small muted">No archives in the bucket yet.</div>
      ) : (
        <div style={{ maxHeight: 420, overflow: 'auto' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Day (UTC)</th>
                <th>Events</th>
                <th>Size</th>
                <th>In HomeXDR</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((a) => (
                <tr key={a.key}>
                  <td className="mono">{a.day}</td>
                  <td>{a.events ? formatNumber(a.events) : '—'}</td>
                  <td>{a.bytes ? formatBytes(a.bytes) : '—'}</td>
                  <td>{a.in_store ? 'yes' : 'no (archive only)'}</td>
                  <td>
                    {!a.in_store ? (
                      <button
                        className="btn small"
                        type="button"
                        disabled={!!view.activity}
                        onClick={() => {
                          setAck(false)
                          imp.reset()
                          setDay(a.day)
                        }}
                      >
                        Import…
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Modal
        open={day !== null}
        onClose={() => setDay(null)}
        title={`Import ${day}?`}
        footer={
          <>
            <button className="btn" type="button" onClick={() => setDay(null)}>
              Cancel
            </button>
            <button className="btn primary" type="button" disabled={!ack || imp.isPending} onClick={() => day && imp.mutate(day)}>
              Import day
            </button>
          </>
        }
      >
        <div className="stack" style={{ gap: 10 }}>
          <p className="small" style={{ margin: 0 }}>
            HomeXDR downloads the archive for {day} and loads its events back into the event store, where search, hunts, process trees and investigations can see
            them. Detection rules are not run on them again, so no new alerts are raised.
          </p>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {limit > 0 ? <li>Days older than the {limit}-day limit are refused: they would be removed again at the next cleanup. Raise the limit first.</li> : null}
            {retention.settings.max_bytes > 0 ? (
              <li>The day counts against the {formatBytes(retention.settings.max_bytes)} size cap. If that pushes the store over the cap, the oldest days (possibly this one) are removed.</li>
            ) : null}
            <li>Archives in a deep cold class (Glacier Flexible, Deep Archive) must be restored in your provider's console first.</li>
            <li>Downloading from the bucket may cost egress fees with some providers.</li>
          </ul>
          <label className="row" style={{ gap: 8, alignItems: 'flex-start' }}>
            <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />
            <span className="small">I understand the imported events are subject to the current retention settings.</span>
          </label>
          {imp.isError ? <div className="callout danger small">{errorMessage(imp.error)}</div> : null}
        </div>
      </Modal>
    </section>
  )
}
