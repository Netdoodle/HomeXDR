// Data health: which data sources are arriving, and how far to trust a quiet console.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { errorMessage } from '../api/client'
import { getFeeds, getRefused, healthKeys, patchFeed, putOfflineLabels, type FeedPatch, type FeedReport, type FeedView, type OfflineLabelRule, type PulledSource } from '../api/health'
import { useCan } from '../components/Auth'
import { PageHeader } from '../components/Layout'
import { LinkTabs, RelTime, Toggle, type TabDef } from '../components/Misc'
import { QueryView } from '../components/States'
import { useToast } from '../components/Toast'
import { FEED_STATUS_BADGE, FEED_STATUS_LABEL, feedName, formatGap, sortFeeds } from '../lib/health'
import { useDocumentTitle } from '../lib/hooks'
import { formatDateTime } from '../lib/time'
import { DoctorTab, SelfCheckTab } from './HealthChecks'

const ALL_TABS: (TabDef & { admin?: boolean })[] = [
  { id: 'sources', label: 'Data sources', icon: 'pulse' },
  { id: 'doctor', label: 'Doctor', icon: 'settings', admin: true },
  { id: 'selfcheck', label: 'Self-check', icon: 'rules', admin: true },
]

export function HealthPage() {
  useDocumentTitle('Data health')
  const isAdmin = useCan('admin')
  const { tab: tabParam } = useParams()
  const tabs = ALL_TABS.filter((t) => isAdmin || !t.admin)
  const tab = tabs.find((t) => t.id === tabParam)?.id ?? tabs[0].id
  return (
    <>
      <PageHeader title="Data health" subtitle="Is everything still sending data, and can your rules actually fire on it?" />
      <LinkTabs tabs={tabs} active={tab} href={(id) => `/health/${id}`} />
      {tab === 'sources' ? <SourcesTab /> : null}
      {tab === 'doctor' ? <DoctorTab /> : null}
      {tab === 'selfcheck' ? <SelfCheckTab /> : null}
    </>
  )
}

function SourcesTab() {
  const q = useQuery({ queryKey: healthKeys.feeds, queryFn: getFeeds, refetchInterval: 60_000 })
  return (
    <div className="stack">
      <p className="small muted" style={{ margin: 0 }}>
        HomeXDR learns how often each source normally sends data. It raises an alert when a source stays quiet for three times its usual longest gap (15 minutes at least, 7 days at most), and
        resolves the alert itself when the source returns. Time the server or the host was away does not count as silence.
      </p>
      {q.data?.pulled?.length ? <PulledSection sources={q.data.pulled} /> : null}
      <section className="panel">
        <QueryView query={q}>{(d) => <SourcesTable report={d} />}</QueryView>
      </section>
      {q.data ? <OfflineLabelsSection rules={q.data.offline_labels ?? []} /> : null}
      <RefusedSection />
    </div>
  )
}

const PULLED_BADGE: Record<PulledSource['status'], string> = { online: 'resolved', offline: 'new', waiting: 'in_progress' }
const PULLED_LABEL: Record<PulledSource['status'], string> = { online: 'Online', offline: 'Offline', waiting: 'Waiting' }

/** Sources HomeXDR reads from, such as a DNS query log: online while the last read worked. */
function PulledSection({ sources }: { sources: PulledSource[] }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Sources HomeXDR reads from</h2>
        <span className="hint">online while the last read worked</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Address</th>
              <th>Last good read</th>
              <th>Checked every</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link to={p.settings_path}>{p.name}</Link>
                  {p.explanation ? (
                    <div className="xsmall muted" style={{ maxWidth: 560, whiteSpace: 'normal' }}>
                      {p.explanation}
                    </div>
                  ) : null}
                </td>
                <td className="mono small">{p.address}</td>
                <td>{p.last_success ? <RelTime iso={p.last_success} /> : <span className="empty-cell">Never</span>}</td>
                <td className="nowrap">{p.interval_sec < 60 ? `${p.interval_sec} s` : formatGap(p.interval_sec)}</td>
                <td>
                  <span className={`badge status ${PULLED_BADGE[p.status]}`}>{PULLED_LABEL[p.status]}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

/** Fixed offline allowances by host label, in place of the learned pattern. */
function OfflineLabelsSection({ rules }: { rules: OfflineLabelRule[] }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canChange = useCan('admin')
  const [draft, setDraft] = useState<OfflineLabelRule[]>(rules)
  const saved = JSON.stringify(rules)
  useEffect(() => setDraft(JSON.parse(saved) as OfflineLabelRule[]), [saved])
  const save = useMutation({
    mutationFn: () => putOfflineLabels(draft),
    onSuccess: (r) => {
      qc.setQueryData(healthKeys.feeds, r)
      toast.success('Offline alert times saved')
    },
    onError: (e) => toast.error(errorMessage(e)),
  })
  const set = (i: number, p: Partial<OfflineLabelRule>) => setDraft(draft.map((r, j) => (j === i ? { ...r, ...p } : r)))
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Offline alerts by host label</h2>
        <span className="hint">replaces the learned pattern for whole hosts</span>
      </div>
      <div className="panel-body stack">
        <p className="small muted" style={{ margin: 0 }}>
          A host with one of these labels raises its “stopped sending data” alert after exactly this long offline, even before HomeXDR has learned its pattern. If a host has several of these labels, the longest time wins.
          Individual data sources on the host still use their learned pattern.
        </p>
        {draft.length === 0 ? <span className="muted small">No label rules. Every host uses its learned pattern.</span> : null}
        {draft.map((r, i) => (
          <div key={i} className="row" style={{ gap: 8, alignItems: 'center' }}>
            <input className="input" aria-label="Host label" placeholder="label" value={r.label} disabled={!canChange} onChange={(e) => set(i, { label: e.target.value })} />
            <input className="input" aria-label={`Hours offline before ${r.label || 'this label'} alerts`} type="number" min={1} max={8760} style={{ width: 100 }} value={r.hours} disabled={!canChange} onChange={(e) => set(i, { hours: Number(e.target.value) })} />
            <span className="small muted">hours{r.hours >= 48 && r.hours % 24 === 0 ? ` (${r.hours / 24} days)` : ''}</span>
            {canChange ? (
              <button className="btn" type="button" onClick={() => setDraft(draft.filter((_, j) => j !== i))}>
                Remove
              </button>
            ) : null}
          </div>
        ))}
        {canChange ? (
          <div className="row" style={{ gap: 8 }}>
            <button className="btn" type="button" onClick={() => setDraft([...draft, { label: '', hours: 24 }])}>
              Add label
            </button>
            <button className="btn primary" type="button" disabled={save.isPending || JSON.stringify(draft) === saved} onClick={() => save.mutate()}>
              Save
            </button>
          </div>
        ) : null}
      </div>
    </section>
  )
}

/** Shown only when the internet-facing agent listener is on. */
function RefusedSection() {
  const q = useQuery({ queryKey: healthKeys.external, queryFn: getRefused, refetchInterval: 60_000 })
  const r = q.data
  if (!r?.enabled) return null
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Internet agent listener</h2>
        <span className="hint">connections refused at the TLS handshake</span>
      </div>
      <div className="panel-body stack">
        <p className="small muted" style={{ margin: 0 }}>
          Anything on the internet can connect to this listener, and everything without a valid agent certificate is refused. That is normal noise and is only counted. An alert is raised when the last full hour had at
          least 50 refused connections and at least three times the average of the 23 hours before.
        </p>
        <dl className="kv">
          <dt>This hour</dt>
          <dd>{r.this_hour}</dd>
          <dt>Last full hour</dt>
          <dd>{r.previous_hour}</dd>
          <dt>Last 24 hours</dt>
          <dd>{r.last_24h}</dd>
        </dl>
        {r.top_sources.length === 0 ? (
          <span className="muted small">No refused connections in the last 24 hours.</span>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Top sources, 24 hours</th>
                <th className="right">Refused</th>
              </tr>
            </thead>
            <tbody>
              {r.top_sources.map((s) => (
                <tr key={s.ip}>
                  <td className="mono">{s.ip}</td>
                  <td className="num right">{s.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}

function SourcesTable({ report }: { report: FeedReport }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canChange = useCan('admin')
  const save = useMutation({
    mutationFn: (p: FeedPatch) => patchFeed(p),
    onSuccess: (r) => qc.setQueryData(healthKeys.feeds, r),
    onError: (e) => toast.error(errorMessage(e)),
  })
  const rows = sortFeeds(report.sources)
  return (
    <>
      {report.grace_until ? (
        <div className="panel-body small muted">The server started recently. No silence alerts until {formatDateTime(report.grace_until)}, so agents have time to reconnect.</div>
      ) : null}
      {report.bootstrapped ? null : <div className="panel-body small muted">Still reading existing history to learn each source’s pattern.</div>}
      {report.note ? <div className="panel-body small muted">{report.note}</div> : null}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Host</th>
              <th>Last seen</th>
              <th>Usual gap</th>
              <th>Allowed silence</th>
              <th>Status</th>
              <th>Mute</th>
              <th>Expected</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <SourceRow key={`${f.host_id}/${f.module}/${f.dataset}`} feed={f} canChange={canChange} onChange={(p) => save.mutate(p)} />
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function SourceRow({ feed: f, canChange, onChange }: { feed: FeedView; canChange: boolean; onChange: (p: FeedPatch) => void }) {
  const id = { host_id: f.host_id, module: f.module, dataset: f.dataset }
  return (
    <tr>
      <td>
        <div className="mono small">{feedName(f)}</div>
        {f.explanation ? (
          <div className="xsmall muted" style={{ maxWidth: 560, whiteSpace: 'normal' }}>
            {f.explanation}
          </div>
        ) : null}
      </td>
      <td>{f.hostname}</td>
      <td>{f.last_seen ? <RelTime iso={f.last_seen} /> : <span className="empty-cell">Never</span>}</td>
      <td className="nowrap">{formatGap(f.usual_gap_sec)}</td>
      <td className="nowrap">{formatGap(f.allowance_sec)}</td>
      <td>
        <span className={`badge status ${FEED_STATUS_BADGE[f.status]}`}>{FEED_STATUS_LABEL[f.status]}</span>
      </td>
      <td>
        <Toggle checked={f.muted} disabled={!canChange} label={`Mute ${feedName(f)}`} onChange={(muted) => onChange({ ...id, muted })} />
      </td>
      <td>
        <Toggle checked={f.expected} disabled={!canChange} label={`Alert if ${feedName(f)} goes quiet, even without a learned pattern`} onChange={(expected) => onChange({ ...id, expected })} />
      </td>
    </tr>
  )
}
