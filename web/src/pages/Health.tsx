// Data health: which data sources are arriving, and how far to trust a quiet console.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useParams } from 'react-router'
import { errorMessage } from '../api/client'
import { getFeeds, healthKeys, patchFeed, type FeedPatch, type FeedReport, type FeedView } from '../api/health'
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
      <section className="panel">
        <QueryView query={q}>{(d) => <SourcesTable report={d} />}</QueryView>
      </section>
    </div>
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
