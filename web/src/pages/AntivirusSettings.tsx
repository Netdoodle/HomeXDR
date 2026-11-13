// Settings → Antivirus: how HomeXDR judges the programs that run on enrolled hosts.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { AppControlPanel } from './AppControlPanel'
import { errorMessage } from '../api'
import { avKeys, forgetAVVerdict, getAV, putAV, type AVSettings, type AVStatus } from '../api/antivirus'
import { useCan } from '../components/Auth'
import { KV, RelTime, Toggle } from '../components/Misc'
import { ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'

export function AntivirusTab() {
  const q = useQuery({ queryKey: avKeys.status, queryFn: getAV, refetchInterval: 15_000 })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="stack" style={{ maxWidth: 980 }}>
      <Status status={q.data} />
      <Form key={JSON.stringify(q.data.settings)} settings={q.data.settings} />
      <AppControlPanel />
      <Detections status={q.data} />
    </div>
  )
}

const SOURCE_NAMES: Record<string, string> = {
  clamav: 'ClamAV',
  yara: 'YARA',
  'yara:tool': 'YARA, hacking tool (alert only)',
  'yara:suspicious': 'YARA, suspicious (alert only)',
  blocklist: 'Blocklist',
}

const SOURCE_LABEL = (s: string) => SOURCE_NAMES[s] ?? (s.startsWith('intel:') ? `Threat intel (${s.slice(6)})` : s)

function YaraStatus({ y }: { y: AVStatus['yara'] }) {
  if (!y?.configured) return <span className="muted">not set up (HOMEXDR_YARA_ADDR)</span>
  if (!y.ok) return <span className="sev-text high">not working: {y.error || 'no rules loaded'}</span>
  return (
    <span>
      {formatNumber(y.rules)} rules{y.package ? ` from ${y.package}` : ''}
      {y.custom_files ? `, ${y.custom_files} custom file${y.custom_files === 1 ? '' : 's'}` : ''}
      {y.yara_version ? <span className="muted small"> (YARA {y.yara_version})</span> : null}
      {y.error ? <div className="sev-text medium small">{y.error}</div> : null}
      {y.custom_error ? (
        <div className="sev-text medium small">
          Custom rules not loaded: <span className="mono xsmall">{y.custom_error}</span>
        </div>
      ) : null}
    </span>
  )
}

function Status({ status }: { status: AVStatus }) {
  const v = status.verdicts ?? {}
  const c = status.clamd
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Antivirus</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Every program that starts on an enrolled host is checked by its SHA-256: against your blocklist, then the threat intel sources, and, when nobody
          vouches for it, by uploading it to this server and scanning it with ClamAV and YARA. Each file is judged once for all hosts. Malware is stopped and
          quarantined within seconds of starting. Without a kernel driver this cannot block a program before it runs, so keep Windows Defender on: the two
          work side by side, and Defender's own detections show up here as alerts.
        </p>
        <KV
          items={[
            ['ClamAV', c.configured ? (c.ok ? c.version : <span className="sev-text high">not answering: {c.error}</span>) : <span className="muted">not set up (HOMEXDR_CLAMD_ADDR)</span>],
            ['YARA', <YaraStatus y={status.yara} />],
            ['Files judged', `${formatNumber(v.clean ?? 0)} clean, ${formatNumber(v.known ?? 0)} known good, ${formatNumber(v.malicious ?? 0)} malware, ${formatNumber(v.skipped ?? 0)} not scannable`],
            ['Since the server started', `${formatNumber(status.scanned)} scanned, ${formatNumber(status.detected)} detections, ${formatNumber(status.queue)} waiting`],
            ...(status.last_error ? ([['Last problem', <span className="xsmall mono">{status.last_error}</span>]] as [string, React.ReactNode][]) : []),
          ]}
        />
      </div>
    </div>
  )
}

function Form({ settings }: { settings: AVSettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const isAdmin = useCan('admin')
  const [s, setS] = useState<AVSettings>(settings)
  const [blocked, setBlocked] = useState((settings.blocked_hashes ?? []).join('\n'))
  const [allowed, setAllowed] = useState((settings.allowed_hashes ?? []).join('\n'))
  const lines = (t: string) => t.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean)
  const save = useMutation({
    mutationFn: () => putAV({ ...s, blocked_hashes: lines(blocked), allowed_hashes: lines(allowed) }),
    onSuccess: (st) => {
      qc.setQueryData(avKeys.status, st)
      toast.success('Antivirus settings saved')
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate()
  }
  const set = (p: Partial<AVSettings>) => setS((x) => ({ ...x, ...p }))
  const ro = !isAdmin
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>Settings</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <Toggle checked={s.enabled} disabled={ro} onChange={(v) => set({ enabled: v })} label="Antivirus on" />
          <span>Check programs that run on enrolled hosts</span>
        </div>
        <label className="field" style={{ maxWidth: 420 }}>
          <span className="label">When malware is found</span>
          <select className="input" value={s.action} disabled={ro} onChange={(e) => set({ action: e.target.value as AVSettings['action'] })}>
            <option value="quarantine">Stop the process and its children, quarantine the file</option>
            <option value="alert">Alert only</option>
          </select>
          <span className="help">The response uses the same signed commands as the host page. A quarantined file can be restored from there. YARA matches for hacking tools and generic suspicious traits only raise an alert.</span>
        </label>
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <Toggle checked={s.use_intel} disabled={ro} onChange={(v) => set({ use_intel: v })} label="Look up hashes" />
          <span>
            Look up file hashes with the threat intel sources <span className="muted small">(only the hash is sent; set keys under Threat intel)</span>
          </span>
        </div>
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <Toggle checked={s.scan_unknown} disabled={ro} onChange={(v) => set({ scan_unknown: v })} label="Scan unknown files" />
          <span>
            Upload programs nobody vouches for and scan them with ClamAV and YARA <span className="muted small">(on this server; the upload is deleted afterwards)</span>
          </span>
        </div>
        <div className="row" style={{ gap: 24, alignItems: 'center', paddingLeft: 52, flexWrap: 'wrap' }}>
          <span className="row" style={{ gap: 10, alignItems: 'center' }}>
            <Toggle checked={s.use_clamav} disabled={ro || !s.scan_unknown} onChange={(v) => set({ use_clamav: v })} label="ClamAV" />
            <span>ClamAV</span>
          </span>
          <span className="row" style={{ gap: 10, alignItems: 'center' }}>
            <Toggle checked={s.use_yara} disabled={ro || !s.scan_unknown} onChange={(v) => set({ use_yara: v })} label="YARA" />
            <span>YARA</span>
          </span>
          <span className="help" style={{ margin: 0 }}>
            For every host, unless its group says otherwise (<Link to="/settings/groups">Settings → Groups</Link>).
          </span>
        </div>
        <label className="field" style={{ maxWidth: 420 }}>
          <span className="label">Windows App Control for confirmed malware</span>
          <select className="input" value={s.app_control} disabled={ro} onChange={(e) => set({ app_control: e.target.value as AVSettings['app_control'] })}>
            <option value="off">Off</option>
            <option value="audit">Audit: Windows logs what it would block</option>
            <option value="enforce">Enforce: Windows refuses to run it</option>
          </select>
          <span className="help">
            For every Windows host unless its group says otherwise. Start with Audit and check the CodeIntegrity log before enforcing.
          </span>
        </label>
        <label className="field" style={{ maxWidth: 260 }}>
          <span className="label">Largest file to upload (MB)</span>
          <input className="input" type="number" min={1} max={100} value={s.max_file_mb} disabled={ro} onChange={(e) => set({ max_file_mb: Number(e.target.value) })} />
        </label>
        <div className="grid-2" style={{ gap: 14 }}>
          <label className="field">
            <span className="label">Blocked hashes</span>
            <textarea className="textarea code" rows={5} value={blocked} readOnly={ro} onChange={(e) => setBlocked(e.target.value)} placeholder="One SHA-256 per line" />
            <span className="help">Always malware, wherever they run, including Windows' own folders.</span>
          </label>
          <label className="field">
            <span className="label">Allowed hashes</span>
            <textarea className="textarea code" rows={5} value={allowed} readOnly={ro} onChange={(e) => setAllowed(e.target.value)} placeholder="One SHA-256 per line" />
            <span className="help">Never checked: for your own tools that a signature mistakes for malware.</span>
          </label>
        </div>
        {save.isError ? <div className="callout danger small">{errorMessage(save.error)}</div> : null}
        {isAdmin ? (
          <div>
            <button className="btn primary" type="submit" disabled={save.isPending}>
              Save
            </button>
          </div>
        ) : null}
      </div>
    </form>
  )
}

function Detections({ status }: { status: AVStatus }) {
  const qc = useQueryClient()
  const toast = useToast()
  const canForget = useCan('analyst')
  const forget = useMutation({
    mutationFn: forgetAVVerdict,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: avKeys.status })
      toast.success('Verdict removed: the file is judged again the next time it runs')
    },
    onError: (e) => toast.error(e),
  })
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Recent detections</h2>
      </div>
      {status.detections.length === 0 ? (
        <div className="panel-body small muted">No malware found yet.</div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Detection</th>
              <th>File</th>
              <th>Found by</th>
              <th>When</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {status.detections.map((d) => (
              <tr key={d.sha256}>
                <td>{d.signature || 'Malware'}</td>
                <td>
                  <div className="mono xsmall">{d.path}</div>
                  <div className="mono xsmall muted" title={d.sha256}>
                    {d.sha256.slice(0, 16)}…
                  </div>
                </td>
                <td className="small">{SOURCE_LABEL(d.source)}</td>
                <td className="small">
                  <RelTime iso={d.checked_at} />
                </td>
                <td>
                  {canForget ? (
                    <button className="btn small" type="button" disabled={forget.isPending} onClick={() => forget.mutate(d.sha256)} title="Remove this verdict, for a false positive">
                      Forget
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
