// Settings → Network → DNS resolver query log: read AdGuard Home's, Pi-hole's or Technitium's
// query log so DNS shows up per device.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { errorMessage } from '../api/client'
import {
  RESOLVERS,
  adguardKeys,
  resolverOf,
  getAdGuardSettings,
  putAdGuardSettings,
  testAdGuardSettings,
  type AdGuardInput,
  type AdGuardSettings,
  type AdGuardTestResult,
  type ResolverKind,
} from '../api/adguard'
import { KV, RelTime, Toggle } from '../components/Misc'
import { HistoryImport } from './AdGuardHistory'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { formatDateTime } from '../lib/time'

export function AdGuardPanel() {
  const q = useQuery({ queryKey: adguardKeys.settings, queryFn: getAdGuardSettings, refetchInterval: 30_000 })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <AdGuardForm key={q.data.url + q.data.pin_sha256} settings={q.data} />
}

const STATE_LABEL: Record<AdGuardSettings['status']['state'], string> = {
  off: 'Off',
  waiting: 'Waiting for the first read',
  ok: 'Reading',
  error: 'Failing',
}

function AdGuardForm({ settings }: { settings: AdGuardSettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const savedKind = resolverOf(settings.kind)
  const [kind, setKind] = useState<ResolverKind>(savedKind)
  const r = RESOLVERS[kind]
  const [enabled, setEnabled] = useState(settings.enabled)
  const [url, setUrl] = useState(settings.url)
  const [username, setUsername] = useState(settings.username)
  const [password, setPassword] = useState('')
  const [serverName, setServerName] = useState(settings.server_name ?? '')
  const [pin, setPin] = useState(settings.pin_sha256 ?? '')
  const [interval, setIntervalSec] = useState(settings.interval_sec)
  const [result, setResult] = useState<AdGuardTestResult | null>(null)

  const input = (): AdGuardInput => ({
    kind,
    enabled,
    url: url.trim(),
    username: r.username ? username.trim() : '',
    password: password || undefined,
    server_name: serverName.trim() || undefined,
    pin_sha256: pin.trim() || undefined,
    interval_sec: interval,
  })
  const save = useMutation({
    mutationFn: putAdGuardSettings,
    onSuccess: (s) => {
      qc.setQueryData(adguardKeys.settings, s)
      setPassword('')
      const n = RESOLVERS[resolverOf(s.kind)].name
      toast.success(s.enabled ? `${n} settings saved. Reading starts within a minute.` : `${n} settings saved`)
    },
  })
  const test = useMutation({ mutationFn: testAdGuardSettings, onSuccess: setResult, onError: () => setResult(null) })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate(input())
  }
  const st = settings.status
  const https = url.trim().toLowerCase().startsWith('https://')
  // A saved secret belongs to the saved resolver; switching needs the new one's.
  const secretSaved = settings.password_set && kind === savedKind

  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>DNS resolver query log</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          When a homelab resolver such as AdGuard Home, Pi-hole or Technitium answers your network's DNS, the firewall's own resolver never sees which device
          asked for what. HomeXDR can read that resolver's query log instead, so every lookup becomes a DNS event with the device's address. Lookups from
          before you turn this on are only imported if you import the history.
        </p>
        <label className="field" style={{ maxWidth: 320 }}>
          <span className="label">Resolver</span>
          <select
            className="input"
            value={kind}
            onChange={(e) => {
              const k = e.target.value as ResolverKind
              setKind(k)
              setResult(null)
              // A trusted certificate belongs to one server.
              setPin(k === savedKind ? (settings.pin_sha256 ?? '') : '')
              setServerName(k === savedKind ? (settings.server_name ?? '') : '')
            }}
          >
            {(Object.keys(RESOLVERS) as ResolverKind[]).map((k) => (
              <option key={k} value={k}>
                {RESOLVERS[k].name}
              </option>
            ))}
          </select>
          {kind !== savedKind && settings.url ? (
            <span className="help">Saving switches from {RESOLVERS[savedKind].name}: reading starts afresh, and its saved password is not reused.</span>
          ) : null}
        </label>
        <Toggle checked={enabled} onChange={setEnabled} label={`Read ${r.name}'s query log`} />
        <label className="field">
          <span className="label">Address</span>
          <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder={r.address} spellCheck={false} />
          <span className="help">
            {r.name}'s web address: scheme, host and port only. Prefer https, so the {r.secret.toLowerCase()} is encrypted on the way.
          </span>
        </label>
        <div className="grid-2" style={{ gap: 14 }}>
          {r.username ? (
            <label className="field">
              <span className="label">Username</span>
              <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" spellCheck={false} />
            </label>
          ) : null}
          <label className="field">
            <span className="label">{r.secret}</span>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={secretSaved ? 'Saved; type to replace' : ''}
            />
          </label>
        </div>
        <p className="xsmall muted" style={{ margin: 0 }}>
          {r.secretHelp} HomeXDR never shows the {r.secret.toLowerCase()} again.
        </p>
        {https ? (
          <div className="grid-2" style={{ gap: 14 }}>
            <label className="field">
              <span className="label">Certificate name</span>
              <input className="input mono" value={serverName} onChange={(e) => setServerName(e.target.value)} placeholder="Taken from the address" spellCheck={false} />
              <span className="help">When the address is an IP, the name on {r.name}'s certificate, such as dns.example.com.</span>
            </label>
            <label className="field">
              <span className="label">Trusted certificate</span>
              <input className="input mono" value={pin} onChange={(e) => setPin(e.target.value)} placeholder="None: check it normally" spellCheck={false} />
              <span className="help">A SHA-256 fingerprint. HomeXDR then trusts exactly that certificate, even if it has expired, and refuses any other.</span>
            </label>
          </div>
        ) : null}
        <label className="field" style={{ maxWidth: 260 }}>
          <span className="label">Check every (seconds)</span>
          <input className="input" type="number" min={10} max={3600} value={interval} onChange={(e) => setIntervalSec(Number(e.target.value))} />
        </label>

        {result ? <TestOutcome result={result} onTrust={(fp) => { setPin(fp); setResult(null) }} /> : null}
        {test.isError ? <div className="callout danger small">{errorMessage(test.error)}</div> : null}
        {save.isError ? <div className="callout danger small">{errorMessage(save.error)}</div> : null}

        <div className="row" style={{ gap: 8 }}>
          <button type="submit" className="btn primary" disabled={save.isPending}>
            {save.isPending ? <Spinner /> : null} Save
          </button>
          <button type="button" className="btn" onClick={() => test.mutate(input())} disabled={test.isPending || !url.trim()}>
            {test.isPending ? <Spinner /> : null} Test connection
          </button>
        </div>

        <KV
          items={[
            ['Status', `${STATE_LABEL[st.state]}${st.version ? ` · ${RESOLVERS[savedKind].name} ${st.version}` : ''}`],
            ...(st.last_success
              ? ([['Last read', <span key="lr"><RelTime iso={st.last_success} />, {formatNumber(st.last_batch)} new lookups</span>]] as [string, ReactNode][])
              : []),
            ...(st.imported ? ([['Stored since start', `${formatNumber(st.imported)} lookups`]] as [string, ReactNode][]) : []),
            ...(st.since ? ([['Importing since', formatDateTime(st.since)]] as [string, ReactNode][]) : []),
            ...(st.fell_behind
              ? ([['Fell behind', `${formatNumber(st.fell_behind)} times; the oldest part of those bursts was skipped. Check more often.`]] as [string, ReactNode][])
              : []),
            ...(st.last_error ? ([['Last error', <span key="le" className="danger-text">{st.last_error}</span>]] as [string, ReactNode][]) : []),
          ]}
        />
        <HistoryImport settings={settings} />
        <p className="xsmall muted" style={{ margin: 0 }}>
          Lookups appear in search as <code>event.dataset:{RESOLVERS[savedKind].dataset}</code>. Blocked lookups from any resolver have{' '}
          <code>event.action:dns-blocked</code>, and <code>event.module:dns</code> covers every DNS source.
        </p>
      </div>
    </form>
  )
}

function TestOutcome({ result, onTrust }: { result: AdGuardTestResult; onTrust: (fingerprint: string) => void }) {
  const c = result.certificate
  return (
    <div className={`callout small ${result.ok ? 'ok' : 'danger'}`}>
      <div>{result.message}</div>
      {c ? (
        <div className="stack" style={{ gap: 6, marginTop: 8 }}>
          <div>
            The certificate is for <strong>{c.subject || (c.names ?? []).join(', ') || 'no name'}</strong>, issued by {c.issuer || 'unknown'},{' '}
            {c.expired ? 'expired' : 'valid until'} {formatDateTime(c.not_after)}.
          </div>
          <div className="mono xsmall" style={{ wordBreak: 'break-all' }}>
            {c.fingerprint}
          </div>
          <div>
            If this is your resolver, you can trust exactly this certificate. Once it is renewed you will need to trust the new one, or clear the field to
            check it normally again.
          </div>
          <div>
            <button type="button" className="btn small" onClick={() => onTrust(c.fingerprint)}>
              Trust this certificate
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
