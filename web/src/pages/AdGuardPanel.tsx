// Settings → Network → AdGuard Home: read its query log so DNS shows up per device.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent, type ReactNode } from 'react'
import { errorMessage } from '../api/client'
import {
  adguardKeys,
  getAdGuardSettings,
  putAdGuardSettings,
  testAdGuardSettings,
  type AdGuardInput,
  type AdGuardSettings,
  type AdGuardTestResult,
} from '../api/adguard'
import { KV, RelTime, Toggle } from '../components/Misc'
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
  const [enabled, setEnabled] = useState(settings.enabled)
  const [url, setUrl] = useState(settings.url)
  const [username, setUsername] = useState(settings.username)
  const [password, setPassword] = useState('')
  const [serverName, setServerName] = useState(settings.server_name ?? '')
  const [pin, setPin] = useState(settings.pin_sha256 ?? '')
  const [interval, setIntervalSec] = useState(settings.interval_sec)
  const [result, setResult] = useState<AdGuardTestResult | null>(null)

  const input = (): AdGuardInput => ({
    enabled,
    url: url.trim(),
    username: username.trim(),
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
      toast.success(s.enabled ? 'AdGuard Home settings saved. Reading starts within a minute.' : 'AdGuard Home settings saved')
    },
  })
  const test = useMutation({ mutationFn: testAdGuardSettings, onSuccess: setResult, onError: () => setResult(null) })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate(input())
  }
  const st = settings.status
  const https = url.trim().toLowerCase().startsWith('https://')

  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>AdGuard Home</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          When AdGuard Home answers your network's DNS, the firewall's own resolver never sees which device asked for what. HomeXDR can read AdGuard Home's
          query log instead, so every lookup becomes a DNS event with the device's address. Lookups from before you turn this on are not imported.
        </p>
        <Toggle checked={enabled} onChange={setEnabled} label="Read AdGuard Home's query log" />
        <label className="field">
          <span className="label">Address</span>
          <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://192.168.20.1:3001" spellCheck={false} />
          <span className="help">AdGuard Home's web address: scheme, host and port only. Prefer https, so the password is encrypted on the way.</span>
        </label>
        <div className="grid-2" style={{ gap: 14 }}>
          <label className="field">
            <span className="label">Username</span>
            <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" spellCheck={false} />
          </label>
          <label className="field">
            <span className="label">Password</span>
            <input
              className="input"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={settings.password_set ? 'Saved; type to replace' : ''}
            />
          </label>
        </div>
        <p className="xsmall muted" style={{ margin: 0 }}>
          AdGuard Home has no read-only accounts, so this login can change its settings. HomeXDR only reads the status and the query log, and never shows the
          password again.
        </p>
        {https ? (
          <div className="grid-2" style={{ gap: 14 }}>
            <label className="field">
              <span className="label">Certificate name</span>
              <input className="input mono" value={serverName} onChange={(e) => setServerName(e.target.value)} placeholder="Taken from the address" spellCheck={false} />
              <span className="help">When the address is an IP, the name on AdGuard Home's certificate, such as ads.example.com.</span>
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
            ['Status', `${STATE_LABEL[st.state]}${st.version ? ` · AdGuard Home ${st.version}` : ''}`],
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
        <p className="xsmall muted" style={{ margin: 0 }}>
          Lookups appear in search as <code>event.dataset:dns.adguard</code>. Blocked lookups have <code>event.action:dns-blocked</code>.
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
            If this is your AdGuard Home, you can trust exactly this certificate. Once it is renewed you will need to trust the new one, or clear the field to
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
