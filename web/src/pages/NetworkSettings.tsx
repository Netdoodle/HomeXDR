// Settings → Network: the home network's subnets, new-device alerts and behaviour detectors.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { errorMessage } from '../api/client'
import {
  getBehaviorSettings,
  getNetworkSettings,
  networkKeys,
  putBehaviorSettings,
  putNetworkSettings,
  type DetectorSettings,
  type NetworkSettings,
} from '../api/network'
import { Toggle } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { behaviorUpdate, parseLines } from '../lib/network'
import { formatDateTime } from '../lib/time'

export function NetworkSettingsTab() {
  const net = useQuery({ queryKey: networkKeys.settings, queryFn: getNetworkSettings })
  const beh = useQuery({ queryKey: networkKeys.behaviorSettings, queryFn: getBehaviorSettings })
  if (net.isPending || beh.isPending) return <Loading />
  if (net.isError) return <ErrorState error={net.error} onRetry={() => net.refetch()} />
  if (beh.isError) return <ErrorState error={beh.error} onRetry={() => beh.refetch()} />
  return (
    <div className="stack" style={{ maxWidth: 980 }}>
      <HomeNetworkForm settings={net.data} />
      <DetectorsForm detectors={beh.data.detectors} />
    </div>
  )
}

const lines = (v: string[] | undefined) => (v ?? []).join('\n')

function HomeNetworkForm({ settings }: { settings: NetworkSettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [subnets, setSubnets] = useState(lines(settings.subnets))
  const [exclude, setExclude] = useState(lines(settings.exclude))
  const [firewall, setFirewall] = useState(lines(settings.firewall_ips))
  const [alerts, setAlerts] = useState(settings.new_device_alerts)
  const [days, setDays] = useState(settings.learning_days)
  const save = useMutation({
    mutationFn: putNetworkSettings,
    onSuccess: (s) => {
      qc.setQueryData(networkKeys.settings, s)
      qc.invalidateQueries({ queryKey: networkKeys.devices })
      toast.success('Network settings saved')
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate({ subnets: parseLines(subnets), exclude: parseLines(exclude), firewall_ips: parseLines(firewall), new_device_alerts: alerts, learning_days: days })
  }
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>Home network</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        <p className="small muted" style={{ margin: 0 }}>
          The device inventory and the behaviour detectors share this view of your network.
        </p>
        <label className="field">
          <span className="label">Home subnets</span>
          <textarea className="textarea code" rows={3} value={subnets} onChange={(e) => setSubnets(e.target.value)} placeholder="Automatic" spellCheck={false} />
          <span className="help">
            One per line, such as 192.168.20.0/24. Leave empty for automatic: every private IPv4 address counts, except 172.16.0.0/12, where Docker's bridges live.
            {settings.subnets_seen?.length ? ` Seen so far: ${settings.subnets_seen.map((s) => `${s.subnet} (${s.devices})`).join(', ')}.` : ''}
          </span>
        </label>
        <label className="field">
          <span className="label">Never count these</span>
          <textarea className="textarea code" rows={2} value={exclude} onChange={(e) => setExclude(e.target.value)} spellCheck={false} />
          <span className="help">Subnets to leave out, such as a guest network or a container bridge. Their devices and traffic are ignored here and by the detectors.</span>
        </label>
        <label className="field">
          <span className="label">Firewall addresses</span>
          <textarea className="textarea code" rows={2} value={firewall} onChange={(e) => setFirewall(e.target.value)} spellCheck={false} />
          <span className="help">
            The firewall's own addresses are not devices. They are learned from its logs, and the same last number is assumed on the firewall's other VLANs. Add any that does not fit.
            {settings.firewall_learned?.length ? ` Learned so far: ${settings.firewall_learned.join(', ')}.` : ''}
          </span>
        </label>
        <div className="field">
          <label className="row small" style={{ gap: 8 }}>
            <Toggle checked={alerts} onChange={setAlerts} label="Alert on new devices" />
            Alert on new devices
          </label>
          <span className="help">Raises a low-severity alert for each device first seen after the learning period. Devices that appear while this is off are not raised later.</span>
        </div>
        <label className="field">
          <span className="label">Learning days</span>
          <input className="input" type="number" style={{ maxWidth: 120 }} min={1} max={90} value={days} onChange={(e) => setDays(Number(e.target.value))} />
          <span className="help">
            Devices seen this soon after the feature first started count as normal.
            {settings.learning_until ? ` Currently until ${formatDateTime(settings.learning_until)}.` : ''}
          </span>
        </label>
        {save.isError ? <div className="callout danger">{errorMessage(save.error)}</div> : null}
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button type="submit" className="btn primary" disabled={save.isPending}>
            {save.isPending ? <Spinner small /> : null} Save
          </button>
        </div>
      </div>
    </form>
  )
}

function DetectorsForm({ detectors }: { detectors: DetectorSettings[] }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [draft, setDraft] = useState(detectors)
  // Lists are edited as text, and only become entries on save.
  const [texts, setTexts] = useState<Record<string, string>>({})
  useEffect(() => setDraft(detectors), [detectors])
  const save = useMutation({
    mutationFn: putBehaviorSettings,
    onSuccess: (s) => {
      qc.setQueryData(networkKeys.behaviorSettings, s)
      qc.invalidateQueries({ queryKey: networkKeys.behaviorStatus })
      setTexts({})
      toast.success('Detector settings saved')
    },
  })
  const update = (id: string, p: Partial<DetectorSettings>) => setDraft((all) => all.map((d) => (d.id === id ? { ...d, ...p } : d)))
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const merged = draft.map((d) => {
      const out = { ...d, lists: { ...d.lists } }
      for (const l of d.list_defs) {
        const t = texts[`${d.id}/${l.key}`]
        if (t !== undefined) out.lists[l.key] = parseLines(t)
      }
      return out
    })
    save.mutate(behaviorUpdate(merged))
  }
  return (
    <form className="panel" onSubmit={submit}>
      <div className="panel-header">
        <h2>Behaviour detectors</h2>
      </div>
      <div className="panel-body stack" style={{ gap: 4 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Detectors run one at a time in the background, and findings appear as low or medium alerts. Each thing is reported once per the days set below. The Devices page shows how each is doing.
        </p>
      </div>
      {draft.map((d) => (
        <details key={d.id} style={{ borderTop: '1px solid var(--border)', padding: '10px 16px' }}>
          <summary className="row" style={{ gap: 10, cursor: 'pointer', flexWrap: 'nowrap' }}>
            <span onClick={(e) => e.stopPropagation()}>
              <Toggle checked={d.enabled} onChange={(v) => update(d.id, { enabled: v })} label={`${d.enabled ? 'Turn off' : 'Turn on'} ${d.title}`} />
            </span>
            <span className="small">
              <strong>{d.title}</strong>
              <div className="muted">{d.about}</div>
            </span>
          </summary>
          <div className="form-grid" style={{ marginTop: 12 }}>
            {d.thresholds.map((t) => (
              <label className="field" key={t.key}>
                <span className="label">{t.label}</span>
                <input
                  className="input"
                  type="number"
                  step="any"
                  min={t.min}
                  max={t.max}
                  value={d.values[t.key] ?? t.default}
                  onChange={(e) => update(d.id, { values: { ...d.values, [t.key]: Number(e.target.value) } })}
                />
                <span className="help">
                  {t.help} Default {t.default}.
                </span>
              </label>
            ))}
            {d.list_defs.map((l) => (
              <label className="field" key={l.key}>
                <span className="label">{l.label}</span>
                <textarea
                  className="textarea code"
                  rows={3}
                  spellCheck={false}
                  value={texts[`${d.id}/${l.key}`] ?? lines(d.lists[l.key])}
                  onChange={(e) => setTexts((x) => ({ ...x, [`${d.id}/${l.key}`]: e.target.value }))}
                />
                <span className="help">{l.help}</span>
              </label>
            ))}
          </div>
        </details>
      ))}
      <div className="panel-body stack">
        {save.isError ? <div className="callout danger">{errorMessage(save.error)}</div> : null}
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <button type="submit" className="btn primary" disabled={save.isPending}>
            {save.isPending ? <Spinner small /> : null} Save
          </button>
        </div>
      </div>
    </form>
  )
}
