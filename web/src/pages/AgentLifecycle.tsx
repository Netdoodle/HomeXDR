// Settings → Agent updates: decommissioning inactive agents and the update policy.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { Link } from 'react-router'
import { api, queryKeys, type AgentLifecycle, type AgentLifecycleView, type UpdateMode, type UpdateRule } from '../api'
import { ChoiceCards } from '../components/ChoiceCards'
import { Icon } from '../components/Icon'
import { RelTime } from '../components/Misc'
import { ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { DECOMMISSION_CHOICES, decommissionLabel, shortVersion, timeZones, UPDATE_MODE_CHOICES, UPDATE_MODE_LABEL } from '../lib/agents'
import { formatDateTime } from '../lib/time'

function Section({ title, help, children }: { title: ReactNode; help?: ReactNode; children: ReactNode }) {
  return (
    <div className="field" style={{ gap: 6 }}>
      <span className="label">{title}</span>
      {help ? <span className="help">{help}</span> : null}
      {children}
    </div>
  )
}

export function AgentLifecycleTab() {
  const q = useQuery({ queryKey: queryKeys.agentLifecycle, queryFn: api.getAgentLifecycle })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <AgentLifecycleForm view={q.data} />
}

function RuleEditor({ rule, onChange, versions, name }: { rule: UpdateRule; onChange: (r: UpdateRule) => void; versions: string[]; name: string }) {
  return (
    <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
      <select
        className="select"
        value={rule.mode}
        aria-label={`${name} update mode`}
        onChange={(e) => onChange({ mode: e.target.value as UpdateMode, version: e.target.value === 'pinned' ? (rule.version ?? versions[0]) : undefined })}
      >
        {UPDATE_MODE_CHOICES.map((c) => (
          <option key={c.value} value={c.value}>
            {c.label}
          </option>
        ))}
      </select>
      {rule.mode === 'pinned' ? (
        <select className="select mono" value={rule.version ?? ''} aria-label={`${name} pinned version`} onChange={(e) => onChange({ mode: 'pinned', version: e.target.value })}>
          {rule.version && !versions.includes(rule.version) ? <option value={rule.version}>{shortVersion(rule.version)} (not archived)</option> : null}
          {versions.map((v) => (
            <option key={v} value={v}>
              {shortVersion(v)}
            </option>
          ))}
        </select>
      ) : null}
    </div>
  )
}

function AgentLifecycleForm({ view }: { view: AgentLifecycleView }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [form, setForm] = useState<AgentLifecycle>(view.settings)
  useEffect(() => setForm(view.settings), [view.settings])
  const zones = useMemo(timeZones, [])
  const versions = view.releases.map((r) => r.version)
  const up = form.updates
  const setUpdates = (u: Partial<AgentLifecycle['updates']>) => setForm((f) => ({ ...f, updates: { ...f.updates, ...u } }))

  const save = useMutation({
    mutationFn: (l: AgentLifecycle) => api.putAgentLifecycle(l),
    onSuccess: (v) => {
      qc.setQueryData(queryKeys.agentLifecycle, v)
      qc.invalidateQueries({ queryKey: queryKeys.hosts() })
      toast.success('Agent settings saved')
    },
    onError: (e) => toast.error(e),
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate(form)
  }
  const customDays = !DECOMMISSION_CHOICES.includes(form.decommission_after_days)
  const moveRule = (i: number, d: -1 | 1) => {
    const labels = [...up.labels]
    ;[labels[i], labels[i + d]] = [labels[i + d], labels[i]]
    setUpdates({ labels })
  }

  return (
    <form className="stack" onSubmit={submit} style={{ maxWidth: 860 }}>
      <section className="panel">
        <div className="panel-header">
          <h2>Inactive agents</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 12 }}>
          <Section
            title="Decommission agents that stay offline"
            help="A decommissioned agent leaves host lists, counts and hunts; its events and alerts are kept. It is restored automatically, with its history, as soon as it reconnects. Syslog sources such as firewalls are not affected."
          >
            <div className="row" style={{ gap: 8 }}>
              <select
                className="select"
                aria-label="Decommission after"
                value={customDays ? 'custom' : String(form.decommission_after_days)}
                onChange={(e) => setForm((f) => ({ ...f, decommission_after_days: e.target.value === 'custom' ? 45 : Number(e.target.value) }))}
              >
                {DECOMMISSION_CHOICES.map((d) => (
                  <option key={d} value={d}>
                    {decommissionLabel(d)}
                  </option>
                ))}
                <option value="custom">Custom…</option>
              </select>
              {customDays ? (
                <label className="row small" style={{ gap: 6 }}>
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={3650}
                    style={{ width: 90 }}
                    value={form.decommission_after_days}
                    onChange={(e) => setForm((f) => ({ ...f, decommission_after_days: Number(e.target.value) }))}
                    aria-label="Days offline"
                  />
                  days offline
                </label>
              ) : null}
            </div>
            {view.decommissioned_agents > 0 ? (
              <span className="small">
                <Link to="/hosts?status=decommissioned">{view.decommissioned_agents} decommissioned {view.decommissioned_agents === 1 ? 'agent' : 'agents'}</Link>
              </span>
            ) : null}
          </Section>
          <p className="small muted" style={{ margin: 0 }}>
            Agent certificates renew themselves about four months before they expire, and an agent that comes back after its certificate expired
            renews it on reconnect. Only revoking a host shuts its agent out for good.
          </p>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Agent updates</h2>
        </div>
        <div className="panel-body stack" style={{ gap: 16 }}>
          <div className={view.release_status.signed ? 'callout ok' : 'callout warn'}>
            <Icon name={view.release_status.signed ? 'check' : 'warning'} size={14} />
            <div>
              {view.release_status.signed ? (
                <>
                  Agents verify every release against the release key pinned when they were installed, so the server cannot push a binary
                  that key did not sign. Agents never downgrade.
                </>
              ) : (
                <>Agent updates are unavailable: {view.release_status.problem}.</>
              )}
            </div>
          </div>

          <Section title="Default policy">
            <ChoiceCards
              name="Default update policy"
              choices={UPDATE_MODE_CHOICES}
              value={up.default.mode}
              onChange={(v) => setUpdates({ default: { mode: v as UpdateMode, version: v === 'pinned' ? (up.default.version ?? versions[0]) : undefined } })}
            />
            {up.default.mode === 'pinned' ? (
              <RuleEditor rule={up.default} versions={versions} name="Default" onChange={(r) => setUpdates({ default: r })} />
            ) : null}
          </Section>

          <Section title="Policies by label" help="Agents with a matching label follow its policy instead of the default. The first matching rule wins.">
            {up.labels.length ? (
              <table className="table compact">
                <thead>
                  <tr>
                    <th style={{ width: 200 }}>Label</th>
                    <th>Policy</th>
                    <th aria-label="Actions" style={{ width: 120 }} />
                  </tr>
                </thead>
                <tbody>
                  {up.labels.map((lr, i) => (
                    <tr key={i}>
                      <td>
                        <input
                          className="input"
                          value={lr.label}
                          aria-label={`Rule ${i + 1} label`}
                          placeholder="e.g. servers"
                          onChange={(e) => setUpdates({ labels: up.labels.map((x, j) => (j === i ? { ...x, label: e.target.value } : x)) })}
                        />
                      </td>
                      <td>
                        <RuleEditor
                          rule={lr.rule}
                          versions={versions}
                          name={`Rule ${i + 1}`}
                          onChange={(r) => setUpdates({ labels: up.labels.map((x, j) => (j === i ? { ...x, rule: r } : x)) })}
                        />
                      </td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <button type="button" className="btn ghost icon sm" disabled={i === 0} onClick={() => moveRule(i, -1)} aria-label="Move up">
                          ↑
                        </button>
                        <button type="button" className="btn ghost icon sm" disabled={i === up.labels.length - 1} onClick={() => moveRule(i, 1)} aria-label="Move down">
                          ↓
                        </button>
                        <button type="button" className="btn ghost icon sm" onClick={() => setUpdates({ labels: up.labels.filter((_, j) => j !== i) })} aria-label="Remove rule">
                          <Icon name="close" size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : null}
            <button
              type="button"
              className="btn sm"
              style={{ alignSelf: 'flex-start' }}
              onClick={() => setUpdates({ labels: [...up.labels, { label: '', rule: { mode: 'n-1' } }] })}
            >
              <Icon name="plus" size={12} /> Add label rule
            </button>
          </Section>

          <Section title="Staged rollout">
            <label className={`choice${up.staged.enabled ? ' selected' : ''}`}>
              <input type="checkbox" checked={up.staged.enabled} onChange={(e) => setUpdates({ staged: { ...up.staged, enabled: e.target.checked } })} />
              <div>
                <div className="choice-title">Update canary agents first</div>
                <div className="choice-note">
                  Agents with the canary label get a new release right away. The others wait until it has been out for the delay, and until a
                  canary runs it without an install error. With no canary agents, only the delay applies.
                  {up.staged.enabled ? ` ${view.canary_agents} ${view.canary_agents === 1 ? 'agent has' : 'agents have'} the canary label.` : ''}
                </div>
              </div>
            </label>
            {up.staged.enabled ? (
              <div className="form-grid">
                <label className="field">
                  <span className="label">Canary label</span>
                  <input className="input" value={up.staged.canary_label} onChange={(e) => setUpdates({ staged: { ...up.staged, canary_label: e.target.value } })} />
                </label>
                <label className="field">
                  <span className="label">Delay for the rest (hours)</span>
                  <input
                    className="input"
                    type="number"
                    min={0}
                    max={2160}
                    value={up.staged.delay_hours}
                    onChange={(e) => setUpdates({ staged: { ...up.staged, delay_hours: Number(e.target.value) } })}
                  />
                </label>
              </div>
            ) : null}
          </Section>

          <Section title="Maintenance window">
            <label className={`choice${up.window.enabled ? ' selected' : ''}`}>
              <input type="checkbox" checked={up.window.enabled} onChange={(e) => setUpdates({ window: { ...up.window, enabled: e.target.checked } })} />
              <div>
                <div className="choice-title">Only update during set hours</div>
                <div className="choice-note">Agents install updates only inside the window. “Update now” on a host ignores it.</div>
              </div>
            </label>
            {up.window.enabled ? (
              <div className="form-grid">
                <label className="field">
                  <span className="label">From</span>
                  <input className="input" type="time" value={up.window.start} onChange={(e) => setUpdates({ window: { ...up.window, start: e.target.value } })} />
                </label>
                <label className="field">
                  <span className="label">Until</span>
                  <input className="input" type="time" value={up.window.end} onChange={(e) => setUpdates({ window: { ...up.window, end: e.target.value } })} />
                  <span className="help">Earlier than “From” means the window runs past midnight.</span>
                </label>
                <label className="field">
                  <span className="label">Time zone</span>
                  <select className="select" value={up.window.timezone} onChange={(e) => setUpdates({ window: { ...up.window, timezone: e.target.value } })}>
                    {(zones.includes(up.window.timezone) ? zones : [up.window.timezone, ...zones]).map((z) => (
                      <option key={z} value={z}>
                        {z}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
            ) : null}
          </Section>

          <div className="row" style={{ gap: 8 }}>
            <button type="submit" className="btn primary" disabled={save.isPending}>
              Save
            </button>
            {save.isPending ? <Spinner small /> : null}
          </div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Release archive</h2>
          <span className="small muted">The server keeps recent signed releases for N-1 and pinned policies.</span>
        </div>
        {view.releases.length ? (
          <table className="table compact">
            <thead>
              <tr>
                <th>Release</th>
                <th>Built</th>
                <th>Available since</th>
                <th className="right">Agents</th>
              </tr>
            </thead>
            <tbody>
              {view.releases.map((r, i) => (
                <tr key={r.version}>
                  <td className="mono small" title={r.version}>
                    {shortVersion(r.version)}
                    {i === 0 ? <span className="badge" style={{ marginLeft: 8 }}>{UPDATE_MODE_LABEL.latest}</span> : null}
                    {i === 1 ? <span className="badge" style={{ marginLeft: 8 }}>{UPDATE_MODE_LABEL['n-1']}</span> : null}
                  </td>
                  <td className="small">{formatDateTime(new Date(r.commit_time * 1000).toISOString())}</td>
                  <td className="small">{r.archived_at ? <RelTime iso={r.archived_at} /> : '—'}</td>
                  <td className="right">{r.agents}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="panel-body small muted">No signed releases yet. The server archives its bundled release once it is signed.</div>
        )}
      </section>
    </form>
  )
}
