// Settings → Firewall: addresses blocked in every host's own firewall (everywhere, or for
// one group and its child groups), the global switch and where the rules are applied.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { errorMessage } from '../api'
import {
  addFirewallBlock,
  firewallKeys,
  getFirewall,
  putFirewallSettings,
  removeFirewallBlock,
  type FirewallBlock,
  type FirewallDirection,
  type FirewallHost,
  type FirewallView,
} from '../api/firewall'
import { getGroups, groupKeys, groupPath } from '../api/groups'
import { useCan } from '../components/Auth'
import { RelTime, Toggle } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { blockProblem, DIRECTION_LABEL, FIREWALL_STATUS, PLATFORM_FIREWALL } from '../lib/firewall'

export function FirewallTab() {
  const q = useQuery({ queryKey: firewallKeys.status, queryFn: getFirewall, refetchInterval: 20_000 })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return (
    <div className="stack" style={{ maxWidth: 1100 }}>
      <Overview v={q.data} />
      <Blocks v={q.data} />
      <Hosts v={q.data} />
    </div>
  )
}

function useFirewallMutation<A>(fn: (a: A) => Promise<FirewallView>, done?: (a: A) => string) {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: fn,
    onSuccess: (v, a) => {
      qc.setQueryData(firewallKeys.status, v)
      qc.invalidateQueries({ queryKey: groupKeys.all })
      if (done) toast.success(done(a))
    },
    onError: (e) => toast.error(e),
  })
}

function Overview({ v }: { v: FirewallView }) {
  const isAdmin = useCan('admin')
  const [confirmOff, setConfirmOff] = useState(false)
  const save = useFirewallMutation((enabled: boolean) => putFirewallSettings({ enabled }), (on) => (on ? 'Host firewall blocking is on' : 'Host firewall blocking is off'))
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Host firewall</h2>
        <span className="hint">Block addresses on every host</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <p className="small muted" style={{ margin: 0 }}>
          Addresses listed here are blocked in each enrolled host's own firewall: Windows Firewall rules in their own <span className="mono">HomeXDR</span>{' '}
          group, the nftables table <span className="mono">inet homexdr_block</span> on Linux, and a pf anchor on macOS. A block applies everywhere or to one
          group and its child groups; a group can turn blocking off under <Link to="/settings/groups">Settings → Groups</Link>. The agent replaces only its
          own rules, and refuses any rule that covers the HomeXDR server.
        </p>
        <div className="row" style={{ gap: 10, alignItems: 'center' }}>
          <Toggle
            checked={v.settings.enabled}
            disabled={!isAdmin || save.isPending}
            onChange={(on) => (on ? save.mutate(true) : setConfirmOff(true))}
            label="Host firewall blocking"
          />
          <span>Block the listed addresses on hosts whose group does not say otherwise</span>
        </div>
        <p className="xsmall muted" style={{ margin: 0 }}>
          Never blocked: this server ({v.server_addrs.length ? v.server_addrs.join(', ') : 'no addresses found'}), loopback, link-local and multicast
          addresses, IPv4 networks broader than /{v.limits.min_prefix_v4} and IPv6 networks broader than /{v.limits.min_prefix_v6}. At most{' '}
          {v.limits.max_blocks} entries.
        </p>
      </div>
      <ConfirmDialog
        open={confirmOff}
        onClose={() => setConfirmOff(false)}
        title="Turn host firewall blocking off?"
        confirmLabel="Turn off"
        danger
        onConfirm={() => save.mutateAsync(false)}
      >
        Hosts whose group does not turn it on again remove every HomeXDR block rule, so they can reach the listed addresses again.
      </ConfirmDialog>
    </div>
  )
}

function Blocks({ v }: { v: FirewallView }) {
  const isAdmin = useCan('admin')
  const [removing, setRemoving] = useState<FirewallBlock | null>(null)
  const remove = useFirewallMutation((b: FirewallBlock) => removeFirewallBlock(b.id), (b) => `${b.cidr} is no longer blocked`)
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Blocked addresses</h2>
        <span className="hint">
          {v.blocks.length} of {v.limits.max_blocks}
        </span>
      </div>
      <div className="panel-body stack" style={{ gap: 14 }}>
        {isAdmin ? <AddForm v={v} /> : null}
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Address</th>
                <th>Direction</th>
                <th>Applies to</th>
                <th>Note</th>
                <th>Added</th>
                {isAdmin ? <th /> : null}
              </tr>
            </thead>
            <tbody>
              {v.blocks.length === 0 ? (
                <tr>
                  <td colSpan={isAdmin ? 6 : 5} className="muted small">
                    Nothing is blocked. Add an address above, or use “Block this IP everywhere” in an alert’s Investigate menu.
                  </td>
                </tr>
              ) : (
                v.blocks.map((b) => (
                  <tr key={b.id}>
                    <td className="mono small">
                      {b.cidr}
                      {b.problem ? <div className="sev-text medium xsmall">{b.problem}</div> : null}
                    </td>
                    <td className="small">{DIRECTION_LABEL[b.direction] ?? b.direction}</td>
                    <td className="small">{b.group_id ? b.scope : `Everywhere (${b.scope})`}</td>
                    <td className="small">
                      {b.note || <span className="muted">—</span>}
                      {b.alert_id ? (
                        <>
                          {' '}
                          <Link to={`/alerts/${encodeURIComponent(b.alert_id)}`} className="xsmall">
                            alert
                          </Link>
                        </>
                      ) : null}
                    </td>
                    <td className="small">
                      <RelTime iso={b.created_at} /> <span className="muted xsmall">by {b.created_by}</span>
                    </td>
                    {isAdmin ? (
                      <td className="right">
                        <button type="button" className="btn sm" onClick={() => setRemoving(b)}>
                          Remove
                        </button>
                      </td>
                    ) : null}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
      <ConfirmDialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        title="Stop blocking this address?"
        confirmLabel="Remove block"
        danger
        onConfirm={() => (removing ? remove.mutateAsync(removing) : undefined)}
      >
        {removing ? (
          <>
            Hosts {removing.group_id ? `in ${removing.scope}` : 'everywhere'} will be able to reach <span className="mono">{removing.cidr}</span> again
            (unless another entry still blocks it).
          </>
        ) : null}
      </ConfirmDialog>
    </div>
  )
}

function AddForm({ v }: { v: FirewallView }) {
  const groupsQ = useQuery({ queryKey: groupKeys.all, queryFn: getGroups, staleTime: 60_000 })
  const [cidr, setCidr] = useState('')
  const [direction, setDirection] = useState<FirewallDirection>('both')
  const [scope, setScope] = useState('')
  const [note, setNote] = useState('')
  const add = useMutation({
    mutationFn: () => addFirewallBlock({ cidr: cidr.trim(), direction, group_id: scope, note: note.trim() }),
  })
  const qc = useQueryClient()
  const toast = useToast()
  const problem = cidr.trim() ? blockProblem(cidr, v.limits.min_prefix_v4, v.limits.min_prefix_v6) : null
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!cidr.trim() || problem) return
    add.mutate(undefined, {
      onSuccess: (nv) => {
        qc.setQueryData(firewallKeys.status, nv)
        toast.success(`${cidr.trim()} is being blocked`)
        setCidr('')
        setNote('')
      },
    })
  }
  const groups = groupsQ.data
  return (
    <form className="stack" style={{ gap: 10 }} onSubmit={submit}>
      <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label className="field" style={{ minWidth: 220, flex: '1 1 220px' }}>
          <span className="label">IP address or CIDR</span>
          <input className="input mono" value={cidr} placeholder="203.0.113.7 or 2001:db8::/48" onChange={(e) => setCidr(e.target.value)} />
        </label>
        <label className="field" style={{ minWidth: 150 }}>
          <span className="label">Direction</span>
          <select className="input" value={direction} onChange={(e) => setDirection(e.target.value as FirewallDirection)}>
            {(Object.keys(DIRECTION_LABEL) as FirewallDirection[]).map((d) => (
              <option key={d} value={d}>
                {DIRECTION_LABEL[d]}
              </option>
            ))}
          </select>
        </label>
        <label className="field" style={{ minWidth: 220 }}>
          <span className="label">Applies to</span>
          <select className="input" value={scope} onChange={(e) => setScope(e.target.value)} aria-label="Applies to">
            <option value="">Everywhere ({groups?.org.name ?? 'Global'})</option>
            {(groups?.groups ?? []).map((g) => (
              <option key={g.id} value={g.id}>
                {g.parent_id ? '   ' : ''}
                {groupPath(groups!, g.id)}
                {g.parent_id ? '' : ' and its child groups'}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label className="field">
        <span className="label">Note</span>
        <input className="input" value={note} maxLength={300} placeholder="Why it is blocked" onChange={(e) => setNote(e.target.value)} />
      </label>
      {problem ? <div className="callout warn small">{problem}</div> : null}
      {add.isError ? <div className="callout danger small">{errorMessage(add.error)}</div> : null}
      <div>
        <button className="btn primary" type="submit" disabled={!cidr.trim() || !!problem || add.isPending}>
          Block
        </button>
      </div>
    </form>
  )
}

function Hosts({ v }: { v: FirewallView }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Hosts</h2>
        <span className="hint">Where the rules are applied</span>
      </div>
      <div className="panel-body">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Firewall</th>
                <th>Blocking</th>
                <th>Status</th>
                <th className="right">Rules</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {v.hosts.length === 0 ? (
                <tr>
                  <td colSpan={6} className="muted small">
                    No Windows, Linux or macOS hosts.
                  </td>
                </tr>
              ) : (
                v.hosts.map((h) => <HostRow key={h.host_id} h={h} />)
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function HostRow({ h }: { h: FirewallHost }) {
  const s = FIREWALL_STATUS[h.status] ?? { label: h.status, cls: '' }
  return (
    <tr>
      <td>
        <Link to={`/hosts/${encodeURIComponent(h.host_id)}`}>{h.hostname}</Link>
      </td>
      <td className="small">{PLATFORM_FIREWALL[h.platform] ?? h.platform}</td>
      <td className="small">
        {h.enabled ? 'On' : 'Off'} <span className="muted xsmall">from {h.enabled_from || 'Global'}</span>
      </td>
      <td className={s.cls}>{s.label}</td>
      <td className="right num">{h.status === 'applied' ? h.applied_rules : h.rules || '—'}</td>
      <td className="small muted">
        {h.message}
        {h.updated_at ? (
          <>
            {' '}
            · <RelTime iso={h.updated_at} />
          </>
        ) : null}
      </td>
    </tr>
  )
}
