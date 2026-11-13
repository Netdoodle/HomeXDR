// Settings → Groups: the organisation (Global), parent groups and child groups, which
// hosts are in them, and the settings each group overrides.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Fragment, useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api, errorMessage, queryKeys } from '../api'
import {
  choiceLabel,
  createGroup,
  deleteGroup,
  effectiveValue,
  getGroups,
  globalValue,
  groupKeys,
  groupPath,
  inheritedValue,
  isWeaker,
  putOrg,
  setHostsGroup,
  SETTINGS,
  updateGroup,
  type GroupsView,
  type HostGroup,
  type SettingDef,
} from '../api/groups'
import { useCan } from '../components/Auth'
import { ConfirmDialog, Modal } from '../components/Modal'
import { ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'

/** Where each setting's global value is changed. */
const GLOBAL_LINK: Record<string, string> = {
  clamav: '/settings/antivirus',
  yara: '/settings/antivirus',
  action: '/settings/antivirus',
  app_control: '/settings/antivirus',
  defender_hardening: '/settings/antivirus',
  ai_auto: '/settings/ai',
}

export function GroupsTab() {
  const q = useQuery({ queryKey: groupKeys.all, queryFn: getGroups })
  if (q.isPending) return <Loading />
  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />
  return <Groups v={q.data} />
}

/** Mutations that answer with the whole tree. */
function useGroupMutation<A>(fn: (a: A) => Promise<GroupsView>, done?: string) {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: fn,
    onSuccess: (v) => {
      qc.setQueryData(groupKeys.all, v)
      qc.invalidateQueries({ queryKey: queryKeys.hosts() })
      if (done) toast.success(done)
    },
    onError: (e) => toast.error(e),
  })
}

/** A change to weaker protection than the group would inherit, waiting for confirmation. */
type PendingWeaker = { g: HostGroup; def: SettingDef; value: string; from: string; fromValue: string }

function Groups({ v }: { v: GroupsView }) {
  const isAdmin = useCan('admin')
  const [adding, setAdding] = useState<{ parent: string } | null>(null)
  const [renaming, setRenaming] = useState<HostGroup | 'org' | null>(null)
  const [deleting, setDeleting] = useState<HostGroup | null>(null)
  const [hostsOf, setHostsOf] = useState<HostGroup | null>(null)
  const [pending, setPending] = useState<PendingWeaker | null>(null)
  const policy = useGroupMutation(({ g, def, value }: { g: HostGroup; def: SettingDef; value: string | undefined }) =>
    updateGroup(g.id, { policy: def.set(g.policy, value) }),
  )
  const del = useGroupMutation((id: string) => deleteGroup(id), 'Group deleted')

  const children = (id: string) => v.groups.filter((g) => g.parent_id === id)
  const parents = children('')

  const change = (g: HostGroup, def: SettingDef, choice: string) => {
    const value = choice === 'inherit' ? undefined : choice
    // Weaker protection than the group would adopt from Global or its parent group asks
    // first: the group stops adopting that setting.
    const inh = inheritedValue(v, g, def.key)
    if (value !== undefined && isWeaker(def, value, inh.value)) {
      setPending({ g, def, value, from: inh.from, fromValue: inh.value })
      return
    }
    policy.mutate({ g, def, value })
  }

  return (
    <div className="stack" style={{ maxWidth: 1400 }}>
      <div className="panel">
        <div className="panel-header">
          <h2>Host groups</h2>
          {isAdmin ? (
            <button className="btn small" onClick={() => setAdding({ parent: '' })}>
              Add parent group
            </button>
          ) : null}
        </div>
        <div className="panel-body stack" style={{ gap: 12 }}>
          <p className="small muted" style={{ margin: 0 }}>
            Your organisation is at the top, with parent groups under it and child groups under those, for example{' '}
            <em>{v.org.name} › DTS Assets › Marketing Dept</em>. Each host is in one group. A group can override settings for its hosts and its child
            groups; set to <strong>Inherit</strong>, it takes the value from its parent group, and parent groups take it from {v.org.name}. New hosts go
            into the group their enrollment token names (<Link to="/settings/tokens">Enrollment</Link>).
          </p>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Group</th>
                  <th style={{ width: 70 }}>Hosts</th>
                  {SETTINGS.map((d) => (
                    <th key={d.key} style={{ width: 210 }}>
                      {d.label}
                    </th>
                  ))}
                  {isAdmin ? <th style={{ width: 200 }} /> : null}
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <strong>{v.org.name}</strong> <span className="muted small">(Global)</span>
                  </td>
                  <td title="Hosts in no group">
                    <Link to="/hosts?group=none">{formatNumber(v.ungrouped)}</Link>
                  </td>
                  {SETTINGS.map((d) => (
                    <td key={d.key}>
                      {choiceLabel(d, globalValue(v, d.key))}
                      {d.key === 'ai_auto' ? <span className="muted xsmall"> (when the AI analyst is on)</span> : null}{' '}
                      <Link className="small" to={GLOBAL_LINK[d.key]}>
                        change
                      </Link>
                    </td>
                  ))}
                  {isAdmin ? (
                    <td className="row" style={{ gap: 6 }}>
                      <button className="btn small ghost" onClick={() => setRenaming('org')}>
                        Rename
                      </button>
                    </td>
                  ) : null}
                </tr>
                {parents.map((p) => (
                  <GroupRows
                    key={p.id}
                    g={p}
                    v={v}
                    kids={children(p.id)}
                    isAdmin={isAdmin}
                    onChange={change}
                    onAdd={() => setAdding({ parent: p.id })}
                    onRename={setRenaming}
                    onDelete={setDeleting}
                    onHosts={setHostsOf}
                    busy={policy.isPending}
                  />
                ))}
                {parents.length === 0 ? (
                  <tr>
                    <td colSpan={2 + SETTINGS.length + (isAdmin ? 1 : 0)} className="muted small">
                      No groups yet. Every host follows the {v.org.name} settings.
                    </td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {adding ? <AddGroup v={v} parent={adding.parent} onClose={() => setAdding(null)} /> : null}
      {renaming ? <Rename v={v} target={renaming} onClose={() => setRenaming(null)} /> : null}
      {hostsOf ? <GroupHosts v={v} g={hostsOf} onClose={() => setHostsOf(null)} /> : null}
      <ConfirmDialog
        open={!!deleting}
        onClose={() => setDeleting(null)}
        title={`Delete ${deleting?.name ?? ''}?`}
        danger
        confirmLabel="Delete group"
        onConfirm={() => deleting && del.mutateAsync(deleting.id)}
      >
        {deleting ? (
          <p>
            Its {formatNumber(deleting.hosts)} hosts move to{' '}
            <strong>{deleting.parent_id ? groupPath(v, deleting.parent_id) : `${v.org.name} (no group)`}</strong> and follow its settings.
          </p>
        ) : null}
      </ConfirmDialog>
      <ConfirmDialog
        open={!!pending}
        onClose={() => setPending(null)}
        title={pending ? `Stop adopting ${pending.def.label} from ${pending.from}?` : ''}
        danger
        confirmLabel={pending ? `Set ${pending.def.label} to ${choiceLabel(pending.def, pending.value)} for ${pending.g.name}` : 'Change'}
        onConfirm={() => pending && policy.mutateAsync({ g: pending.g, def: pending.def, value: pending.value })}
      >
        {pending ? <WeakerWarning v={v} p={pending} /> : null}
      </ConfirmDialog>
    </div>
  )
}

function WeakerWarning({ v, p }: { v: GroupsView; p: PendingWeaker }) {
  const name = p.def.label
  const kids = v.groups.filter((g) => g.parent_id === p.g.id)
  // Child groups that set the value themselves are not affected.
  const kidsOwn = kids.filter((k) => p.def.get(k.policy) !== undefined)
  const followers = kids.filter((k) => p.def.get(k.policy) === undefined)
  const hosts = p.g.hosts + followers.reduce((n, k) => n + k.hosts, 0)
  return (
    <div className="stack" style={{ gap: 8 }}>
      <p style={{ margin: 0 }}>
        {name} is <strong>{choiceLabel(p.def, p.fromValue)}</strong> for <strong>{p.from}</strong>, and <strong>{groupPath(v, p.g.id)}</strong> adopts
        that setting today. Setting it to <strong>{choiceLabel(p.def, p.value)}</strong> here overrides it: {formatNumber(hosts)} host
        {hosts === 1 ? '' : 's'}
        {followers.length ? ` in this group and ${followers.length} of its child groups` : ' in this group'} {p.def.weaker(name)}.
      </p>
      {kidsOwn.length ? (
        <p className="small muted" style={{ margin: 0 }}>
          {kidsOwn.map((k) => k.name).join(', ')} {kidsOwn.length === 1 ? 'sets' : 'set'} {name} itself and {kidsOwn.length === 1 ? 'is' : 'are'} not
          affected.
        </p>
      ) : null}
      <p className="small muted" style={{ margin: 0 }}>
        Other groups are not affected. Set this group back to Inherit to adopt the setting again.
      </p>
    </div>
  )
}

function GroupRows({
  g,
  v,
  kids,
  isAdmin,
  onChange,
  onAdd,
  onRename,
  onDelete,
  onHosts,
  busy,
}: {
  g: HostGroup
  v: GroupsView
  kids: HostGroup[]
  isAdmin: boolean
  onChange: (g: HostGroup, d: SettingDef, choice: string) => void
  onAdd: () => void
  onRename: (g: HostGroup) => void
  onDelete: (g: HostGroup) => void
  onHosts: (g: HostGroup) => void
  busy: boolean
}) {
  const row = (x: HostGroup, child: boolean) => (
    <tr key={x.id}>
      <td style={{ paddingLeft: child ? 40 : 20 }}>
        {child ? <span className="muted">└ </span> : null}
        {x.name}
      </td>
      <td>
        <Link to={`/hosts?group=${x.id}`}>{formatNumber(x.hosts)}</Link>
      </td>
      {SETTINGS.map((d) => {
        const own = d.get(x.policy)
        const inh = inheritedValue(v, x, d.key)
        return (
          <td key={d.key}>
            {isAdmin ? (
              <select
                className="input small"
                value={own ?? 'inherit'}
                disabled={busy}
                aria-label={`${d.label} for ${x.name}`}
                onChange={(e) => onChange(x, d, e.target.value)}
              >
                <option value="inherit">
                  Inherit ({choiceLabel(d, inh.value).toLowerCase()}, from {inh.from})
                </option>
                {d.choices.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </select>
            ) : (
              <span>
                {choiceLabel(d, effectiveValue(x.effective, d.key))}{' '}
                <span className="muted small">{own === undefined ? `from ${inh.from}` : 'set here'}</span>
              </span>
            )}
          </td>
        )
      })}
      {isAdmin ? (
        <td className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
          <button className="btn small ghost" onClick={() => onHosts(x)}>
            Hosts
          </button>
          {!child ? (
            <button className="btn small ghost" onClick={onAdd}>
              Add child
            </button>
          ) : null}
          <button className="btn small ghost" onClick={() => onRename(x)}>
            Rename
          </button>
          <button
            className="btn small ghost danger"
            onClick={() => onDelete(x)}
            disabled={!child && kids.length > 0}
            title={!child && kids.length > 0 ? 'Delete its child groups first' : undefined}
          >
            Delete
          </button>
        </td>
      ) : null}
    </tr>
  )
  return (
    <>
      {row(g, false)}
      {kids.map((k) => row(k, true))}
    </>
  )
}

function AddGroup({ v, parent, onClose }: { v: GroupsView; parent: string; onClose: () => void }) {
  const [name, setName] = useState('')
  const m = useGroupMutation(() => createGroup(name, parent), 'Group added')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    m.mutate(undefined, { onSuccess: onClose })
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={parent ? `Add a child group to ${groupPath(v, parent)}` : `Add a parent group to ${v.org.name}`}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" form="add-group" type="submit" disabled={!name.trim() || m.isPending}>
            Add
          </button>
        </>
      }
    >
      <form id="add-group" onSubmit={submit} className="stack">
        <label className="field">
          <span className="label">Name</span>
          <input className="input" autoFocus value={name} maxLength={80} onChange={(e) => setName(e.target.value)} placeholder={parent ? 'Marketing Dept' : 'DTS Assets'} />
          <span className="help">New groups inherit every setting until you change it.</span>
        </label>
        {m.isError ? <div className="callout danger small">{errorMessage(m.error)}</div> : null}
      </form>
    </Modal>
  )
}

function Rename({ v, target, onClose }: { v: GroupsView; target: HostGroup | 'org'; onClose: () => void }) {
  const [name, setName] = useState(target === 'org' ? v.org.name : target.name)
  const m = useGroupMutation(() => (target === 'org' ? putOrg(name) : updateGroup(target.id, { name })), 'Renamed')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    m.mutate(undefined, { onSuccess: onClose })
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={target === 'org' ? 'Organisation name' : `Rename ${target.name}`}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" form="rename-group" type="submit" disabled={!name.trim() || m.isPending}>
            Save
          </button>
        </>
      }
    >
      <form id="rename-group" onSubmit={submit} className="stack">
        <label className="field">
          <span className="label">Name</span>
          <input className="input" autoFocus value={name} maxLength={80} onChange={(e) => setName(e.target.value)} />
          {target === 'org' ? <span className="help">Shown at the top of the group tree, for the settings that apply everywhere.</span> : null}
        </label>
        {m.isError ? <div className="callout danger small">{errorMessage(m.error)}</div> : null}
      </form>
    </Modal>
  )
}

/** Choose which hosts are in a group. Hosts taken out move to the parent group. */
function GroupHosts({ v, g, onClose }: { v: GroupsView; g: HostGroup; onClose: () => void }) {
  const hosts = useQuery({ queryKey: queryKeys.hosts({}), queryFn: () => api.listHosts({}) })
  const [filter, setFilter] = useState('')
  const [picked, setPicked] = useState<Set<string> | null>(null)
  const list = useMemo(
    () => (hosts.data?.hosts ?? []).filter((h) => h.kind === 'endpoint').sort((a, b) => a.hostname.localeCompare(b.hostname)),
    [hosts.data],
  )
  const current = useMemo(() => new Set(list.filter((h) => h.group_id === g.id).map((h) => h.id)), [list, g.id])
  const sel = picked ?? current
  const shown = list.filter((h) => !filter || h.hostname.toLowerCase().includes(filter.toLowerCase()))
  const added = [...sel].filter((id) => !current.has(id))
  const removed = [...current].filter((id) => !sel.has(id))
  const save = useGroupMutation(async () => {
    let out: GroupsView | undefined
    if (added.length) out = await setHostsGroup(added, g.id)
    if (removed.length) out = await setHostsGroup(removed, g.parent_id)
    return out ?? getGroups()
  }, 'Group members saved')
  const upTo = g.parent_id ? groupPath(v, g.parent_id) : `${v.org.name} (no group)`
  return (
    <Modal
      open
      wide
      onClose={onClose}
      title={`Hosts in ${groupPath(v, g.id)}`}
      footer={
        <>
          <span className="muted small" style={{ marginRight: 'auto' }}>
            {added.length} to add, {removed.length} to take out (they move to {upTo})
          </span>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={(!added.length && !removed.length) || save.isPending} onClick={() => save.mutate(undefined, { onSuccess: onClose })}>
            Save
          </button>
        </>
      }
    >
      {hosts.isPending ? (
        <Loading />
      ) : hosts.isError ? (
        <ErrorState error={hosts.error} />
      ) : (
        <div className="stack" style={{ gap: 10 }}>
          <input className="input" placeholder="Filter by hostname" value={filter} onChange={(e) => setFilter(e.target.value)} />
          <div className="table-wrap" style={{ maxHeight: 420, overflow: 'auto' }}>
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 36 }} />
                  <th>Host</th>
                  <th>Now in</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((h) => (
                  <tr key={h.id}>
                    <td>
                      <input
                        type="checkbox"
                        checked={sel.has(h.id)}
                        aria-label={`${h.hostname} in ${g.name}`}
                        onChange={(e) => {
                          const n = new Set(sel)
                          if (e.target.checked) n.add(h.id)
                          else n.delete(h.id)
                          setPicked(n)
                        }}
                      />
                    </td>
                    <td>{h.hostname}</td>
                    <td className="muted small">{h.group_id ? groupPath(v, h.group_id) : `${v.org.name} (no group)`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {save.isError ? <div className="callout danger small">{errorMessage(save.error)}</div> : null}
        </div>
      )}
    </Modal>
  )
}

/** The host page's group picker. */
export function HostGroupPicker({ hostId, groupId }: { hostId: string; groupId?: string }) {
  const isAdmin = useCan('admin')
  const q = useQuery({ queryKey: groupKeys.all, queryFn: getGroups })
  const qc = useQueryClient()
  const save = useGroupMutation((id: string) => setHostsGroup([hostId], id), 'Group changed')
  if (!q.data) return null
  const v = q.data
  const eff = groupId ? v.groups.find((g) => g.id === groupId)?.effective : undefined
  return (
    <div className="stack" style={{ gap: 8 }}>
      {isAdmin ? (
        <GroupSelect
          v={v}
          value={groupId ?? ''}
          disabled={save.isPending}
          label="Host group"
          onChange={(id) => save.mutate(id, { onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.host(hostId) }) })}
        />
      ) : (
        <span>{groupId ? groupPath(v, groupId) : `${v.org.name} (no group)`}</span>
      )}
      <div className="small muted" style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '2px 12px' }}>
        {SETTINGS.map((d) => (
          <Fragment key={d.key}>
            <span>{d.label}</span>
            <span>
              <span style={{ color: 'var(--text)' }}>{choiceLabel(d, eff ? effectiveValue(eff, d.key) : globalValue(v, d.key))}</span>{' '}
              <span className="xsmall">from {(eff?.[d.key].group_name) ?? v.org.name}</span>
            </span>
          </Fragment>
        ))}
      </div>
      <Link className="small" to="/settings/groups">
        Edit groups
      </Link>
    </div>
  )
}

/** A select of the organisation and its groups. With anyLabel, "" means no filter and
 * "none" means hosts in no group. */
export function GroupSelect({
  v,
  value,
  onChange,
  disabled,
  label,
  anyLabel,
  className = 'input',
}: {
  v: GroupsView
  value: string
  onChange: (id: string) => void
  disabled?: boolean
  label: string
  anyLabel?: string
  className?: string
}) {
  return (
    <select className={className} value={value} disabled={disabled} aria-label={label} onChange={(e) => onChange(e.target.value)}>
      {anyLabel ? <option value="">{anyLabel}</option> : null}
      <option value={anyLabel ? 'none' : ''}>{v.org.name} (no group)</option>
      {v.groups.map((g) => (
        <option key={g.id} value={g.id}>
          {g.parent_id ? '   ' : ''}
          {groupPath(v, g.id)}
        </option>
      ))}
    </select>
  )
}

/** A host's group under its name in lists; nothing when there are no groups. */
export function HostGroupName({ id }: { id?: string }) {
  const q = useQuery({ queryKey: groupKeys.all, queryFn: getGroups, staleTime: 60_000 })
  if (!q.data || q.data.groups.length === 0 || !id) return null
  return <div className="xsmall muted truncate">{groupPath(q.data, id)}</div>
}

/** The group filter for the Hosts and Alerts pages; renders nothing until groups exist. */
export function GroupFilter({ value, onChange }: { value: string; onChange: (id: string) => void }) {
  const q = useQuery({ queryKey: groupKeys.all, queryFn: getGroups, staleTime: 60_000 })
  if (!q.data || q.data.groups.length === 0) return null
  return <GroupSelect v={q.data} value={value} onChange={onChange} label="Group" anyLabel="Any group" className="select" />
}
