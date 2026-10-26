import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState, type FormEvent } from 'react'
import { useNavigate, useParams } from 'react-router'
import { api, errorMessage, queryKeys, ROLES, type EnrollmentToken, type Role, type ServerSettings, type User } from '../api'
import { useCan, useUser } from '../components/Auth'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { CopyButton, KV, LinkTabs, Pager, RelTime, type TabDef } from '../components/Misc'
import { ConfirmDialog, Modal } from '../components/Modal'
import { EmptyState, ErrorState, Loading, QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatBytes, formatNumber, formatSizeSetting, splitList } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { agentUrlOptions, buildInstallCommands } from '../lib/install'
import { ROLE_HELP, ROLE_LABEL } from '../lib/roles'
import { formatDateTime, formatTimestamp } from '../lib/time'
import { AgentConfigEditor } from './AgentConfigEditor'
import { AgentLifecycleTab } from './AgentLifecycle'
import { AIAnalystTab } from './AISettings'

const ALL_TABS: (TabDef & { admin?: boolean })[] = [
  { id: 'tokens', label: 'Enrollment', icon: 'key', admin: true },
  { id: 'users', label: 'Users', icon: 'user', admin: true },
  { id: 'agent-config', label: 'Agent config', icon: 'settings' },
  { id: 'agents', label: 'Agent updates', icon: 'refresh', admin: true },
  { id: 'integrations', label: 'Integrations', icon: 'network' },
  { id: 'ai', label: 'AI analyst', icon: 'sparkle', admin: true },
  { id: 'audit', label: 'Audit log', icon: 'clock', admin: true },
  { id: 'account', label: 'My account', icon: 'user' },
]

export function SettingsPage() {
  useDocumentTitle('Settings')
  const isAdmin = useCan('admin')
  const { tab: tabParam } = useParams()
  const tabs = ALL_TABS.filter((t) => isAdmin || !t.admin)
  const tab = tabs.find((t) => t.id === tabParam)?.id ?? tabs[0].id
  return (
    <>
      <PageHeader title="Settings" subtitle={isAdmin ? 'Server, enrollment, users and agent configuration' : 'Some settings need the admin role'} />
      <LinkTabs tabs={tabs} active={tab} href={(id) => `/settings/${id}`} />
      {tab === 'tokens' ? <TokensTab /> : null}
      {tab === 'users' ? <UsersTab /> : null}
      {tab === 'agent-config' ? <AgentConfigEditor /> : null}
      {tab === 'agents' ? <AgentLifecycleTab /> : null}
      {tab === 'integrations' ? <IntegrationsTab /> : null}
      {tab === 'ai' ? <AIAnalystTab /> : null}
      {tab === 'audit' ? <AuditTab /> : null}
      {tab === 'account' ? <AccountTab /> : null}
    </>
  )
}

// --- enrollment tokens -------------------------------------------------------------------

function InstallCommands({ settings, token }: { settings: ServerSettings; token: string }) {
  const options = agentUrlOptions(settings)
  const [url, setUrl] = useState(options[0] ?? '')
  const cmds = buildInstallCommands(url, token, settings.ca_pin, settings.agent_release.signed ? settings.update_key : undefined)
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="field">
        <label htmlFor="agent-url">Agent API address</label>
        <select id="agent-url" className="select" value={url} onChange={(e) => setUrl(e.target.value)}>
          {options.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <span className="help">Must be reachable from the host and covered by the server certificate (HOMEXDR_SERVER_NAMES).</span>
      </div>
      <div className="field">
        <span className="label">Linux (as root)</span>
        <div className="copy-field">
          <pre className="codeblock wrap">{cmds.linux}</pre>
          <CopyButton text={cmds.linux} small />
        </div>
      </div>
      <div className="field">
        <span className="label">Windows (elevated PowerShell, from the folder with homexdr-agent.exe)</span>
        <div className="copy-field">
          <pre className="codeblock wrap">{cmds.windows}</pre>
          <CopyButton text={cmds.windows} small />
        </div>
      </div>
      <p className="muted xsmall" style={{ margin: 0 }}>
        The <span className="mono">--ca-pin</span> makes the agent verify it is talking to this server before it sends the token. The Linux
        script is fetched with <span className="mono">-k</span> because the CA is not installed yet; the agent then pins it.
        {settings.agent_release.signed && settings.update_key ? (
          <>
            {' '}
            <span className="mono">--update-key</span> lets the agent install new versions signed with the release key; leave it out to
            update by hand.
          </>
        ) : null}
      </p>
    </div>
  )
}

function TokensTab() {
  const qc = useQueryClient()
  const toast = useToast()
  const tokensQ = useQuery({ queryKey: queryKeys.tokens, queryFn: api.listTokens })
  const settingsQ = useQuery({ queryKey: queryKeys.serverSettings, queryFn: api.serverSettings, staleTime: 5 * 60_000 })
  const [name, setName] = useState('')
  const [expires, setExpires] = useState('168')
  const [maxUses, setMaxUses] = useState('')
  const [labels, setLabels] = useState('')
  const [created, setCreated] = useState<EnrollmentToken | null>(null)
  const [deleting, setDeleting] = useState<EnrollmentToken | null>(null)

  const create = useMutation({
    mutationFn: () =>
      api.createToken({
        name: name.trim(),
        expires_hours: expires ? Number(expires) : undefined,
        max_uses: maxUses ? Number(maxUses) : undefined,
        labels: splitList(labels).map((l) => l.toLowerCase()),
      }),
    onSuccess: (t) => {
      setCreated(t)
      setName('')
      setMaxUses('')
      setLabels('')
      qc.invalidateQueries({ queryKey: queryKeys.tokens })
    },
    onError: (e) => toast.error(e),
  })

  const maxValid = maxUses === '' || (/^\d+$/.test(maxUses) && Number(maxUses) > 0)

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Create an enrollment token</h2>
          <span className="hint">Agents use a token once to enroll and receive their own certificate</span>
        </div>
        <form
          className="panel-body"
          onSubmit={(e: FormEvent) => {
            e.preventDefault()
            if (name.trim() && maxValid) create.mutate()
          }}
        >
          <div className="form-grid">
            <div className="field">
              <label htmlFor="tok-name">Name</label>
              <input id="tok-name" className="input" placeholder="e.g. homelab-servers" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="tok-exp">Expires</label>
              <select id="tok-exp" className="select" value={expires} onChange={(e) => setExpires(e.target.value)}>
                <option value="1">in 1 hour</option>
                <option value="24">in 1 day</option>
                <option value="168">in 7 days</option>
                <option value="720">in 30 days</option>
                <option value="">never</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="tok-max">Max uses</label>
              <input id="tok-max" className={maxValid ? 'input' : 'input invalid'} inputMode="numeric" placeholder="unlimited" value={maxUses} onChange={(e) => setMaxUses(e.target.value.trim())} />
            </div>
            <div className="field">
              <label htmlFor="tok-labels">Labels for enrolled hosts</label>
              <input id="tok-labels" className="input" placeholder="server, dmz" value={labels} onChange={(e) => setLabels(e.target.value)} />
            </div>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button type="submit" className="btn primary" disabled={!name.trim() || !maxValid || create.isPending}>
              {create.isPending ? <Spinner small /> : <Icon name="plus" size={14} />} Create token
            </button>
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Tokens</h2>
        </div>
        <QueryView query={tokensQ} isEmpty={(d) => d.tokens.length === 0} empty={<EmptyState title="No enrollment tokens">Create one above to enroll your first host.</EmptyState>}>
          {(d) => (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Labels</th>
                    <th className="right">Uses</th>
                    <th>Expires</th>
                    <th>Created</th>
                    <th aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {d.tokens.map((t) => {
                    const expired = t.expires_at ? Date.parse(t.expires_at) < Date.now() : false
                    const used = t.max_uses !== undefined && t.uses >= t.max_uses
                    return (
                      <tr key={t.id}>
                        <td>
                          {t.name}
                          {expired || used ? <span className="badge" style={{ marginLeft: 6 }}>{expired ? 'expired' : 'used up'}</span> : null}
                        </td>
                        <td>{t.labels.length ? t.labels.map((l) => <span key={l} className="tag" style={{ marginRight: 4 }}>{l}</span>) : <span className="empty-cell">—</span>}</td>
                        <td className="right num">
                          {t.uses}
                          {t.max_uses !== undefined ? ` / ${t.max_uses}` : ''}
                        </td>
                        <td>{t.expires_at ? <RelTime iso={t.expires_at} /> : <span className="muted">never</span>}</td>
                        <td>
                          <RelTime iso={t.created_at} /> <span className="muted small">by {t.created_by}</span>
                        </td>
                        <td className="right">
                          <button type="button" className="btn ghost sm" onClick={() => setDeleting(t)} aria-label={`Delete token ${t.name}`}>
                            <Icon name="trash" size={12} /> Delete
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>

      <Modal
        open={created !== null}
        onClose={() => setCreated(null)}
        title={`Token “${created?.name ?? ''}” created`}
        wide
        footer={
          <button type="button" className="btn primary" onClick={() => setCreated(null)}>
            I have copied it
          </button>
        }
      >
        {created?.token ? (
          <div className="stack" style={{ gap: 12 }}>
            <div className="callout warn">
              <Icon name="warning" size={14} />
              <span>This is the only time the token is shown. Copy it now; it cannot be retrieved later.</span>
            </div>
            <div className="copy-field">
              <pre className="codeblock wrap">{created.token}</pre>
              <CopyButton text={created.token} small />
            </div>
            {settingsQ.data ? (
              <InstallCommands settings={settingsQ.data} token={created.token} />
            ) : settingsQ.isError ? (
              <ErrorState error={settingsQ.error} compact title="Could not load server settings for the install commands" />
            ) : (
              <Loading compact />
            )}
          </div>
        ) : (
          <p>The server did not return a token value.</p>
        )}
      </Modal>

      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title={`Delete token “${deleting?.name ?? ''}”?`}
        danger
        confirmLabel="Delete token"
        onConfirm={async () => {
          if (!deleting) return
          await api.deleteToken(deleting.id)
          qc.invalidateQueries({ queryKey: queryKeys.tokens })
          toast.success('Token deleted')
        }}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Stop new agents from enrolling with this token.</li>
          <li>Leave hosts that already enrolled with it working; they have their own certificates.</li>
        </ul>
      </ConfirmDialog>
    </div>
  )
}

// --- users --------------------------------------------------------------------------------

function UsersTab() {
  const qc = useQueryClient()
  const toast = useToast()
  const me = useUser()
  const q = useQuery({ queryKey: queryKeys.users, queryFn: api.listUsers })
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [deleting, setDeleting] = useState<User | null>(null)
  const [roleChange, setRoleChange] = useState<{ user: User; role: Role } | null>(null)

  const create = useMutation({
    mutationFn: () => api.createUser({ username: username.trim(), password, role }),
    onSuccess: (u) => {
      toast.success(`User ${u.username} created`)
      setUsername('')
      setPassword('')
      qc.invalidateQueries({ queryKey: queryKeys.users })
    },
    onError: (e) => toast.error(e),
  })

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel-header">
          <h2>Add a user</h2>
        </div>
        <form
          className="panel-body"
          onSubmit={(e) => {
            e.preventDefault()
            if (username.trim() && password.length >= 10) create.mutate()
          }}
        >
          <div className="form-grid">
            <div className="field">
              <label htmlFor="u-name">Username</label>
              <input id="u-name" className="input" autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="u-pass">Initial password</label>
              <input id="u-pass" className={password && password.length < 10 ? 'input invalid' : 'input'} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <span className={password && password.length < 10 ? 'error' : 'help'}>At least 10 characters.</span>
            </div>
            <div className="field">
              <label htmlFor="u-role">Role</label>
              <select id="u-role" className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {ROLE_LABEL[r]}
                  </option>
                ))}
              </select>
              <span className="help">{ROLE_HELP[role]}</span>
            </div>
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button type="submit" className="btn primary" disabled={!username.trim() || password.length < 10 || create.isPending}>
              {create.isPending ? <Spinner small /> : <Icon name="plus" size={14} />} Add user
            </button>
          </div>
        </form>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Users</h2>
        </div>
        <QueryView query={q} isEmpty={(d) => d.users.length === 0}>
          {(d) => (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Last login</th>
                    <th aria-label="Actions" />
                  </tr>
                </thead>
                <tbody>
                  {d.users.map((u) => {
                    const self = u.id === me.id
                    return (
                      <tr key={u.id}>
                        <td>
                          {u.username} {self ? <span className="tag">you</span> : null}
                        </td>
                        <td>
                          <select
                            className="select"
                            value={u.role}
                            disabled={self}
                            title={self ? 'You cannot change your own role' : undefined}
                            onChange={(e) => setRoleChange({ user: u, role: e.target.value as Role })}
                            aria-label={`Role of ${u.username}`}
                          >
                            {ROLES.map((r) => (
                              <option key={r} value={r}>
                                {ROLE_LABEL[r]}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td>{formatDateTime(u.created_at)}</td>
                        <td>{u.last_login ? <RelTime iso={u.last_login} /> : <span className="muted">never</span>}</td>
                        <td className="right">
                          <button type="button" className="btn ghost sm" disabled={self} onClick={() => setDeleting(u)} aria-label={`Delete ${u.username}`}>
                            <Icon name="trash" size={12} /> Delete
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>
      <ConfirmDialog
        open={roleChange !== null}
        onClose={() => setRoleChange(null)}
        title={`Change ${roleChange?.user.username}’s role?`}
        confirmLabel="Change role"
        onConfirm={async () => {
          if (!roleChange) return
          await api.patchUser(roleChange.user.id, { role: roleChange.role })
          qc.invalidateQueries({ queryKey: queryKeys.users })
          toast.success('Role changed')
        }}
      >
        {roleChange ? (
          <p>
            {roleChange.user.username} changes from <strong>{ROLE_LABEL[roleChange.user.role]}</strong> to <strong>{ROLE_LABEL[roleChange.role]}</strong>:{' '}
            {ROLE_HELP[roleChange.role]}
          </p>
        ) : null}
      </ConfirmDialog>
      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title={`Delete user ${deleting?.username ?? ''}?`}
        danger
        confirmLabel="Delete user"
        onConfirm={async () => {
          if (!deleting) return
          await api.deleteUser(deleting.id)
          qc.invalidateQueries({ queryKey: queryKeys.users })
          toast.success('User deleted')
        }}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Remove the account and end its sessions.</li>
          <li>Keep their notes and audit entries, which still show their username.</li>
        </ul>
      </ConfirmDialog>
    </div>
  )
}

// --- integrations ----------------------------------------------------------------------------

function IntegrationsTab() {
  const q = useQuery({ queryKey: queryKeys.integrations, queryFn: api.integrations, refetchInterval: 15_000 })
  const settingsQ = useQuery({ queryKey: queryKeys.serverSettings, queryFn: api.serverSettings })
  return (
    <div className="grid grid-sidebar" style={{ alignItems: 'start' }}>
      <section className="panel">
        <div className="panel-header">
          <h2>Syslog intake</h2>
          {q.data ? (
            <span className="row small">
              <span className={`dot ${q.data.syslog.listening ? 'online' : 'revoked'}`} aria-hidden="true" />
              {q.data.syslog.listening ? `Listening on ${q.data.syslog.addr}` : 'Not listening'}
            </span>
          ) : null}
        </div>
        <QueryView query={q}>
          {(d) => (
            <>
              <div className="stats" style={{ padding: 12 }}>
                <div className="stat">
                  <span className="label">Received</span>
                  <span className="value">{formatNumber(d.syslog.received)}</span>
                </div>
                <div className="stat">
                  <span className="label">Parsed</span>
                  <span className="value">{formatNumber(d.syslog.parsed)}</span>
                </div>
                <div className="stat">
                  <span className="label">Failed to parse</span>
                  <span className="value">{formatNumber(d.syslog.failed)}</span>
                  <span className="sub">{d.syslog.received ? `${((d.syslog.failed / d.syslog.received) * 100).toFixed(2)}%` : ''}</span>
                </div>
              </div>
              {d.syslog.sources.length === 0 ? (
                <EmptyState title="No syslog sources yet" compact>
                  Point OPNsense (System → Settings → Logging → Remote) at {settingsQ.data?.server_names[0] ?? 'this server'} port 514.
                </EmptyState>
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Source</th>
                        <th>IP</th>
                        <th>Decoder</th>
                        <th className="right">Messages</th>
                        <th>Last message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {d.syslog.sources.map((s) => (
                        <tr key={`${s.ip}-${s.name}-${s.kind}`}>
                          <td>{s.name}</td>
                          <td className="mono">{s.ip}</td>
                          <td>
                            <span className="tag">{s.kind}</span>
                          </td>
                          <td className="right num">{formatNumber(s.count)}</td>
                          <td>
                            <RelTime iso={s.last_seen} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </QueryView>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Server</h2>
        </div>
        <div className="panel-body">
          <QueryView query={settingsQ} compact>
            {(s) => (
              <KV
                items={[
                  ['Version', s.version],
                  ['Agent API', <span key="a" className="mono small">{s.agent_url}</span>],
                  ['Server names', s.server_names.join(', ')],
                  ['CA pin', <span key="p" className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>{s.ca_pin}</span>],
                  ['Event store', s.event_store === 'sqlite' ? 'SQLite (lite mode)' : 'ClickHouse'],
                  ['Retention', retentionText(s)],
                  ['Agent updates', agentUpdatesText(s)],
                  ['Syslog listener', <span key="s" className="mono">{s.syslog_addr}</span>],
                ]}
              />
            )}
          </QueryView>
        </div>
      </section>
    </div>
  )
}

function retentionText(s: ServerSettings): string {
  const age = s.retention_days > 0 ? `${s.retention_days} days` : 'No time limit'
  const cap = s.retention_max_bytes > 0 ? `capped at ${formatSizeSetting(s.retention_max_bytes)}` : 'no size cap'
  const used = s.event_store_bytes != null ? ` (${formatBytes(s.event_store_bytes)} used)` : ''
  return `${age}, ${cap}${used}`
}

function agentUpdatesText(s: ServerSettings): string {
  const r = s.agent_release
  if (r.signed) return `Offering ${r.version ?? 'this release'} (signed) to agents with auto-update`
  return r.problem ? `Off: ${r.problem}` : 'Off'
}

// --- audit ------------------------------------------------------------------------------------

function AuditTab() {
  const [offset, setOffset] = useState(0)
  const limit = 50
  const q = useQuery({ queryKey: queryKeys.audit(offset), queryFn: () => api.audit(limit, offset), placeholderData: keepPreviousData })
  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Audit log</h2>
        <span className="hint">Response actions, rule changes, logins and admin changes</span>
      </div>
      <QueryView query={q} isEmpty={(d) => d.entries.length === 0} empty={<EmptyState title="No audit entries" />}>
        {(d) => (
          <>
            <div className="table-wrap">
              <table className="table fixed compact" style={{ minWidth: 820 }}>
                <colgroup>
                  <col style={{ width: 180 }} />
                  <col style={{ width: 110 }} />
                  <col style={{ width: 170 }} />
                  <col style={{ width: '24%' }} />
                  <col />
                </colgroup>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>User</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {d.entries.map((e) => {
                    const details = e.details === null || e.details === undefined ? '' : typeof e.details === 'string' ? e.details : JSON.stringify(e.details)
                    return (
                      <tr key={e.id}>
                        <td className="mono small">{formatTimestamp(e.at)}</td>
                        <td className="truncate">{e.user}</td>
                        <td className="truncate mono small">{e.action}</td>
                        <td className="truncate" title={e.target}>
                          {e.target}
                        </td>
                        <td className="truncate cmd" title={details}>
                          {details || <span className="empty-cell">—</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
            <Pager offset={offset} limit={limit} total={d.total} shown={d.entries.length} onChange={setOffset} />
          </>
        )}
      </QueryView>
    </section>
  )
}

// --- account ----------------------------------------------------------------------------------

function AccountTab() {
  const me = useUser()
  const toast = useToast()
  const navigate = useNavigate()
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const change = useMutation({
    mutationFn: () => api.patchUser(me.id, { password: pw }),
    onSuccess: () => {
      toast.success('Password changed')
      setPw('')
      setConfirm('')
    },
  })
  const valid = pw.length >= 10 && pw === confirm
  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <section className="panel">
        <div className="panel-header">
          <h2>Change password</h2>
        </div>
        <form
          className="panel-body stack"
          style={{ gap: 10, maxWidth: 380 }}
          onSubmit={(e) => {
            e.preventDefault()
            if (valid) change.mutate()
          }}
        >
          <input type="text" autoComplete="username" value={me.username} readOnly hidden />
          <div className="field">
            <label htmlFor="pw-new">New password</label>
            <input id="pw-new" className={pw && pw.length < 10 ? 'input invalid' : 'input'} type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
            <span className={pw && pw.length < 10 ? 'error' : 'help'}>At least 10 characters.</span>
          </div>
          <div className="field">
            <label htmlFor="pw-confirm">Confirm new password</label>
            <input id="pw-confirm" className={confirm && confirm !== pw ? 'input invalid' : 'input'} type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            {confirm && confirm !== pw ? <span className="error">Passwords do not match.</span> : null}
          </div>
          {change.isError ? (
            <div className="callout danger" role="alert">
              <Icon name="warning" size={14} /> <span>{errorMessage(change.error)}</span>
            </div>
          ) : null}
          <div>
            <button type="submit" className="btn primary" disabled={!valid || change.isPending}>
              {change.isPending ? <Spinner small /> : null} Change password
            </button>
          </div>
        </form>
      </section>
      <section className="panel">
        <div className="panel-header">
          <h2>Account</h2>
        </div>
        <div className="panel-body">
          <KV
            items={[
              ['Username', me.username],
              ['Role', `${ROLE_LABEL[me.role]} — ${ROLE_HELP[me.role]}`],
              ['Created', formatDateTime(me.created_at)],
              ['Last login', me.last_login ? formatDateTime(me.last_login) : undefined],
            ]}
          />
          <button type="button" className="btn" style={{ marginTop: 12 }} onClick={() => navigate('/')}>
            Back to dashboard
          </button>
        </div>
      </section>
    </div>
  )
}
