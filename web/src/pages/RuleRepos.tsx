// Rules → Repositories: import Sigma rule repositories and keep them updated.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { api, queryKeys, SEVERITIES, type RuleRepo, type RuleRepoFile, type RuleRepoSettings, type Severity, type SigmaStatus } from '../api'
import { errorMessage } from '../api/client'
import { useCan } from '../components/Auth'
import { ChoiceCards } from '../components/ChoiceCards'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { KV, RelTime, Toggle } from '../components/Misc'
import { ConfirmDialog, Modal } from '../components/Modal'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber, plural } from '../lib/format'
import { useDocumentTitle, useUrlState } from '../lib/hooks'
import {
  buildTree,
  DEFAULT_REPO_SETTINGS,
  folderCounts,
  folderState,
  INTERVAL_CHOICES,
  intervalLabel,
  isArchiveUrl,
  parseFolders,
  pathsFromSelection,
  REPO_PRESETS,
  repoRulesSummary,
  repoState,
  selectionFromPaths,
  selectionSummary,
  shortRepoVersion,
  SIGMA_STATUSES,
  toggleFolder,
  UPDATE_CHOICES,
  type FolderCounts,
  type FolderNode,
} from '../lib/ruleRepos'
import { SEVERITY_LABEL } from '../lib/severity'

export function RuleReposPage() {
  useDocumentTitle('Rule repositories')
  const isAdmin = useCan('admin')
  const [sp, patch] = useUrlState()
  const q = useQuery({
    queryKey: queryKeys.ruleRepos,
    queryFn: api.listRuleRepos,
    // Poll while a download runs; it reports back through the repository's state.
    refetchInterval: (query) => (query.state.data?.some((r) => r.syncing) ? 1500 : false),
  })
  const [editing, setEditing] = useState<RuleRepo | null>(null)
  // A repository added without folders: choose them from the tree once it is downloaded.
  const [pickFolders, setPickFolders] = useState<string | null>(null)
  useSyncResults(q.data, (r) => {
    if (r.id !== pickFolders) return
    setPickFolders(null)
    if (r.version && !r.error) setEditing(r)
  })
  const [removing, setRemoving] = useState<RuleRepo | null>(null)
  const adding = sp.get('add') === '1'
  const qc = useQueryClient()
  const toast = useToast()

  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/rules">Rules</Link>
        <Icon name="chevronRight" size={10} />
        <span>Repositories</span>
      </div>
      <PageHeader
        title="Rule repositories"
        subtitle="Sigma rules downloaded from git repositories or release archives, checked for updates on a schedule"
        actions={
          isAdmin ? (
            <button type="button" className="btn primary" onClick={() => patch({ add: '1' })}>
              <Icon name="plus" size={14} /> Add repository
            </button>
          ) : null
        }
      />
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.length === 0 ? (
        <section className="panel">
          <EmptyState
            title="No rule repositories yet"
            action={
              isAdmin ? (
                <button type="button" className="btn primary" onClick={() => patch({ add: '1' })}>
                  <Icon name="download" size={14} /> Import rules
                </button>
              ) : undefined
            }
          >
            Import a collection such as SigmaHQ’s community rules. HomeXDR downloads it, loads the rules it can run, and checks for new
            versions on the schedule you pick.
          </EmptyState>
        </section>
      ) : (
        <div className="stack">
          {q.data.map((r) => (
            <RepoCard key={r.id} repo={r} isAdmin={isAdmin} onEdit={() => setEditing(r)} onRemove={() => setRemoving(r)} />
          ))}
        </div>
      )}
      {adding ? <RepoFormDialog onClose={() => patch({ add: '' })} onAdded={(r) => (r.paths.length === 0 ? setPickFolders(r.id) : undefined)} /> : null}
      {editing ? <RepoFormDialog repo={editing} onClose={() => setEditing(null)} /> : null}
      <ConfirmDialog
        open={!!removing}
        onClose={() => setRemoving(null)}
        title={`Remove “${removing?.name}”?`}
        danger
        confirmLabel="Remove repository"
        onConfirm={async () => {
          if (!removing) return
          await api.deleteRuleRepo(removing.id)
          qc.invalidateQueries({ queryKey: queryKeys.ruleRepos })
          qc.invalidateQueries({ queryKey: queryKeys.rules() })
          toast.success(`${removing.name} removed`)
        }}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Stop loading its {formatNumber(removing?.rules ?? 0)} rules and delete the downloaded files.</li>
          <li>Keep existing alerts from those rules.</li>
          <li>Remember rules you enabled or disabled by hand, in case you add the repository again.</li>
        </ul>
      </ConfirmDialog>
    </>
  )
}

/** Reports the outcome of downloads when they finish, and refreshes the rule list. */
function useSyncResults(repos: RuleRepo[] | undefined, onFinished?: (r: RuleRepo) => void) {
  const finished = useRef(onFinished)
  finished.current = onFinished
  const prev = useRef(new Map<string, RuleRepo>())
  const qc = useQueryClient()
  const toast = useToast()
  useEffect(() => {
    if (!repos) return
    for (const r of repos) {
      const before = prev.current.get(r.id)
      if (before?.syncing && !r.syncing) {
        qc.invalidateQueries({ queryKey: queryKeys.rules() })
        if (r.error) toast.error(`${r.name}: ${r.error}`)
        else if (r.version !== before.version)
          toast.success(`${r.name}: installed ${shortRepoVersion(r.version)}, ${plural(r.rules, 'rule')} loaded (${r.added} new, ${r.removed} removed)`)
        else toast.success(`${r.name} is up to date`)
        qc.invalidateQueries({ queryKey: queryKeys.ruleRepoFiles(r.id) })
        finished.current?.(r)
      }
    }
    prev.current = new Map(repos.map((r) => [r.id, r]))
  }, [repos, qc, toast])
}

function RepoCard({ repo: r, isAdmin, onEdit, onRemove }: { repo: RuleRepo; isAdmin: boolean; onEdit: () => void; onRemove: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const state = repoState(r)
  const setRepo = (next: RuleRepo) =>
    qc.setQueryData(queryKeys.ruleRepos, (old: RuleRepo[] | undefined) => old?.map((x) => (x.id === next.id ? next : x)))
  const check = useMutation({
    mutationFn: () => api.checkRuleRepo(r.id),
    onSuccess: (next) => {
      setRepo(next)
      if (next.error) toast.error(`${next.name}: ${next.error}`)
      else if (next.update_available) toast.success(`${next.name}: version ${shortRepoVersion(next.latest_version)} is available`)
      else toast.success(`${next.name} is up to date`)
    },
    onError: (e) => toast.error(e),
  })
  const update = useMutation({
    mutationFn: () => api.updateRuleRepo(r.id),
    onSuccess: setRepo,
    onError: (e) => toast.error(e),
  })
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.patchRuleRepo(r.id, { enabled }),
    onSuccess: (next) => {
      setRepo(next)
      qc.invalidateQueries({ queryKey: queryKeys.rules() })
      toast.success(`${next.name} ${next.enabled ? 'enabled' : 'disabled'}`)
    },
    onError: (e) => toast.error(e),
  })
  const busy = r.syncing || check.isPending || update.isPending
  const [showSkipped, setShowSkipped] = useState(false)
  const [bulk, setBulk] = useState<boolean | null>(null)

  return (
    <section className="panel">
      <div className="panel-header">
        <h2 className="row grow" style={{ gap: 8, minWidth: 0 }}>
          <span className="truncate-inline">{r.name}</span>
          <span className="badge">{r.auto_update ? 'Automatic updates' : 'Manual updates'}</span>
          {state === 'update' ? <span className="badge sev medium">Update available</span> : null}
        </h2>
        <span className="row" style={{ gap: 6 }} title={isAdmin ? undefined : 'Only admins can change rule repositories'}>
          <Toggle checked={r.enabled} disabled={!isAdmin || toggle.isPending || r.syncing} onChange={(v) => toggle.mutate(v)} label={r.enabled ? `Disable ${r.name}` : `Enable ${r.name}`} />
          {isAdmin ? (
            <>
              <button type="button" className="btn sm" disabled={busy || !r.enabled} onClick={() => check.mutate()} title="Look for a new version without installing it">
                {check.isPending ? <Spinner small /> : <Icon name="refresh" size={12} />} Check
              </button>
              <button
                type="button"
                className={state === 'update' || state === 'never' ? 'btn sm primary' : 'btn sm'}
                disabled={busy || !r.enabled}
                onClick={() => update.mutate()}
                title="Download and install the newest version now"
              >
                <Icon name="download" size={12} /> Update
              </button>
              <button type="button" className="btn sm" disabled={r.syncing} onClick={onEdit}>
                <Icon name="edit" size={12} /> Edit
              </button>
              <button type="button" className="btn sm ghost icon" disabled={r.syncing} onClick={onRemove} aria-label={`Remove ${r.name}`} title="Remove">
                <Icon name="trash" size={12} />
              </button>
            </>
          ) : null}
        </span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <RepoStatus repo={r} />
        {showSkipped ? <SkippedDialog repo={r} onClose={() => setShowSkipped(false)} /> : null}
        <ConfirmDialog
          open={bulk !== null}
          onClose={() => setBulk(null)}
          title={`${bulk ? 'Enable' : 'Disable'} every rule from ${r.name}?`}
          confirmLabel={bulk ? `Enable ${plural(r.rules - r.rules_enabled, 'rule')}` : `Disable ${plural(r.rules_enabled, 'rule')}`}
          danger={bulk === false}
          onConfirm={async () => {
            const res = await api.setRuleRepoRulesEnabled(r.id, !!bulk)
            qc.invalidateQueries({ queryKey: queryKeys.ruleRepos })
            qc.invalidateQueries({ queryKey: queryKeys.rules() })
            toast.success(`${bulk ? 'Enabled' : 'Disabled'} ${plural(res.changed, 'rule')} from ${r.name}`)
          }}
        >
          <ul className="effect-list">
            <li>
              {bulk ? 'Every loaded rule from this repository starts checking new events now.' : 'No rule from this repository checks new events until you enable it again.'}
            </li>
            <li>This replaces any rule you enabled or disabled by hand; the choice is kept through updates.</li>
            <li>Rules that appear in later updates still start {r.enable_rules ? 'enabled' : 'disabled'}, as set for the repository.</li>
          </ul>
        </ConfirmDialog>
        <KV
          items={[
            [
              'Source',
              <span key="s" className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                <a href={r.url} target="_blank" rel="noreferrer noopener" className="mono small" style={{ overflowWrap: 'anywhere' }}>
                  {r.url}
                </a>
                {r.kind === 'git' ? <span className="muted small">· {r.ref ? r.ref : 'default branch'}</span> : <span className="muted small">· archive</span>}
              </span>,
            ],
            ['Folders', r.paths.length ? <span className="mono small">{r.paths.join(', ')}</span> : 'Whole repository'],
            [
              'Filters',
              [
                r.min_level ? `${SEVERITY_LABEL[r.min_level]} and above` : 'All levels',
                r.statuses.length ? r.statuses.join(', ') : 'all statuses but deprecated and unsupported',
                r.enable_rules ? 'new rules start enabled' : 'new rules start disabled',
              ].join(' · '),
            ],
            [
              'Installed',
              r.version ? (
                <span key="v" className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                  {r.browse_url ? (
                    <a href={r.browse_url} target="_blank" rel="noreferrer noopener" className="mono">
                      {shortRepoVersion(r.version)}
                    </a>
                  ) : (
                    <span className="mono">{shortRepoVersion(r.version)}</span>
                  )}
                  <RelTime iso={r.installed_at} />
                  {r.added || r.removed ? (
                    <span className="muted small">
                      · last update {r.added} new, {r.removed} removed
                    </span>
                  ) : null}
                </span>
              ) : undefined,
            ],
            [
              'Updates',
              <span key="u">
                {r.auto_update ? 'Installed automatically' : 'Reported, installed by an admin'}, {intervalLabel(r.interval_hours).toLowerCase()}
                {r.enabled && r.next_check_at ? (
                  <span className="muted small">
                    {' '}
                    · next check <RelTime iso={r.next_check_at} />
                  </span>
                ) : null}
              </span>,
            ],
            [
              'Rules',
              r.version ? (
                <span key="r" className="stack" style={{ gap: 4 }}>
                  <span>{repoRulesSummary(r, formatNumber).join(' · ')}</span>
                  <span className="row small" style={{ gap: 12, flexWrap: 'wrap' }}>
                    <Link to={`/rules?source=repo&repo=${encodeURIComponent(r.id)}`}>View rules</Link>
                    {r.duplicates || r.load_errors ? (
                      <button type="button" className="link-button" onClick={() => setShowSkipped(true)}>
                        Why {plural(r.duplicates + r.load_errors, 'rule is', 'rules are')} not loaded
                      </button>
                    ) : null}
                    {isAdmin && r.rules ? (
                      <>
                        <button type="button" className="link-button" disabled={r.rules_enabled === r.rules} onClick={() => setBulk(true)}>
                          Enable all
                        </button>
                        <button type="button" className="link-button" disabled={r.rules_enabled === 0} onClick={() => setBulk(false)}>
                          Disable all
                        </button>
                      </>
                    ) : null}
                  </span>
                </span>
              ) : undefined,
            ],
          ]}
        />
      </div>
    </section>
  )
}

function RepoStatus({ repo: r }: { repo: RuleRepo }) {
  switch (repoState(r)) {
    case 'syncing':
      return (
        <div className="callout info" role="status">
          <Spinner small />
          <span>{r.version ? 'Checking for a new version and installing it…' : 'Downloading and loading rules…'}</span>
        </div>
      )
    case 'disabled':
      return <span className="muted small">Disabled: its rules are not loaded and it is not checked for updates.</span>
    case 'error':
      return (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span style={{ overflowWrap: 'anywhere' }}>
            The last {r.version ? 'check' : 'download'} failed <RelTime iso={r.checked_at} />: {r.error}
            {r.version ? ' The installed rules are still loaded.' : ''} It is retried <RelTime iso={r.next_check_at} />.
          </span>
        </div>
      )
    case 'never':
      return <span className="muted small">Not downloaded yet.</span>
    case 'update':
      return (
        <div className="callout warn">
          <Icon name="info" size={14} />
          <span>
            Version <span className="mono">{shortRepoVersion(r.latest_version)}</span> is available (installed{' '}
            <span className="mono">{shortRepoVersion(r.version)}</span>). Click Update to install it.
          </span>
        </div>
      )
    default:
      return (
        <span className="small">
          <span className="ok-text">Up to date</span>
          <span className="muted">
            {' '}
            · checked <RelTime iso={r.checked_at} />
          </span>
        </span>
      )
  }
}

/** Add (no repo) or edit a repository. */
function RepoFormDialog({ repo, onClose, onAdded }: { repo?: RuleRepo; onClose: () => void; onAdded?: (r: RuleRepo) => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [preset, setPreset] = useState(repo ? 'custom' : REPO_PRESETS[0].id)
  const [form, setForm] = useState<RuleRepoSettings>(() => (repo ? pickSettings(repo) : { ...DEFAULT_REPO_SETTINGS, ...REPO_PRESETS[0].settings }))
  const [folderText, setFolderText] = useState(form.paths.join('\n'))
  // Once downloaded, folders are chosen from a tree of the download with rule counts.
  const files = useQuery({ queryKey: queryKeys.ruleRepoFiles(repo?.id ?? ''), queryFn: () => api.ruleRepoFiles(repo!.id), enabled: !!repo?.version })
  const tree = files.data && files.data.files.length > 0 ? files.data.files : null
  const [sel, setSel] = useState(() => selectionFromPaths(form.paths))
  const set = (p: Partial<RuleRepoSettings>) => setForm((f) => ({ ...f, ...p }))
  const archive = isArchiveUrl(form.url)

  const choosePreset = (id: string) => {
    const p = REPO_PRESETS.find((x) => x.id === id)
    if (!p) return
    setPreset(id)
    setForm((f) => ({ ...f, ...p.settings }))
    setFolderText((p.settings.paths ?? []).join('\n'))
  }

  const save = useMutation({
    mutationFn: (s: RuleRepoSettings) => (repo ? api.patchRuleRepo(repo.id, s) : api.addRuleRepo(s)),
    onSuccess: (next) => {
      qc.invalidateQueries({ queryKey: queryKeys.ruleRepos })
      qc.invalidateQueries({ queryKey: queryKeys.rules() })
      toast.success(repo ? `${next.name} saved` : next.paths.length ? `Importing ${next.name}…` : `Downloading ${next.name}; choose its folders when it finishes`)
      if (!repo) onAdded?.(next)
      onClose()
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    const paths = tree ? pathsFromSelection(sel) : parseFolders(folderText)
    if (paths) save.mutate({ ...form, paths })
  }
  const toggleStatus = (s: SigmaStatus, on: boolean) => set({ statuses: on ? [...form.statuses, s] : form.statuses.filter((x) => x !== s) })

  return (
    <Modal
      open
      wide
      onClose={save.isPending ? () => undefined : onClose}
      title={repo ? `Edit ${repo.name}` : 'Add a rule repository'}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose} disabled={save.isPending}>
            Cancel
          </button>
          <button type="submit" form="repo-form" className="btn primary" disabled={save.isPending || !form.url.trim() || (!!tree && !pathsFromSelection(sel))}>
            {save.isPending ? <Spinner small /> : null}
            {repo ? 'Save' : 'Import'}
          </button>
        </>
      }
    >
      <form id="repo-form" className="stack" style={{ gap: 14 }} onSubmit={submit}>
        {!repo ? <ChoiceCards name="Rule source" choices={REPO_PRESETS.map((p) => ({ value: p.id, label: p.label, note: p.note }))} value={preset} onChange={choosePreset} /> : null}
        <div className="form-grid">
          <label className="field" style={{ gridColumn: '1 / -1' }}>
            <span className="label">Repository or archive URL</span>
            <input
              className="input mono"
              value={form.url}
              required
              placeholder="https://github.com/owner/repo"
              onChange={(e) => {
                set({ url: e.target.value })
                if (!repo) setPreset('custom')
              }}
            />
            <span className="help">
              Public repositories on GitHub, GitLab, Gitea/Forgejo or Bitbucket, or a link to a .zip / .tar.gz. A link to a folder
              (…/tree/main/rules/windows) also fills in the branch and folder.
            </span>
          </label>
          <label className="field">
            <span className="label">Name</span>
            <input className="input" value={form.name} maxLength={100} placeholder="from the URL" onChange={(e) => set({ name: e.target.value })} />
          </label>
          {!archive ? (
            <label className="field">
              <span className="label">Branch, tag or commit</span>
              <input className="input mono" value={form.ref} placeholder="default branch" onChange={(e) => set({ ref: e.target.value })} />
              <span className="help">A commit pins the rules to that version.</span>
            </label>
          ) : null}
        </div>

        <div className="field">
          <span className="label">Folders</span>
          {tree ? (
            <>
              <span className="help">
                Only rules in the ticked folders are loaded. Every enabled rule runs on every event, so pick the platforms you collect. Counts follow the
                level and status filters below.
              </span>
              <FolderTree files={tree} sel={sel} onChange={setSel} filters={form} />
            </>
          ) : repo?.version && files.isPending ? (
            <Loading compact label="Reading the download…" />
          ) : (
            <>
              <span className="help">
                One per line. Only rules in these folders are loaded; leave empty for the whole repository
                {repo ? '' : ' (after the first download you can pick folders from a tree with rule counts)'}. Every enabled rule runs on every event, so
                pick the platforms you collect.
              </span>
              <textarea className="textarea code" rows={3} value={folderText} placeholder="rules/windows" onChange={(e) => setFolderText(e.target.value)} />
              {repo?.folders.length ? <FolderPicker folders={repo.folders} text={folderText} onChange={setFolderText} /> : null}
            </>
          )}
        </div>

        <div className="form-grid">
          <label className="field">
            <span className="label">Minimum level</span>
            <select className="select" value={form.min_level} onChange={(e) => set({ min_level: e.target.value as Severity | '' })}>
              <option value="">All levels</option>
              {SEVERITIES.filter((s) => s !== 'critical' && s !== 'informational')
                .reverse()
                .map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY_LABEL[s]} and above
                  </option>
                ))}
              <option value="critical">Critical only</option>
            </select>
          </label>
          <div className="field">
            <span className="label">New rules</span>
            <label className="row small" style={{ gap: 8, minHeight: 30 }}>
              <Toggle checked={form.enable_rules} onChange={(v) => set({ enable_rules: v })} label="Enable new rules from this repository" />
              {form.enable_rules ? 'Start enabled' : 'Start disabled (enable them one by one)'}
            </label>
          </div>
        </div>
        <div className="field">
          <span className="label">Rule statuses</span>
          <div className="row" style={{ gap: 14, flexWrap: 'wrap' }}>
            {SIGMA_STATUSES.map((s) => (
              <label key={s.value} className="checkbox small" title={s.note}>
                <input type="checkbox" checked={form.statuses.includes(s.value)} onChange={(e) => toggleStatus(s.value, e.target.checked)} />
                {s.value}
              </label>
            ))}
          </div>
          {form.statuses.length === 0 ? <span className="help">None ticked: every status except deprecated and unsupported is loaded.</span> : null}
        </div>

        <div className="field" style={{ gap: 6 }}>
          <span className="label">Updates</span>
          <ChoiceCards name="Update mode" choices={UPDATE_CHOICES} value={form.auto_update ? 'auto' : 'manual'} onChange={(v) => set({ auto_update: v === 'auto' })} />
          <label className="row small" style={{ gap: 8 }}>
            Check for a new version
            <select className="select" value={form.interval_hours} onChange={(e) => set({ interval_hours: Number(e.target.value) })} aria-label="Check interval">
              {INTERVAL_CHOICES.some((c) => c.hours === form.interval_hours) ? null : <option value={form.interval_hours}>{intervalLabel(form.interval_hours)}</option>}
              {INTERVAL_CHOICES.map((c) => (
                <option key={c.hours} value={c.hours}>
                  {c.label.toLowerCase()}
                </option>
              ))}
            </select>
          </label>
          {!repo ? <span className="help">The first download starts as soon as you click Import, whichever mode you choose.</span> : null}
        </div>

        {save.isError ? (
          <div className="callout danger" role="alert">
            <Icon name="warning" size={14} />
            <span>{errorMessage(save.error)}</span>
          </div>
        ) : null}
      </form>
    </Modal>
  )
}

function pickSettings(r: RuleRepo): RuleRepoSettings {
  const { name, url, ref, paths, min_level, statuses, enable_rules, auto_update, interval_hours, enabled } = r
  return { name, url, ref, paths, min_level, statuses, enable_rules, auto_update, interval_hours, enabled }
}

/** Ticks folders found in the last download into the folder list. */
function FolderPicker({ folders, text, onChange }: { folders: RuleRepo['folders']; text: string; onChange: (text: string) => void }) {
  const [filter, setFilter] = useState('')
  const chosen = parseFolders(text)
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase()
    return folders.filter((x) => !f || x.path.toLowerCase().includes(f)).slice(0, 300)
  }, [folders, filter])
  const flip = (path: string, on: boolean) => onChange((on ? [...chosen, path] : chosen.filter((p) => p !== path)).join('\n'))
  return (
    <div className="stack" style={{ gap: 6, marginTop: 4 }}>
      <input type="search" className="input" placeholder={`Filter ${plural(folders.length, 'folder')} in the download…`} value={filter} onChange={(e) => setFilter(e.target.value)} />
      <div style={{ maxHeight: 220, overflow: 'auto', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '6px 10px' }}>
        {shown.map((f) => {
          const depth = f.path.split('/').length - 1
          return (
            <label key={f.path} className="checkbox small" style={{ display: 'flex', paddingLeft: depth * 16, lineHeight: '24px' }}>
              <input type="checkbox" checked={chosen.includes(f.path)} onChange={(e) => flip(f.path, e.target.checked)} />
              <span className="mono grow">{f.path.split('/').pop()}</span>
              <span className="muted num">{formatNumber(f.files)}</span>
            </label>
          )
        })}
        {shown.length === 0 ? <span className="muted small">No folders match.</span> : null}
      </div>
    </div>
  )
}

function TriCheckbox({ state, onChange, label }: { state: 'on' | 'partial' | 'off'; onChange: () => void; label: string }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = state === 'partial'
  }, [state])
  return <input ref={ref} type="checkbox" checked={state === 'on'} onChange={onChange} aria-label={label} aria-checked={state === 'partial' ? 'mixed' : state === 'on'} />
}

/** Folders of a download as a tree with tri-state boxes and rule counts, and what the selection loads. */
function FolderTree({
  files,
  sel,
  onChange,
  filters,
}: {
  files: RuleRepoFile[]
  sel: string[]
  onChange: (sel: string[]) => void
  filters: Pick<RuleRepoSettings, 'statuses' | 'min_level'>
}) {
  const { root, byPath } = useMemo(() => buildTree(files), [files])
  const counts = useMemo(() => folderCounts(files, filters), [files, filters])
  const summary = useMemo(() => selectionSummary(files, sel, filters), [files, sel, filters])
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set(['']))
  const expand = (p: string) =>
    setExpanded((s) => {
      const n = new Set(s)
      if (n.has(p)) n.delete(p)
      else n.add(p)
      return n
    })
  const toggle = (p: string) => onChange(toggleFolder(sel, p, byPath))
  const all = counts.get('')
  return (
    <div className="stack" style={{ gap: 8 }}>
      <div className="tree" role="group" aria-label="Folders">
        <div className="tree-row tree-head">
          <span className="tree-spacer" />
          <label className="row grow" style={{ gap: 8 }}>
            <TriCheckbox state={folderState(sel, '')} onChange={() => toggle('')} label="The whole repository" />
            <span className="small">Whole repository</span>
          </label>
          <span className="small num nowrap">{all ? formatNumber(all.matching) : 0}</span>
          <span className="tree-note xsmall muted">rules</span>
        </div>
        {root.children
          .filter((k) => counts.has(k.path))
          .map((k) => (
            <FolderRow key={k.path} node={k} depth={0} counts={counts} sel={sel} expanded={expanded} onExpand={expand} onToggle={toggle} />
          ))}
      </div>
      <div className={`callout ${summary.selected ? 'info' : 'warn'}`}>
        <Icon name="info" size={14} />
        <div className="grow small">
          {summary.selected ? (
            <>
              <strong>{plural(summary.runnable, 'rule')}</strong> will load
              {summary.unsupported ? <>; {formatNumber(summary.unsupported)} use Sigma features HomeXDR does not support yet and are skipped</> : null}.
              <div className="muted xsmall" style={{ marginTop: 2 }}>
                {summary.products
                  .slice(0, 8)
                  .map(([p, n]) => `${p} ${formatNumber(n)}`)
                  .join(' · ')}
              </div>
            </>
          ) : sel.length ? (
            'No rules in the ticked folders pass the level and status filters.'
          ) : (
            'Tick at least one folder.'
          )}
        </div>
      </div>
    </div>
  )
}

function FolderRow({
  node,
  depth,
  counts,
  sel,
  expanded,
  onExpand,
  onToggle,
}: {
  node: FolderNode
  depth: number
  counts: Map<string, FolderCounts>
  sel: string[]
  expanded: Set<string>
  onExpand: (path: string) => void
  onToggle: (path: string) => void
}) {
  const c = counts.get(node.path)
  if (!c) return null
  const open = expanded.has(node.path)
  const kids = node.children.filter((k) => counts.has(k.path))
  return (
    <>
      <div className="tree-row" style={{ paddingLeft: 6 + depth * 18 }}>
        {kids.length ? (
          <button type="button" className="btn ghost icon sm" aria-label={open ? `Collapse ${node.path}` : `Expand ${node.path}`} aria-expanded={open} onClick={() => onExpand(node.path)}>
            <Icon name={open ? 'chevronDown' : 'chevronRight'} size={12} />
          </button>
        ) : (
          <span className="tree-spacer" />
        )}
        <label className="row grow" style={{ gap: 8, minWidth: 0 }}>
          <TriCheckbox state={folderState(sel, node.path)} onChange={() => onToggle(node.path)} label={`Load ${node.path}`} />
          <span className="mono small truncate-inline">{node.name}/</span>
        </label>
        <span className="small num nowrap" title={`${c.total} rules in this folder; ${c.matching} pass the level and status filters`}>
          {formatNumber(c.matching)}
          {c.matching !== c.total ? <span className="muted xsmall"> of {formatNumber(c.total)}</span> : null}
        </span>
        <span className="xsmall muted nowrap tree-note">{c.unsupported ? `${c.unsupported} can't run` : ''}</span>
      </div>
      {open ? kids.map((k) => <FolderRow key={k.path} node={k} depth={depth + 1} counts={counts} sel={sel} expanded={expanded} onExpand={onExpand} onToggle={onToggle} />) : null}
    </>
  )
}

/** Rules in a repository's chosen folders that are not loaded, and why. */
function SkippedDialog({ repo, onClose }: { repo: RuleRepo; onClose: () => void }) {
  const q = useQuery({ queryKey: queryKeys.ruleRepoFiles(repo.id), queryFn: () => api.ruleRepoFiles(repo.id) })
  return (
    <Modal open wide onClose={onClose} title={`Rules not loaded from ${repo.name}`}>
      <p className="small muted" style={{ marginTop: 0 }}>
        These rules are in the folders you chose but do not run: they use Sigma features HomeXDR does not support yet (correlations, aggregations,
        placeholders, field references), or another source already has a rule with the same id. Rules skipped by the level and status filters are not
        listed.
      </p>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.skipped.length === 0 ? (
        <EmptyState title="Every rule in the chosen folders is loaded" compact />
      ) : (
        <div className="table-wrap" style={{ maxHeight: 420 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>Why it is not loaded</th>
              </tr>
            </thead>
            <tbody>
              {q.data.skipped.map((s, i) => (
                <tr key={i}>
                  <td className="small">
                    {s.title || <span className="muted">{s.path.split('/').pop()}</span>}
                    <div className="mono xsmall muted" style={{ overflowWrap: 'anywhere' }}>
                      {s.path}
                    </div>
                  </td>
                  <td className="small" style={{ overflowWrap: 'anywhere' }}>
                    {s.error}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  )
}
