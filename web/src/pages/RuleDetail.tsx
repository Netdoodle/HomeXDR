import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { api, isApiError, queryKeys } from '../api'
import { useCan } from '../components/Auth'
import { MitreTag, SeverityBadge, Tags } from '../components/Badges'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { CopyButton, KV, RelTime, Toggle } from '../components/Misc'
import { ConfirmDialog } from '../components/Modal'
import { EmptyState, ErrorState, Loading } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { useToggleRule } from './Rules'

export function RuleDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  const isAdmin = useCan('admin')
  const q = useQuery({ queryKey: queryKeys.rule(id), queryFn: () => api.getRule(id) })
  const toggle = useToggleRule()
  const [deleting, setDeleting] = useState(false)
  useDocumentTitle(q.data?.title ?? 'Rule')

  if (q.isPending) return <Loading />
  if (q.isError) {
    return (
      <div className="panel">
        {isApiError(q.error) && q.error.status === 404 ? (
          <EmptyState title="Rule not found" action={<Link to="/rules">Back to rules</Link>} />
        ) : (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        )}
      </div>
    )
  }
  const r = q.data
  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/rules">Rules</Link>
        <Icon name="chevronRight" size={10} />
        <span className="mono">{r.id}</span>
      </div>
      <PageHeader
        title={
          <span className="row" style={{ gap: 10 }}>
            <SeverityBadge severity={r.level} />
            {r.title}
          </span>
        }
        subtitle={
          <span className="row" style={{ gap: 14 }}>
            <span>{r.source === 'custom' ? 'Custom rule' : r.repo ? `From ${r.repo.name}` : 'Built-in rule'}</span>
            <span>{r.enabled ? 'Enabled' : 'Disabled'}</span>
            <span>{formatNumber(r.hits_24h)} hits in 24h</span>
            <span>
              updated <RelTime iso={r.updated_at} />
            </span>
          </span>
        }
        actions={
          <>
            <span className="row small" title={isAdmin ? undefined : 'Only admins can enable or disable rules'}>
              <Toggle checked={r.enabled} disabled={!isAdmin || toggle.isPending} onChange={(v) => toggle.mutate({ id: r.id, enabled: v })} label={r.enabled ? 'Disable rule' : 'Enable rule'} />
              {r.enabled ? 'Enabled' : 'Disabled'}
            </span>
            <Link className="btn" to={`/alerts?rule=${encodeURIComponent(r.id)}&status=all`}>
              <Icon name="alert" size={14} /> Alerts
            </Link>
            {isAdmin && r.source === 'custom' ? (
              <>
                <Link className="btn" to={`/rules/${encodeURIComponent(r.id)}/edit`}>
                  <Icon name="edit" size={14} /> Edit
                </Link>
                <button type="button" className="btn danger" onClick={() => setDeleting(true)}>
                  <Icon name="trash" size={14} /> Delete
                </button>
              </>
            ) : null}
            {r.repo?.url ? (
              <a className="btn" href={r.repo.url} target="_blank" rel="noreferrer noopener" title="This rule's file in its repository">
                <Icon name="external" size={14} /> Upstream
              </a>
            ) : null}
            {isAdmin && r.source !== 'custom' ? (
              <Link
                className="btn"
                to={`/rules/new?from=${encodeURIComponent(r.id)}`}
                title={`${r.repo ? 'Repository' : 'Built-in'} rules are read-only; copy it into a custom rule to change it`}
              >
                <Icon name="copy" size={14} /> Copy as custom
              </Link>
            ) : null}
          </>
        }
      />
      <div className="grid grid-sidebar" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2>Rule YAML</h2>
            {r.yaml ? <CopyButton text={r.yaml} small /> : null}
          </div>
          <div className="panel-body">
            {r.yaml ? <pre className="codeblock">{r.yaml}</pre> : <EmptyState title="No YAML returned for this rule" compact />}
          </div>
        </section>
        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Details</h2>
            </div>
            <div className="panel-body stack" style={{ gap: 10 }}>
              {r.description ? <p style={{ margin: 0 }}>{r.description}</p> : null}
              <KV
                items={[
                  [
                    'Repository',
                    r.repo ? (
                      <span key="repo" className="stack" style={{ gap: 2 }}>
                        <Link to="/rules/repositories">{r.repo.name}</Link>
                        <span className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>
                          {r.repo.path}
                        </span>
                      </span>
                    ) : undefined,
                  ],
                  ['Status', r.status],
                  ['Author', r.author],
                  ['Product', r.logsource.product],
                  ['Category', r.logsource.category],
                  ['Service', r.logsource.service],
                  ['Tags', <Tags key="t" tags={r.tags} />],
                  [
                    'References',
                    r.references?.length ? (
                      <div key="r" className="stack" style={{ gap: 2 }}>
                        {r.references.map((u) => (
                          <a key={u} href={u} target="_blank" rel="noreferrer noopener" className="truncate-inline">
                            {u}
                          </a>
                        ))}
                      </div>
                    ) : undefined,
                  ],
                ]}
              />
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h2>MITRE ATT&amp;CK</h2>
            </div>
            <div className="panel-body">
              {r.mitre.length === 0 ? (
                <span className="muted small">No mapping.</span>
              ) : (
                <div className="stack" style={{ gap: 6 }}>
                  {r.mitre.map((m, i) => (
                    <div key={i} className="row">
                      <MitreTag m={{ technique_id: m.technique_id, tactic: m.tactic }} />
                      <span>{m.technique}</span>
                      {m.tactic ? <span className="muted small">· {m.tactic}</span> : null}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
      <ConfirmDialog
        open={deleting}
        onClose={() => setDeleting(false)}
        title={`Delete “${r.title}”?`}
        danger
        confirmLabel="Delete rule"
        onConfirm={async () => {
          await api.deleteRule(r.id)
          qc.invalidateQueries({ queryKey: queryKeys.rules() })
          qc.removeQueries({ queryKey: queryKeys.rule(r.id) })
          toast.success('Rule deleted')
          navigate('/rules')
        }}
      >
        <p>This will:</p>
        <ul className="effect-list">
          <li>Remove the custom rule permanently; new events are no longer checked against it.</li>
          <li>Keep existing alerts from this rule.</li>
        </ul>
      </ConfirmDialog>
    </>
  )
}
