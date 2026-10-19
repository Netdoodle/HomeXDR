import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, queryKeys, SEVERITIES, type Rule, type RuleFilter } from '../api'
import { useCan } from '../components/Auth'
import { MitreTag, SeverityBadge } from '../components/Badges'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { RelTime, Toggle } from '../components/Misc'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber, plural } from '../lib/format'
import { useDebounced, useDocumentTitle, useUrlState } from '../lib/hooks'
import { SEVERITY_LABEL } from '../lib/severity'

export function useToggleRule() {
  const qc = useQueryClient()
  const toast = useToast()
  return useMutation({
    mutationFn: (r: { id: string; enabled: boolean }) => api.setRuleEnabled(r.id, r.enabled),
    onSuccess: (rule) => {
      qc.setQueryData(queryKeys.rule(rule.id), (old: Rule | undefined) => ({ ...rule, yaml: rule.yaml ?? old?.yaml }))
      qc.invalidateQueries({ queryKey: queryKeys.rules() })
      toast.success(`${rule.title} ${rule.enabled ? 'enabled' : 'disabled'}`)
    },
    onError: (e) => toast.error(e),
  })
}

export function RulesPage() {
  useDocumentTitle('Rules')
  const [sp, patch] = useUrlState()
  const navigate = useNavigate()
  const isAdmin = useCan('admin')
  const [text, setText] = useState(sp.get('q') ?? '')
  const debounced = useDebounced(text, 300)
  const appliedQ = useRef(debounced)
  useEffect(() => {
    if (debounced !== appliedQ.current) {
      appliedQ.current = debounced
      patch({ q: debounced })
    }
  }, [debounced, patch])

  const filter: RuleFilter = {
    q: sp.get('q') || undefined,
    level: sp.get('level') || undefined,
    source: sp.get('source') || undefined,
    enabled: sp.get('enabled') || undefined,
  }
  const q = useQuery({ queryKey: queryKeys.rules(filter), queryFn: () => api.listRules(filter), placeholderData: keepPreviousData })
  const toggle = useToggleRule()
  const qc = useQueryClient()
  const toast = useToast()
  const reload = useMutation({
    mutationFn: api.reloadRules,
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: queryKeys.rules() })
      const errs = r.load_errors.length ? `, ${plural(r.load_errors.length, 'file')} failed to load` : ''
      toast.success(`Reloaded ${plural(r.total, 'rule')} (${formatNumber(r.enabled)} enabled)${errs}`)
    },
    onError: (e) => toast.error(e),
  })

  return (
    <>
      <PageHeader
        title="Detection rules"
        subtitle={q.data ? `${plural(q.data.total, 'rule')} · Sigma format` : 'Sigma format'}
        actions={
          <>
            {q.isFetching && !q.isPending ? <Spinner small /> : null}
            {isAdmin ? (
              <>
                <button
                  type="button"
                  className="btn"
                  onClick={() => reload.mutate()}
                  disabled={reload.isPending}
                  title="Re-read the server's rules folder now. Changes there are also picked up automatically within a minute."
                >
                  <Icon name="refresh" size={14} /> Reload rules folder
                </button>
                <Link className="btn primary" to="/rules/new">
                  <Icon name="plus" size={14} /> New custom rule
                </Link>
              </>
            ) : null}
          </>
        }
      />
      <div className="filters">
        <input type="search" className="input" placeholder="Title, tag, technique…" value={text} onChange={(e) => setText(e.target.value)} aria-label="Filter rules" />
        <select className="select" value={filter.level ?? ''} onChange={(e) => patch({ level: e.target.value })} aria-label="Level">
          <option value="">Any level</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </select>
        <select className="select" value={filter.source ?? ''} onChange={(e) => patch({ source: e.target.value })} aria-label="Source">
          <option value="">Built-in and custom</option>
          <option value="builtin">Built-in</option>
          <option value="custom">Custom</option>
        </select>
        <select className="select" value={filter.enabled ?? ''} onChange={(e) => patch({ enabled: e.target.value })} aria-label="Enabled">
          <option value="">Enabled and disabled</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
      </div>
      {q.data?.load_errors.length ? (
        <div className="callout danger" role="alert" style={{ marginBottom: 12 }}>
          <Icon name="warning" size={14} />
          <div className="stack" style={{ gap: 4 }}>
            <strong>{q.data.load_errors.length === 1 ? '1 rule failed to load' : `${q.data.load_errors.length} rules failed to load`} and is not running</strong>
            {q.data.load_errors.slice(0, 10).map((e, i) => (
              <span key={i} className="mono xsmall" style={{ overflowWrap: 'anywhere' }}>
                {e.path}: {e.error}
              </span>
            ))}
          </div>
        </div>
      ) : null}
      <section className="panel">
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : q.data.rules.length === 0 ? (
          <EmptyState title="No rules match" />
        ) : (
          <div className="table-wrap">
            <table className="table fixed" style={{ minWidth: 1000 }}>
              <colgroup>
                <col style={{ width: 64 }} />
                <col />
                <col style={{ width: 96 }} />
                <col style={{ width: 84 }} />
                <col style={{ width: '22%' }} />
                <col style={{ width: 150 }} />
                <col style={{ width: 76 }} />
                <col style={{ width: 90 }} />
              </colgroup>
              <thead>
                <tr>
                  <th>Enabled</th>
                  <th>Title</th>
                  <th>Level</th>
                  <th>Source</th>
                  <th>MITRE</th>
                  <th>Log source</th>
                  <th className="right">Hits 24h</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {q.data.rules.map((r) => (
                  <tr key={r.id} className="clickable" onClick={() => navigate(`/rules/${encodeURIComponent(r.id)}`)}>
                    <td onClick={(e) => e.stopPropagation()} title={isAdmin ? undefined : 'Only admins can enable or disable rules'}>
                      <Toggle
                        checked={r.enabled}
                        disabled={!isAdmin || (toggle.isPending && toggle.variables?.id === r.id)}
                        onChange={(v) => toggle.mutate({ id: r.id, enabled: v })}
                        label={`${r.enabled ? 'Disable' : 'Enable'} ${r.title}`}
                      />
                    </td>
                    <td className="truncate" title={r.title}>
                      <Link to={`/rules/${encodeURIComponent(r.id)}`} onClick={(e) => e.stopPropagation()}>
                        {r.title}
                      </Link>
                      {r.description ? <div className="muted xsmall truncate-inline">{r.description}</div> : null}
                    </td>
                    <td>
                      <SeverityBadge severity={r.level} />
                    </td>
                    <td>{r.source === 'custom' ? <span className="tag">custom</span> : <span className="muted small">built-in</span>}</td>
                    <td className="truncate">
                      <span className="row nowrap" style={{ gap: 4 }}>
                        {r.mitre.length ? r.mitre.slice(0, 2).map((m, i) => <MitreTag key={i} m={m} />) : <span className="empty-cell">—</span>}
                      </span>
                    </td>
                    <td className="truncate mono small">{[r.logsource.product, r.logsource.category ?? r.logsource.service].filter(Boolean).join(' / ') || '—'}</td>
                    <td className="right num">{r.hits_24h ? <strong>{formatNumber(r.hits_24h)}</strong> : <span className="empty-cell">0</span>}</td>
                    <td>
                      <RelTime iso={r.updated_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}
