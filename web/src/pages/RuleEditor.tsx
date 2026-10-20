import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type KeyboardEvent } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { api, queryKeys, type RuleTestResponse, type RuleValidateResponse } from '../api'
import { useCan } from '../components/Auth'
import { MitreTag, SeverityBadge } from '../components/Badges'
import { EventTable } from '../components/EventTable'
import { Icon } from '../components/Icon'
import { PageHeader } from '../components/Layout'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { errorMessage } from '../api/client'
import { formatNumber } from '../lib/format'
import { useDocumentTitle } from '../lib/hooks'
import { uuid } from '../lib/uuid'

function template(): string {
  const id = uuid()
  return `title: Suspicious Child Of Office Application
id: ${id}
status: experimental
description: An Office application started a command interpreter.
author: you
tags:
  - attack.execution
  - attack.t1059
logsource:
  product: windows
  category: process_creation
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
  selection_child:
    Image|endswith:
      - '\\cmd.exe'
      - '\\powershell.exe'
  condition: all of selection_*
falsepositives:
  - Macros you wrote yourself
level: high
`
}

/** Turns a built-in rule's YAML into a starting point for a custom copy. */
function asCustomCopy(yaml: string): string {
  return yaml
    .replace(/^id:.*$/m, `id: ${uuid()}`)
    .replace(/^title:\s*(.*)$/m, (_, t: string) => `title: Custom: ${t.replace(/^Custom:\s*/, '')}`)
    .replace(/^status:.*$/m, 'status: experimental')
}

export function RuleEditorPage() {
  const { id } = useParams()
  const [sp] = useSearchParams()
  const from = sp.get('from')
  const editing = !!id
  const isAdmin = useCan('admin')
  const navigate = useNavigate()
  const qc = useQueryClient()
  const toast = useToast()
  useDocumentTitle(editing ? 'Edit rule' : 'New rule')

  const sourceId = id ?? from ?? undefined
  const src = useQuery({ queryKey: queryKeys.rule(sourceId ?? ''), queryFn: () => api.getRule(sourceId!), enabled: !!sourceId })

  const [yaml, setYaml] = useState<string | null>(sourceId ? null : template())
  useEffect(() => {
    if (yaml === null && src.data?.yaml) setYaml(editing ? src.data.yaml : asCustomCopy(src.data.yaml))
  }, [src.data, yaml, editing])

  const [validation, setValidation] = useState<RuleValidateResponse | null>(null)
  const [testResult, setTestResult] = useState<RuleTestResponse | null>(null)
  const [hours, setHours] = useState(24)

  const validate = useMutation({ mutationFn: (y: string) => api.validateRule(y), onSuccess: setValidation, onError: (e) => setValidation({ ok: false, error: errorMessage(e) }) })
  const test = useMutation({ mutationFn: (y: string) => api.testRule(y, hours), onSuccess: setTestResult })
  const save = useMutation({
    mutationFn: (y: string) => (editing ? api.updateRule(id!, y) : api.createRule(y)),
    onSuccess: (rule) => {
      qc.invalidateQueries({ queryKey: queryKeys.rules() })
      qc.setQueryData(queryKeys.rule(rule.id), rule)
      toast.success(editing ? 'Rule saved' : 'Rule created and enabled')
      navigate(`/rules/${encodeURIComponent(rule.id)}`)
    },
  })

  // Any edit invalidates earlier validation/test output.
  const onEdit = (v: string) => {
    setYaml(v)
    setValidation(null)
    save.reset()
  }

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Tab' && !e.shiftKey) {
      // YAML forbids tabs; insert two spaces instead.
      e.preventDefault()
      const ta = e.currentTarget
      const { selectionStart: s, selectionEnd: end, value } = ta
      const next = value.slice(0, s) + '  ' + value.slice(end)
      onEdit(next)
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = s + 2
      })
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && yaml) {
      e.preventDefault()
      validate.mutate(yaml)
    }
  }

  if (!isAdmin) {
    return (
      <div className="panel">
        <EmptyState title="Only admins can create or edit rules" action={<Link to="/rules">Back to rules</Link>} />
      </div>
    )
  }
  if (sourceId && src.isPending) return <Loading />
  if (sourceId && src.isError) return <div className="panel"><ErrorState error={src.error} onRetry={() => src.refetch()} /></div>
  if (editing && src.data && src.data.source !== 'custom') {
    return (
      <div className="panel">
        <EmptyState title="Built-in rules are read-only" action={<Link to={`/rules/new?from=${encodeURIComponent(src.data.id)}`}>Copy it into a custom rule</Link>} />
      </div>
    )
  }

  const value = yaml ?? ''
  return (
    <>
      <div className="row small muted" style={{ marginBottom: 6 }}>
        <Link to="/rules">Rules</Link>
        <Icon name="chevronRight" size={10} />
        <span>{editing ? src.data?.title : from ? 'Copy of ' + (src.data?.title ?? 'rule') : 'New custom rule'}</span>
      </div>
      <PageHeader
        title={editing ? 'Edit custom rule' : 'New custom rule'}
        subtitle="Sigma YAML. Field names are standard Sigma (Image, CommandLine, TargetObject, …) and are mapped to HomeXDR fields."
        actions={
          <>
            <button type="button" className="btn" onClick={() => validate.mutate(value)} disabled={!value.trim() || validate.isPending}>
              {validate.isPending ? <Spinner small /> : <Icon name="check" size={14} />} Validate
            </button>
            <span className="row nowrap">
              <select className="select" value={hours} onChange={(e) => setHours(Number(e.target.value))} aria-label="Test window">
                <option value={1}>last hour</option>
                <option value={24}>last 24h</option>
                <option value={168}>last 7 days</option>
              </select>
              <button type="button" className="btn" onClick={() => test.mutate(value)} disabled={!value.trim() || test.isPending}>
                {test.isPending ? <Spinner small /> : <Icon name="play" size={12} />} Test
              </button>
            </span>
            <button type="button" className="btn primary" onClick={() => save.mutate(value)} disabled={!value.trim() || save.isPending}>
              {save.isPending ? <Spinner small /> : null} {editing ? 'Save rule' : 'Create rule'}
            </button>
          </>
        }
      />
      <div className="grid grid-sidebar" style={{ alignItems: 'start' }}>
        <section className="panel">
          <div className="panel-header">
            <h2>YAML</h2>
            <span className="hint">Tab inserts spaces · Ctrl+Enter validates</span>
          </div>
          <div className="panel-body">
            <textarea
              className={validation && !validation.ok ? 'textarea code invalid' : 'textarea code'}
              style={{ width: '100%', minHeight: 460 }}
              value={value}
              onChange={(e) => onEdit(e.target.value)}
              onKeyDown={onKeyDown}
              spellCheck={false}
              aria-label="Rule YAML"
              wrap="off"
            />
          </div>
        </section>
        <div className="stack">
          <section className="panel">
            <div className="panel-header">
              <h2>Validation</h2>
            </div>
            <div className="panel-body">
              {save.isError ? (
                <div className="callout danger" role="alert" style={{ marginBottom: 10 }}>
                  <Icon name="warning" size={14} />
                  <span>Save failed: {errorMessage(save.error)}</span>
                </div>
              ) : null}
              {!validation ? (
                <span className="muted small">Validate to check the YAML and compile the detection.</span>
              ) : validation.ok ? (
                <div className="stack" style={{ gap: 8 }}>
                  <div className="callout ok">
                    <Icon name="check" size={14} />
                    <span>Valid. The rule compiles.</span>
                  </div>
                  {validation.rule ? (
                    <dl className="kv small">
                      <dt>Title</dt>
                      <dd>{validation.rule.title}</dd>
                      <dt>Level</dt>
                      <dd>
                        <SeverityBadge severity={validation.rule.level} />
                      </dd>
                      <dt>Log source</dt>
                      <dd className="mono">{[validation.rule.logsource.product, validation.rule.logsource.category, validation.rule.logsource.service].filter(Boolean).join(' / ') || '—'}</dd>
                      <dt>MITRE</dt>
                      <dd className="row" style={{ gap: 4 }}>
                        {validation.rule.mitre.length ? validation.rule.mitre.map((m, i) => <MitreTag key={i} m={m} />) : '—'}
                      </dd>
                    </dl>
                  ) : null}
                </div>
              ) : (
                <div className="callout danger" role="alert">
                  <Icon name="warning" size={14} />
                  <span className="mono small" style={{ overflowWrap: 'anywhere' }}>
                    {validation.error ?? 'Invalid rule'}
                  </span>
                </div>
              )}
            </div>
          </section>
          <section className="panel">
            <div className="panel-header">
              <h2>Test against stored events</h2>
              {testResult ? (
                <span className="hint">
                  {formatNumber(testResult.matches.length)} matches in {formatNumber(testResult.scanned)} events
                </span>
              ) : null}
            </div>
            {test.isError ? (
              <ErrorState error={test.error} compact title="Test failed" />
            ) : !testResult ? (
              <div className="panel-body">
                <span className="muted small">Runs the rule over recent events without creating alerts.</span>
              </div>
            ) : testResult.matches.length === 0 ? (
              <EmptyState title="No matches" compact>
                Nothing in the selected window matches. That can be correct for a rare behavior.
              </EmptyState>
            ) : (
              <EventTable events={testResult.matches.slice(0, 50)} showHost />
            )}
          </section>
        </div>
      </div>
    </>
  )
}
