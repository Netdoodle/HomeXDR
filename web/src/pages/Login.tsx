import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState, type FormEvent } from 'react'
import { Navigate, useSearchParams } from 'react-router'
import { api, errorMessage, queryKeys } from '../api'
import { Icon } from '../components/Icon'
import { ErrorState, Loading, Spinner } from '../components/States'

function safeNext(next: string | null): string {
  // Only allow same-app relative paths.
  if (!next || !next.startsWith('/') || next.startsWith('//') || next.startsWith('/login')) return '/'
  return next
}

function Brand() {
  return (
    <div className="brand-line">
      <svg width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
        <path d="M16 3 5 7.5v7.7c0 6.8 4.6 12 11 14.3 6.4-2.3 11-7.5 11-14.3V7.5L16 3Z" fill="none" stroke="var(--accent)" strokeWidth="2.4" strokeLinejoin="round" />
        <path d="m11.5 12 9 9m0-9-9 9" stroke="var(--text)" strokeWidth="2.4" strokeLinecap="round" />
      </svg>
      HomeXDR
    </div>
  )
}

export function LoginPage() {
  const [sp] = useSearchParams()
  const next = safeNext(sp.get('next'))
  const status = useQuery({ queryKey: queryKeys.setup, queryFn: api.setupStatus, retry: 1 })
  const me = useQuery({ queryKey: queryKeys.me, queryFn: async () => (await api.me()).user, retry: false, enabled: status.data?.needs_setup === false })

  useEffect(() => {
    document.title = status.data?.needs_setup ? 'Set up HomeXDR' : 'Sign in · HomeXDR'
    return () => {
      document.title = 'HomeXDR'
    }
  }, [status.data?.needs_setup])

  // Where to go after this page signs someone in; set by the forms below.
  const [signedInTo, setSignedInTo] = useState<string | null>(null)
  if (signedInTo) return <Navigate to={signedInTo} replace />
  if (me.data) return <Navigate to={next} replace />

  return (
    <div className="auth-page">
      <div className="auth-card">
        <Brand />
        {status.isPending ? (
          <Loading compact />
        ) : status.isError ? (
          <ErrorState error={status.error} onRetry={() => status.refetch()} title="Cannot reach the server" compact />
        ) : status.data.needs_setup ? (
          <SetupForm onDone={() => setSignedInTo(next === '/' ? '/settings/tokens' : next)} />
        ) : (
          <LoginForm onDone={() => setSignedInTo(next)} />
        )}
        {status.data ? <p className="faint xsmall" style={{ marginTop: 16, marginBottom: 0 }}>Version {status.data.version}</p> : null}
      </div>
    </div>
  )
}

function LoginForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const login = useMutation({
    mutationFn: () => api.login(username.trim(), password),
    onSuccess: ({ user }) => {
      qc.setQueryData(queryKeys.me, user)
      onDone()
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (!username.trim() || !password) return
    login.mutate()
  }
  return (
    <form onSubmit={submit} noValidate>
      <h1 style={{ fontSize: 'var(--fs-lg)' }}>Sign in</h1>
      <div className="field">
        <label htmlFor="login-user">Username</label>
        <input id="login-user" className="input" autoComplete="username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="login-pass">Password</label>
        <input id="login-pass" className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      {login.isError ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>{errorMessage(login.error)}</span>
        </div>
      ) : null}
      <button type="submit" className="btn primary" disabled={login.isPending || !username.trim() || !password}>
        {login.isPending ? <Spinner small /> : null} Sign in
      </button>
    </form>
  )
}

function SetupForm({ onDone }: { onDone: () => void }) {
  const qc = useQueryClient()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [touched, setTouched] = useState(false)
  const tooShort = password.length > 0 && password.length < 10
  const mismatch = confirm.length > 0 && confirm !== password
  const valid = username.trim().length >= 2 && password.length >= 10 && confirm === password
  const setup = useMutation({
    mutationFn: () => api.setup(username.trim(), password),
    onSuccess: ({ user }) => {
      qc.setQueryData(queryKeys.me, user)
      qc.setQueryData(queryKeys.setup, (s: { needs_setup: boolean; version: string } | undefined) => (s ? { ...s, needs_setup: false } : s))
      onDone()
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (valid) setup.mutate()
  }
  return (
    <form onSubmit={submit} noValidate>
      <div>
        <h1 style={{ fontSize: 'var(--fs-lg)', marginBottom: 6 }}>Create the admin account</h1>
        <p className="muted small">This is a new installation. The first account has full access; you can add analysts and viewers later.</p>
      </div>
      <div className="field">
        <label htmlFor="setup-user">Username</label>
        <input id="setup-user" className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="setup-pass">Password</label>
        <input
          id="setup-pass"
          className={(touched || tooShort) && password.length < 10 ? 'input invalid' : 'input'}
          type="password"
          autoComplete="new-password"
          autoFocus
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          aria-describedby="setup-pass-help"
        />
        <span id="setup-pass-help" className={tooShort ? 'error' : 'help'}>
          At least 10 characters{password ? ` (${password.length})` : ''}.
        </span>
      </div>
      <div className="field">
        <label htmlFor="setup-confirm">Confirm password</label>
        <input
          id="setup-confirm"
          className={mismatch ? 'input invalid' : 'input'}
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {mismatch ? <span className="error">Passwords do not match.</span> : null}
      </div>
      {setup.isError ? (
        <div className="callout danger" role="alert">
          <Icon name="warning" size={14} />
          <span>{errorMessage(setup.error)}</span>
        </div>
      ) : null}
      <button type="submit" className="btn primary" disabled={setup.isPending || !valid}>
        {setup.isPending ? <Spinner small /> : null} Create account and sign in
      </button>
    </form>
  )
}
