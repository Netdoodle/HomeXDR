// "Two-factor login" card on Settings → My account: turn authenticator-app codes on and
// off, and manage recovery codes. Optional; nobody is forced to use it.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import QRCode from 'qrcode'
import { useEffect, useState, type FormEvent } from 'react'
import { api, errorMessage, queryKeys } from '../api'
import { Icon } from '../components/Icon'
import { CopyButton } from '../components/Misc'
import { QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'

type Step =
  | { kind: 'idle' }
  | { kind: 'password' } // asking for the password before starting
  | { kind: 'scan'; secret: string; uri: string }
  | { kind: 'codes'; codes: string[] }
  | { kind: 'recovery' } // password + code, then new recovery codes
  | { kind: 'disable' } // password + code, then off

function ErrorLine({ error }: { error: unknown }) {
  return (
    <div className="callout danger" role="alert">
      <Icon name="warning" size={14} />
      <span>{errorMessage(error)}</span>
    </div>
  )
}

function QrImage({ uri }: { uri: string }) {
  const [src, setSrc] = useState<string | null>(null)
  useEffect(() => {
    let live = true
    QRCode.toDataURL(uri, { margin: 2, width: 200 })
      .then((d) => live && setSrc(d))
      .catch(() => live && setSrc(null))
    return () => {
      live = false
    }
  }, [uri])
  if (!src) return <div className="muted small">Drawing the QR code…</div>
  return <img src={src} width={200} height={200} alt="QR code to scan with your authenticator app" style={{ background: '#fff', borderRadius: 6 }} />
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join('\n') + '\n'
  const download = () => {
    const url = URL.createObjectURL(new Blob([`HomeXDR recovery codes\n\n${text}`], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'homexdr-recovery-codes.txt'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }
  return (
    <div className="stack" style={{ gap: 10 }}>
      <div className="callout warn">
        <Icon name="warning" size={14} />
        <span>
          Save these recovery codes now. You won’t see them again. Each one works once if you lose your authenticator app.
        </span>
      </div>
      <pre className="codeblock" aria-label="Recovery codes">
        {text}
      </pre>
      <div className="row" style={{ gap: 8 }}>
        <CopyButton text={text} label="Copy" />
        <button type="button" className="btn" onClick={download}>
          <Icon name="download" size={14} /> Download (.txt)
        </button>
        <button type="button" className="btn primary" onClick={onDone}>
          I have saved them
        </button>
      </div>
    </div>
  )
}

/** Password (and optionally a code) form for the actions that need re-confirming. */
function ConfirmForm({
  withCode,
  submitLabel,
  danger,
  pending,
  error,
  onSubmit,
  onCancel,
}: {
  withCode: boolean
  submitLabel: string
  danger?: boolean
  pending: boolean
  error: unknown
  onSubmit: (password: string, code: string) => void
  onCancel: () => void
}) {
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const valid = password !== '' && (!withCode || code.trim() !== '')
  const submit = (e: FormEvent) => {
    e.preventDefault()
    if (valid) onSubmit(password, code.trim())
  }
  return (
    <form className="stack" style={{ gap: 10, maxWidth: 380 }} onSubmit={submit} noValidate>
      <div className="field">
        <label htmlFor="tf-password">Your password</label>
        <input id="tf-password" className="input" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      {withCode ? (
        <div className="field">
          <label htmlFor="tf-code">Authenticator code or recovery code</label>
          <input id="tf-code" className="input mono" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
        </div>
      ) : null}
      {error ? <ErrorLine error={error} /> : null}
      <div className="row" style={{ gap: 8 }}>
        <button type="submit" className={danger ? 'btn danger' : 'btn primary'} disabled={!valid || pending}>
          {pending ? <Spinner small /> : null} {submitLabel}
        </button>
        <button type="button" className="btn ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}

export function TwoFactorCard() {
  const qc = useQueryClient()
  const toast = useToast()
  const status = useQuery({ queryKey: queryKeys.totp, queryFn: api.totpStatus })
  const [step, setStep] = useState<Step>({ kind: 'idle' })
  const [code, setCode] = useState('')

  const refresh = () => {
    qc.invalidateQueries({ queryKey: queryKeys.totp })
    qc.invalidateQueries({ queryKey: queryKeys.me })
  }
  const idle = () => {
    setStep({ kind: 'idle' })
    setCode('')
  }

  const setup = useMutation({
    mutationFn: (password: string) => api.totpSetup(password),
    onSuccess: (r) => setStep({ kind: 'scan', secret: r.secret, uri: r.uri }),
  })
  const enable = useMutation({
    mutationFn: () => api.totpEnable(code.trim()),
    onSuccess: (r) => {
      setCode('')
      setStep({ kind: 'codes', codes: r.recovery_codes })
      refresh()
      toast.success('Two-factor login is on')
    },
  })
  const newCodes = useMutation({
    mutationFn: (v: { password: string; code: string }) => api.totpNewRecovery(v.password, v.code),
    onSuccess: (r) => {
      setStep({ kind: 'codes', codes: r.recovery_codes })
      refresh()
    },
  })
  const disable = useMutation({
    mutationFn: (v: { password: string; code: string }) => api.totpDisable(v.password, v.code),
    onSuccess: () => {
      idle()
      refresh()
      toast.success('Two-factor login is off')
    },
  })

  return (
    <section className="panel">
      <div className="panel-header">
        <h2>Two-factor login</h2>
      </div>
      <div className="panel-body">
        <QueryView query={status}>
          {(s) => (
            <div className="stack" style={{ gap: 12 }}>
              {step.kind === 'idle' && !s.enabled ? (
                <>
                  <p className="muted small" style={{ margin: 0 }}>
                    Off. Turn it on to ask for a 6-digit code from an authenticator app each time you sign in, on top of your password.
                  </p>
                  <div>
                    <button type="button" className="btn primary" onClick={() => setStep({ kind: 'password' })}>
                      <Icon name="key" size={14} /> Turn on
                    </button>
                  </div>
                </>
              ) : null}
              {step.kind === 'idle' && s.enabled ? (
                <>
                  <p style={{ margin: 0 }}>
                    <span className="tag">On</span> You are asked for an authenticator code when you sign in.
                  </p>
                  <p className="muted small" style={{ margin: 0 }}>
                    Recovery codes left: <strong>{s.recovery_left}</strong>
                  </p>
                  <div className="row" style={{ gap: 8 }}>
                    <button type="button" className="btn" onClick={() => setStep({ kind: 'recovery' })}>
                      New recovery codes
                    </button>
                    <button type="button" className="btn" onClick={() => setStep({ kind: 'disable' })}>
                      Turn off
                    </button>
                  </div>
                </>
              ) : null}
              {step.kind === 'password' ? (
                <ConfirmForm
                  withCode={false}
                  submitLabel="Continue"
                  pending={setup.isPending}
                  error={setup.error}
                  onSubmit={(pw) => setup.mutate(pw)}
                  onCancel={() => {
                    setup.reset()
                    idle()
                  }}
                />
              ) : null}
              {step.kind === 'scan' ? (
                <form
                  className="stack"
                  style={{ gap: 10, maxWidth: 380 }}
                  onSubmit={(e) => {
                    e.preventDefault()
                    if (code.trim()) enable.mutate()
                  }}
                  noValidate
                >
                  <p className="muted small" style={{ margin: 0 }}>
                    Scan this QR code with an authenticator app (any app that supports one-time codes), then enter the 6-digit code it shows.
                  </p>
                  <QrImage uri={step.uri} />
                  <div className="field">
                    <span className="label">Or enter this key by hand</span>
                    <div className="copy-field">
                      <pre className="codeblock wrap" aria-label="Secret key">
                        {step.secret}
                      </pre>
                      <CopyButton text={step.secret} small />
                    </div>
                  </div>
                  <div className="field">
                    <label htmlFor="tf-confirm">6-digit code</label>
                    <input id="tf-confirm" className="input mono" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
                  </div>
                  {enable.isError ? <ErrorLine error={enable.error} /> : null}
                  <div className="row" style={{ gap: 8 }}>
                    <button type="submit" className="btn primary" disabled={!code.trim() || enable.isPending}>
                      {enable.isPending ? <Spinner small /> : null} Turn on
                    </button>
                    <button
                      type="button"
                      className="btn ghost"
                      onClick={() => {
                        enable.reset()
                        idle()
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              ) : null}
              {step.kind === 'codes' ? <RecoveryCodes codes={step.codes} onDone={idle} /> : null}
              {step.kind === 'recovery' ? (
                <ConfirmForm
                  withCode
                  submitLabel="Make new codes"
                  pending={newCodes.isPending}
                  error={newCodes.error}
                  onSubmit={(password, code) => newCodes.mutate({ password, code })}
                  onCancel={() => {
                    newCodes.reset()
                    idle()
                  }}
                />
              ) : null}
              {step.kind === 'disable' ? (
                <>
                  <p className="muted small" style={{ margin: 0 }}>
                    Turning it off removes the authenticator and all recovery codes; sign-in goes back to the password alone.
                  </p>
                  <ConfirmForm
                    withCode
                    danger
                    submitLabel="Turn off"
                    pending={disable.isPending}
                    error={disable.error}
                    onSubmit={(password, code) => disable.mutate({ password, code })}
                    onCancel={() => {
                      disable.reset()
                      idle()
                    }}
                  />
                </>
              ) : null}
            </div>
          )}
        </QueryView>
      </div>
    </section>
  )
}
