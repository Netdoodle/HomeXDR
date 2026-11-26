// Permanently removing a host: type its name and give a fresh authenticator code.

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, queryKeys, type Host } from '../api'
import { ConfirmDialog } from './Modal'
import { useToast } from './Toast'
import { Icon } from './Icon'

export function RemoveHostDialog({ host, open, onClose }: { host: Pick<Host, 'id' | 'hostname' | 'kind'>; open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [code, setCode] = useState('')
  const totp = useQuery({ queryKey: queryKeys.totp, queryFn: api.totpStatus, enabled: open })

  useEffect(() => {
    if (open) {
      setName('')
      setCode('')
    }
  }, [open])

  const nameOk = name.trim().toLowerCase() === host.hostname.toLowerCase()
  const codeOk = /^\d{6}$/.test(code.replace(/\s+/g, ''))
  const noTotp = totp.data !== undefined && !totp.data.enabled

  return (
    <ConfirmDialog
      open={open}
      onClose={onClose}
      title={`Remove ${host.hostname}?`}
      danger
      confirmLabel="Remove host permanently"
      disabled={!nameOk || !codeOk || noTotp}
      onConfirm={async () => {
        await api.removeHost(host.id, code.replace(/\s+/g, ''), name.trim())
        qc.removeQueries({ queryKey: queryKeys.host(host.id) })
        qc.invalidateQueries({ queryKey: queryKeys.hosts() })
        toast.success(`${host.hostname} removed`)
        navigate('/hosts')
      }}
    >
      <p>This cannot be undone. It will:</p>
      <ul className="effect-list">
        <li>Delete {host.hostname} from HomeXDR with its command history, uploaded files, vulnerability findings and group membership.</li>
        <li>Keep the events and alerts already stored; alerts still show the host name.</li>
        {host.kind === 'endpoint' ? (
          <li>Make the agent&apos;s certificate useless: it is refused on its next connection and cannot bring the host back. To monitor the machine again, reinstall the agent and enroll it with a new token.</li>
        ) : (
          <li>Remove the device from the list. If it keeps sending syslog it will show up again as a new device.</li>
        )}
      </ul>
      {noTotp ? (
        <div className="callout warn" style={{ marginTop: 12 }}>
          <Icon name="warning" size={14} />
          <span>
            Removing a host needs two-factor authentication. <Link to="/settings/account">Set it up on your account</Link> first.
          </span>
        </div>
      ) : null}
      <div className="stack" style={{ gap: 10, marginTop: 14 }}>
        <div className="field">
          <label htmlFor="rm-name">
            Type <span className="mono">{host.hostname}</span> to confirm
          </label>
          <input
            id="rm-name"
            className="input mono"
            autoComplete="off"
            spellCheck={false}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="field">
          <label htmlFor="rm-code">Authenticator code</label>
          <input
            id="rm-code"
            className="input mono"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={7}
            placeholder="123456"
            style={{ maxWidth: 140 }}
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <span className="help">The 6-digit code from your authenticator app. A code can be used once; recovery codes do not work here.</span>
        </div>
      </div>
    </ConfirmDialog>
  )
}
