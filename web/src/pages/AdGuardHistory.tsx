// One-time import of the lookups AdGuard Home still keeps from before live importing began.

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { adguardKeys, backfillAdGuard, type AdGuardSettings } from '../api/adguard'
import { errorMessage } from '../api/client'
import { Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'
import { formatDateTime } from '../lib/time'

export function HistoryImport({ settings }: { settings: AdGuardSettings }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [confirm, setConfirm] = useState(false)
  const b = settings.backfill
  const run = useMutation({
    mutationFn: backfillAdGuard,
    onSuccess: () => {
      setConfirm(false)
      toast.success('Importing AdGuard Home history')
      qc.invalidateQueries({ queryKey: adguardKeys.settings })
    },
  })
  if (!settings.enabled || !settings.status.since) return null
  const back = b?.oldest ? ` back to ${formatDateTime(b.oldest)}` : ''
  return (
    <div className="stack" style={{ gap: 8 }}>
      {b?.state === 'running' ? (
        <div className="callout small">
          <Spinner /> Importing history: {formatNumber(b.imported)} lookups so far{back}.
        </div>
      ) : b?.state === 'done' ? (
        <div className="callout ok small">History imported{b.imported ? `: ${formatNumber(b.imported)} lookups${back}` : ''}.</div>
      ) : b?.state === 'error' ? (
        <div className="callout danger small">History import stopped: {b.error}</div>
      ) : null}
      {b?.state === 'done' || b?.state === 'running' ? null : confirm ? (
        <div className="callout small stack" style={{ gap: 8 }}>
          <span>
            Import every lookup AdGuard Home still keeps from before {formatDateTime(settings.status.since)}, as far back as its query log retention. They are
            stored as history: detection rules are not run on them, so no alerts are raised. This runs once and can take a while for a large log.
          </span>
          {run.isError ? <span className="danger-text">{errorMessage(run.error)}</span> : null}
          <span className="row" style={{ gap: 8 }}>
            <button className="btn primary small" type="button" disabled={run.isPending} onClick={() => run.mutate()}>
              Import history
            </button>
            <button className="btn small" type="button" onClick={() => setConfirm(false)}>
              Cancel
            </button>
          </span>
        </div>
      ) : (
        <div>
          <button className="btn small" type="button" onClick={() => setConfirm(true)}>
            Import older history…
          </button>
        </div>
      )}
    </div>
  )
}
