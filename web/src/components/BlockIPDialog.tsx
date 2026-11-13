// "Block this IP everywhere": a confirmation that adds a Global host firewall block, used
// from an alert's Investigate menu.

import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { addFirewallBlock, firewallKeys } from '../api/firewall'
import { blockProblem } from '../lib/firewall'
import { ConfirmDialog } from './Modal'
import { useToast } from './Toast'

export interface BlockRequest {
  address: string
  note: string
  alertId?: string
}

export function BlockIPDialog({ request, onClose }: { request: BlockRequest | null; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [note, setNote] = useState('')
  useEffect(() => setNote(request?.note ?? ''), [request])
  const add = useMutation({
    mutationFn: (r: BlockRequest) => addFirewallBlock({ cidr: r.address, note: note.trim(), alert_id: r.alertId, direction: 'both' }),
    onSuccess: (v) => {
      qc.setQueryData(firewallKeys.status, v)
      toast.success(`${request?.address} is being blocked on every host`)
    },
  })
  const problem = request ? blockProblem(request.address) : null
  return (
    <ConfirmDialog
      open={request !== null}
      onClose={onClose}
      title="Block this IP everywhere"
      confirmLabel="Block everywhere"
      danger
      disabled={!!problem}
      onConfirm={() => (request ? add.mutateAsync(request) : undefined)}
    >
      {request ? (
        <div className="stack" style={{ gap: 12 }}>
          <p style={{ margin: 0 }}>
            Every enrolled host blocks <span className="mono">{request.address}</span> in its own firewall, inbound and outbound: Windows Firewall rules
            in the <span className="mono">HomeXDR</span> group, nftables on Linux, pf on macOS. Groups that turn the host firewall off are left out.
          </p>
          {problem ? <div className="callout danger small">{problem}</div> : null}
          <label className="field">
            <span className="label">Note</span>
            <input className="input" value={note} maxLength={300} onChange={(e) => setNote(e.target.value)} />
          </label>
          <p className="small muted" style={{ margin: 0 }}>
            Remove it any time under <Link to="/settings/firewall">Settings → Firewall</Link>.
          </p>
        </div>
      ) : null}
    </ConfirmDialog>
  )
}
