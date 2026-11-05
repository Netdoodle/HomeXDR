// Devices: what is on the home network, and how the behaviour detectors are doing.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useMemo, useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { errorMessage } from '../api/client'
import { listDevices, networkKeys, patchDevice, type Device, type DeviceList, type DevicePatch } from '../api/network'
import { useCan } from '../components/Auth'
import { PageHeader } from '../components/Layout'
import { RelTime, Toggle } from '../components/Misc'
import { Modal } from '../components/Modal'
import { EmptyState, ErrorState, Loading, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { plural } from '../lib/format'
import { useDocumentTitle, useUrlState } from '../lib/hooks'
import { addressSearchHref, deviceName, filterDevices, SOURCE_LABEL, sortDevices, type DeviceFilter, type DeviceSort } from '../lib/network'
import { formatDateTime } from '../lib/time'
import { BehaviorPanel } from './BehaviorPanel'

export function DevicesPage() {
  useDocumentTitle('Devices')
  const [sp, patch] = useUrlState()
  const q = useQuery({ queryKey: networkKeys.devices, queryFn: listDevices, refetchInterval: 30_000 })
  const [editing, setEditing] = useState<string | null>(null)
  const canEdit = useCan('analyst')
  const text = sp.get('q') ?? ''
  const filter = (sp.get('show') ?? '') as DeviceFilter
  const sort = (sp.get('sort') || 'last_seen') as DeviceSort
  const rows = useMemo(() => sortDevices(filterDevices(q.data?.devices ?? [], text, filter), sort), [q.data, text, filter, sort])
  const current = q.data?.devices.find((d) => d.id === editing)
  return (
    <>
      <PageHeader
        title="Devices"
        subtitle={q.data ? plural(q.data.total, 'device') : 'What is on your network'}
        actions={
          <>
            {q.isFetching && !q.isPending ? <Spinner small /> : null}
            <Link className="btn" to="/settings/network">
              Network settings
            </Link>
          </>
        }
      />
      <div className="stack">
        {q.data?.learning ? <LearningNote until={q.data.learning_until} /> : null}
        <div className="filters">
          <input type="search" className="input" placeholder="Name, address, MAC, vendor or note" value={text} onChange={(e) => patch({ q: e.target.value })} aria-label="Filter devices" />
          <select className="select" value={filter} onChange={(e) => patch({ show: e.target.value })} aria-label="Show">
            <option value="">All devices</option>
            <option value="new">New</option>
            <option value="known">Marked as known</option>
            <option value="unknown">Not marked as known</option>
          </select>
          <select className="select" value={sort} onChange={(e) => patch({ sort: e.target.value === 'last_seen' ? '' : e.target.value })} aria-label="Sort">
            <option value="last_seen">Last seen</option>
            <option value="first_seen">Newest first</option>
            <option value="name">Name</option>
            <option value="ip">Address</option>
          </select>
        </div>
        <section className="panel">
          {q.isPending ? (
            <Loading />
          ) : q.isError ? (
            <ErrorState error={q.error} onRetry={() => q.refetch()} />
          ) : q.data.total === 0 ? (
            <EmptyState title="No devices yet">Devices appear as firewall logs, DHCP, DNS or NetFlow mention them. See docs/network-visibility.md for what to turn on.</EmptyState>
          ) : rows.length === 0 ? (
            <EmptyState title="No devices match these filters" />
          ) : (
            <DeviceTable rows={rows} canEdit={canEdit} onEdit={setEditing} />
          )}
        </section>
        {q.data?.overflow ? (
          <div className="callout warn">The inventory is full, and {q.data.overflow} addresses were ignored. Narrow the home subnets under Settings → Network.</div>
        ) : null}
        <BehaviorPanel />
      </div>
      {current ? <DeviceDialog device={current} canEdit={canEdit} onClose={() => setEditing(null)} /> : null}
    </>
  )
}

function LearningNote({ until }: { until: string }) {
  return (
    <div className="callout info" role="status">
      Learning until {formatDateTime(until)}. Devices seen until then count as normal, so no new-device alerts go out yet.
    </div>
  )
}

function DeviceTable({ rows, canEdit, onEdit }: { rows: Device[]; canEdit: boolean; onEdit: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table className="table" style={{ minWidth: 900 }}>
        <thead>
          <tr>
            <th>Device</th>
            <th>Address</th>
            <th>MAC</th>
            <th>Seen by</th>
            <th>First seen</th>
            <th>Last seen</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr key={d.id}>
              <td>
                <button type="button" className="btn ghost sm" style={{ padding: 0, height: 'auto' }} onClick={() => onEdit(d.id)}>
                  {deviceName(d)}
                </button>
                <span className="row" style={{ gap: 4, display: 'inline-flex', marginLeft: 6 }}>
                  {d.new ? <span className="tag">new</span> : null}
                  {d.known ? <span className="tag">known</span> : null}
                  {d.mac ? null : <span className="tag" title="Only an address so far. DHCP logs would link it to a MAC and a name.">no MAC yet</span>}
                </span>
                {d.name && d.hostname && d.name !== d.hostname ? <div className="xsmall muted">{d.hostname}</div> : null}
                {d.host_id ? (
                  <div className="xsmall">
                    <Link to={`/hosts/${encodeURIComponent(d.host_id)}`}>Agent: {d.host_name || d.host_id}</Link>
                  </div>
                ) : null}
                {d.note ? <div className="xsmall muted">{d.note}</div> : null}
              </td>
              <td className="small">
                {d.ip ? <span className="mono">{d.ip}</span> : <span className="muted">none now</span>}
                {d.subnet ? <div className="xsmall muted">{d.subnet}</div> : null}
              </td>
              <td className="small">
                {d.mac ? <span className="mono">{d.mac}</span> : <span className="muted">—</span>}
                {d.vendor ? <div className="xsmall muted">{d.vendor}</div> : null}
                {d.randomized_mac ? <div className="xsmall muted">Randomized</div> : null}
              </td>
              <td className="small">
                {d.sources.map((s) => (
                  <span key={s} className="tag" style={{ marginRight: 4 }}>
                    {SOURCE_LABEL[s] ?? s}
                  </span>
                ))}
              </td>
              <td className="small">
                <RelTime iso={d.first_seen} />
              </td>
              <td className="small">
                <RelTime iso={d.last_seen} />
              </td>
              <td className="right small" style={{ whiteSpace: 'nowrap' }}>
                {d.ip ? <Link to={addressSearchHref(d.ip)}>Events</Link> : null}
                {canEdit ? (
                  <button type="button" className="btn ghost sm" style={{ marginLeft: 8 }} onClick={() => onEdit(d.id)}>
                    Edit
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DeviceDialog({ device, canEdit, onClose }: { device: Device; canEdit: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const toast = useToast()
  const [name, setName] = useState(device.name ?? '')
  const [note, setNote] = useState(device.note ?? '')
  const [known, setKnown] = useState(device.known)
  const save = useMutation({
    mutationFn: (p: DevicePatch) => patchDevice(device.id, p),
    onSuccess: (d) => {
      qc.setQueryData<DeviceList>(networkKeys.devices, (old) => (old ? { ...old, devices: old.devices.map((x) => (x.id === d.id ? d : x)) } : old))
      toast.success('Device saved')
      onClose()
    },
  })
  const submit = (e: FormEvent) => {
    e.preventDefault()
    save.mutate({ name, note, known })
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={deviceName(device)}
      footer={
        <>
          <button type="button" className="btn ghost" onClick={onClose}>
            {canEdit ? 'Cancel' : 'Close'}
          </button>
          {canEdit ? (
            <button type="submit" form="device-form" className="btn primary" disabled={save.isPending}>
              {save.isPending ? <Spinner small /> : null} Save
            </button>
          ) : null}
        </>
      }
    >
      <form id="device-form" className="stack" onSubmit={submit}>
        {device.dest_only ? (
          <div className="callout">This address has only received traffic and has not sent any. A sweep of a subnet produces records like this, so it may not be a real device.</div>
        ) : null}
        {canEdit ? (
          <>
            <label className="field">
              <span className="label">Name</span>
              <input className="input" maxLength={128} value={name} onChange={(e) => setName(e.target.value)} placeholder={device.hostname ?? 'Kitchen camera'} />
              <span className="help">Your name for it, used in alerts about this device.</span>
            </label>
            <label className="field">
              <span className="label">Note</span>
              <textarea className="textarea" rows={2} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <div className="field">
              <label className="row small" style={{ gap: 8 }}>
                <Toggle checked={known} onChange={setKnown} label="This device is known" />
                I know this device
              </label>
              <span className="help">A known device no longer shows as new.</span>
            </div>
          </>
        ) : null}
        {save.isError ? <div className="callout danger">{errorMessage(save.error)}</div> : null}
        <dl className="small" style={{ margin: 0 }}>
          <dt className="muted">Names it has given</dt>
          <dd style={{ margin: '0 0 8px' }}>{device.hostnames?.length ? device.hostnames.join(', ') : 'None'}</dd>
          <dt className="muted">MAC addresses</dt>
          <dd className="mono" style={{ margin: '0 0 8px' }}>
            {device.macs?.length ? device.macs.join(', ') : 'None known'}
          </dd>
          <dt className="muted">Addresses it has used</dt>
          <dd style={{ margin: 0 }}>
            {device.ips.map((i) => (
              <div key={i.ip}>
                <Link className="mono" to={addressSearchHref(i.ip)}>
                  {i.ip}
                </Link>{' '}
                <span className="muted">
                  last seen <RelTime iso={i.last_seen} />
                </span>
              </div>
            ))}
          </dd>
        </dl>
      </form>
    </Modal>
  )
}
