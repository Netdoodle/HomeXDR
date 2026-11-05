// Settings → Offline lists: which public lists are downloaded, and how they are doing.

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { errorMessage } from '../api/client'
import { getLists, listsKey, refreshList, setListEnabled, type OfflineList } from '../api/lists'
import { Icon } from '../components/Icon'
import { RelTime, Toggle } from '../components/Misc'
import { QueryView, Spinner } from '../components/States'
import { useToast } from '../components/Toast'
import { formatNumber } from '../lib/format'

export function OfflineListsTab() {
  const q = useQuery({
    queryKey: listsKey,
    queryFn: getLists,
    refetchInterval: (query) => (query.state.data?.lists.some((l) => l.updating) ? 2000 : false),
  })
  return (
    <div className="stack" style={{ maxWidth: 1100 }}>
      <p className="small muted" style={{ margin: 0 }}>
        These public lists are downloaded ahead of time. Looking something up in them never touches the network, so nothing about your network leaves this server. They add facts to Investigate
        and to alerts. A download that fails or looks wrong changes nothing: the last good copy stays in use.
      </p>
      <section className="panel">
        <QueryView query={q}>
          {(d) => (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>List</th>
                    <th>On</th>
                    <th>Last update</th>
                    <th className="num">Entries</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {d.lists.map((l) => (
                    <ListRow key={l.id} list={l} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryView>
      </section>
    </div>
  )
}

function ListRow({ list: l }: { list: OfflineList }) {
  const qc = useQueryClient()
  const toast = useToast()
  const onDone = () => qc.invalidateQueries({ queryKey: listsKey })
  const onError = (e: unknown) => toast.error(errorMessage(e))
  const toggle = useMutation({ mutationFn: (on: boolean) => setListEnabled(l.id, on), onSuccess: onDone, onError })
  const refresh = useMutation({ mutationFn: () => refreshList(l.id), onSuccess: onDone, onError })
  return (
    <tr>
      <td style={{ whiteSpace: 'normal', minWidth: 340 }}>
        <div>
          <a href={l.site_url} target="_blank" rel="noreferrer">
            {l.name}
          </a>
        </div>
        <div className="xsmall muted">{l.about}</div>
        <div className="xsmall muted">
          Licence: {l.license}
          {l.license_url ? (
            <>
              {' '}
              <a href={l.license_url} target="_blank" rel="noreferrer">
                Read the terms
              </a>
            </>
          ) : null}
        </div>
        {l.warning ? <div className="xsmall">{l.warning}</div> : null}
        {l.error ? (
          <div className="xsmall" style={{ color: 'var(--danger)' }}>
            Last error: {l.error}
          </div>
        ) : null}
      </td>
      <td>
        <Toggle checked={l.enabled} disabled={toggle.isPending} label={`Use ${l.name}`} onChange={(on) => toggle.mutate(on)} />
      </td>
      <td className="nowrap">{l.last_update ? <RelTime iso={l.last_update} /> : <span className="empty-cell">Never</span>}</td>
      <td className="num">{l.entries ? formatNumber(l.entries) : '—'}</td>
      <td>
        <button type="button" className="btn" disabled={l.updating || refresh.isPending || !l.enabled} onClick={() => refresh.mutate()} title={l.enabled ? 'Check for a new copy now' : 'Turn this list on first'}>
          {l.updating ? <Spinner /> : <Icon name="refresh" size={14} />} {l.updating ? 'Updating…' : 'Refresh'}
        </button>
      </td>
    </tr>
  )
}
