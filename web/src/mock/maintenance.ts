// Mock Settings → Maintenance.

import type { MaintenanceInput, MaintenanceView } from '../api/maintenance'
import type { Role } from '../api/types'

type Ctx = { params: Record<string, string>; body: unknown }
type Route = (method: string, path: string, handler: (c: Ctx) => unknown, opts?: { role?: Role }) => void

const ago = (ms: number) => new Date(Date.now() - ms).toISOString()

const view: MaintenanceView = {
  days: 30,
  container_start_minutes: 5,
  ssh_keys: [
    {
      fingerprint: 'SHA256:WaETwa68OJhBShgClfIkGSkFhB7ppvxZJJ03HcZ4zoI',
      name: '',
      maintenance: false,
      logins: 212,
      last_login: ago(4 * 60_000),
      users: ['root'],
      hosts: ['Tower2'],
      sources: ['192.168.10.52'],
      suppressed: 0,
    },
    {
      fingerprint: 'SHA256:CbPtkGqAGFaaH0z/4IqYEnoLzKAIbUcg7YUvw6haT+A',
      name: '',
      maintenance: false,
      logins: 64,
      last_login: ago(3 * 3600_000),
      users: ['hxadmin'],
      hosts: ['WIN-SN24A9KD4DM'],
      sources: ['192.168.10.52'],
      suppressed: 0,
    },
  ],
  sources: [
    { id: 'docker-update', title: 'Docker container updates', help: "Commands started by Unraid's Docker manager or the CA Auto Update plugin while they update, create or start containers.", maintenance: false, suppressed: 0 },
    { id: 'appdata-backup', title: 'Appdata backup', help: 'Commands started by the appdata backup plugin, which stops every container, backs it up and starts it again.', maintenance: false, suppressed: 0 },
    { id: 'container-start', title: 'Container start-up', help: "Everything a container runs in its first minutes after HomeXDR first sees it: a new or updated container's init scripts.", maintenance: false, suppressed: 0 },
  ],
}

export function maintenanceRoutes(route: Route, fail: (status: number, message: string) => never) {
  route('GET', '/api/settings/maintenance', () => view)
  route(
    'PUT',
    '/api/settings/maintenance',
    ({ body }) => {
      const m = body as MaintenanceInput
      for (const k of m.ssh_keys) {
        if (k.maintenance && !k.name.trim()) fail(400, 'name the key before using it for maintenance')
        const cur = view.ssh_keys.find((x) => x.fingerprint === k.fingerprint)
        if (cur) Object.assign(cur, { name: k.name.trim(), maintenance: k.maintenance, expires_at: k.maintenance ? k.expires_at : undefined, suppression_id: k.maintenance ? 'sup-' + k.fingerprint.slice(7, 13) : undefined })
      }
      for (const s of m.sources) {
        const cur = view.sources.find((x) => x.id === s.id)
        if (cur) Object.assign(cur, { maintenance: s.maintenance, expires_at: s.maintenance ? s.expires_at : undefined, suppression_id: s.maintenance ? 'sup-' + s.id : undefined })
      }
      view.container_start_minutes = m.container_start_minutes || 5
      return view
    },
    { role: 'admin' },
  )
}
