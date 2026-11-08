// Human descriptions of response actions, used by confirm dialogs and command history.

import type { CommandRecord, CommandRequest, CommandType, DefenderParams, Host } from '../api/types'

export const COMMAND_LABEL: Record<CommandType, string> = {
  'process.kill': 'Kill process',
  'host.isolate': 'Isolate host',
  'host.release': 'Release host',
  'file.quarantine': 'Quarantine file',
  'file.restore': 'Restore file',
  'file.get': 'Get file',
  'file.hash': 'Hash file',
  'artifact.collect': 'Run artifact',
  'defender.action': 'Defender action',
}

export function commandLabel(type: string): string {
  return COMMAND_LABEL[type as CommandType] ?? type
}

export interface CommandDescription {
  title: string
  /** What will happen, one statement per line. */
  effects: string[]
  confirmLabel: string
  danger: boolean
}

/** Describes exactly what a command will do on `host`, for the confirm dialog. */
export function describeCommand(req: CommandRequest, host: Pick<Host, 'hostname'>): CommandDescription {
  const h = host.hostname
  switch (req.type) {
    case 'process.kill': {
      const p = req.params
      const effects = [
        `Terminate process PID ${p.pid} on ${h}${p.tree ? ' and every process it started' : ''}.`,
        'Unsaved work in the process is lost. This cannot be undone.',
      ]
      if (p.entity_id) effects.push('The agent first checks that the PID still belongs to the same process, so a reused PID is never hit.')
      else effects.push('No process entity ID is attached: if the PID was reused, a different process could be terminated.')
      return { title: `Kill PID ${p.pid} on ${h}?`, effects, confirmLabel: p.tree ? 'Kill process tree' : 'Kill process', danger: true }
    }
    case 'host.isolate': {
      const allow = req.params.allow ?? []
      return {
        title: `Isolate ${h} from the network?`,
        effects: [
          `${h} loses all network access except to the HomeXDR server, loopback, DHCP and DNS.`,
          allow.length ? `Also allowed: ${allow.join(', ')}.` : 'No extra addresses are allowed.',
          'Users on the host are disconnected from file shares, the internet and remote sessions until you release it.',
        ],
        confirmLabel: 'Isolate host',
        danger: true,
      }
    }
    case 'host.release':
      return {
        title: `Release ${h} from isolation?`,
        effects: [`Normal network access is restored on ${h}.`],
        confirmLabel: 'Release host',
        danger: false,
      }
    case 'file.quarantine':
      return {
        title: `Quarantine a file on ${h}?`,
        effects: [
          `The agent moves ${req.params.path} into its quarantine folder and removes it from the original location.`,
          'Programs that depend on the file stop working. It can be restored later with its quarantine ID.',
        ],
        confirmLabel: 'Quarantine file',
        danger: true,
      }
    case 'file.restore':
      return {
        title: `Restore a quarantined file on ${h}?`,
        effects: [`The file with quarantine ID ${req.params.id} is moved back to its original path on ${h}.`],
        confirmLabel: 'Restore file',
        danger: false,
      }
    case 'file.get':
      return {
        title: `Fetch a file from ${h}?`,
        effects: [
          `The agent uploads a copy of ${req.params.path} to the HomeXDR server${
            req.params.max_bytes ? ` (at most ${req.params.max_bytes.toLocaleString('en')} bytes)` : ' (at most 100 MiB)'
          }.`,
          'The file on the host is not changed. Anyone with console access can download the copy.',
        ],
        confirmLabel: 'Get file',
        danger: false,
      }
    case 'file.hash':
      return {
        title: `Hash a file on ${h}?`,
        effects: [`The agent reads ${req.params.path} and reports its size, MD5, SHA-1 and SHA-256. The file is not changed.`],
        confirmLabel: 'Hash file',
        danger: false,
      }
    case 'artifact.collect': {
      const params = Object.entries(req.params.params ?? {})
      return {
        title: `Run ${req.params.name} on ${h}?`,
        effects: [
          `The agent runs the built-in read-only collector ${req.params.name} and uploads its rows.`,
          params.length ? `Parameters: ${params.map(([k, v]) => `${k}=${v}`).join(', ')}.` : 'Default parameters.',
        ],
        confirmLabel: 'Run artifact',
        danger: false,
      }
    }
    case 'defender.action':
      return describeDefender(req.params, h)
  }
}

function describeDefender(p: DefenderParams, h: string): CommandDescription {
  switch (p.action) {
    case 'status':
      return { title: `Read Defender status on ${h}?`, effects: ['The agent reports whether protection is on, the signature version and the threats Defender knows. Nothing changes.'], confirmLabel: 'Read status', danger: false }
    case 'scan':
      if (p.scan_type === 'path')
        return { title: `Scan a file with Defender on ${h}?`, effects: [`Defender scans ${p.path ?? ''} and handles anything it finds per its own settings.`], confirmLabel: 'Scan file', danger: false }
      return {
        title: `Start a Defender ${p.scan_type} scan on ${h}?`,
        effects: [`Defender starts a ${p.scan_type} scan in the background${p.scan_type === 'full' ? ' (this can take hours and slows the PC)' : ''}. Detections show up as alerts.`],
        confirmLabel: `Start ${p.scan_type} scan`,
        danger: false,
      }
    case 'update':
      return { title: `Update Defender signatures on ${h}?`, effects: ['Defender downloads its latest signatures now.'], confirmLabel: 'Update signatures', danger: false }
    case 'remove_threats':
      return { title: `Remove all active threats on ${h}?`, effects: ['Defender cleans every threat it currently lists as active.'], confirmLabel: 'Remove threats', danger: true }
    case 'allow_threat':
      return {
        title: `Allow threat ${p.threat_id} on ${h}?`,
        effects: [
          `Defender stops acting on threat ID ${p.threat_id} on this host and restores its files from quarantine.`,
          'Only do this for a false positive: real malware would be allowed to run.',
        ],
        confirmLabel: 'Allow threat',
        danger: true,
      }
    case 'block_threat':
      return {
        title: `Block threat ${p.threat_id} again on ${h}?`,
        effects: [`Defender quarantines threat ID ${p.threat_id} again when it finds it (undoes an earlier allow).`],
        confirmLabel: 'Block threat',
        danger: false,
      }
  }
}

/** Short one-line description of a command's params for history tables. */
export function commandParamsSummary(c: Pick<CommandRecord, 'type' | 'params'>): string {
  const p = (c.params ?? {}) as Record<string, unknown>
  switch (c.type) {
    case 'process.kill':
      return `PID ${String(p.pid ?? '?')}${p.tree ? ' (tree)' : ''}`
    case 'host.isolate':
      return Array.isArray(p.allow) && p.allow.length ? `allow ${p.allow.join(', ')}` : ''
    case 'file.quarantine':
    case 'file.get':
    case 'file.hash':
      return String(p.path ?? '')
    case 'file.restore':
      return `id ${String(p.id ?? '')}`
    case 'defender.action':
      return [p.action, p.scan_type, p.path, p.threat_id].filter((x) => x !== undefined && x !== '').map(String).join(' ')
    case 'artifact.collect': {
      const params = p.params && typeof p.params === 'object' ? Object.entries(p.params as Record<string, string>) : []
      return `${String(p.name ?? '')}${params.length ? ' ' + params.map(([k, v]) => `${k}=${v}`).join(' ') : ''}`
    }
    default:
      return ''
  }
}

/** Whether a host's local policy allows a command type (unknown policy = allowed). */
export function actionAllowed(host: Pick<Host, 'allowed_actions' | 'kind' | 'status'>, type: CommandType): boolean {
  if (host.kind === 'network' || host.status === 'revoked') return false
  if (!host.allowed_actions) return true
  return host.allowed_actions.includes(type)
}
