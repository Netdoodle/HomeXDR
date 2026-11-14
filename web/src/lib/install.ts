// Agent install commands shown after creating an enrollment token (docs/api.md).

import type { ServerSettings } from '../api/types'

/** POSIX single-quote unless the value is made of obviously safe characters. */
export function shellQuote(s: string): string {
  if (/^[A-Za-z0-9._:\/=+@%-]+$/.test(s)) return s
  return `'${s.replace(/'/g, `'"'"'`)}'`
}

/** PowerShell single-quote unless safe. */
export function psQuote(s: string): string {
  if (/^[A-Za-z0-9._:\/=+@%-]+$/.test(s)) return s
  return `'${s.replace(/'/g, "''")}'`
}

/**
 * Normalizes "host", "host:8443" or "https://host:8443/" into "https://host:8443".
 * A missing port becomes `defaultPort` (the agent API's, 8443 unless configured).
 */
export function normalizeAgentUrl(u: string, defaultPort = '8443'): string {
  let s = u.trim().replace(/\/+$/, '')
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s
  try {
    const url = new URL(s)
    if (!url.port && url.protocol === 'https:' && defaultPort !== '443') url.port = defaultPort
    return `${url.protocol}//${url.host}`
  } catch {
    return s
  }
}

/** Candidate agent URLs: the configured agent_url first, then one per server name. */
export function agentUrlOptions(settings: Pick<ServerSettings, 'agent_url' | 'server_names'>): string[] {
  const out: string[] = []
  // Server names get the same port as the configured agent URL.
  let port = '8443'
  try {
    if (settings.agent_url) port = new URL(normalizeAgentUrl(settings.agent_url)).port || '443'
  } catch {
    // keep the default
  }
  const add = (u: string) => {
    const n = normalizeAgentUrl(u, port)
    if (n && !out.includes(n)) out.push(n)
  }
  if (settings.agent_url) add(settings.agent_url)
  for (const name of settings.server_names ?? []) {
    const isBareIPv6 = !name.includes('[') && name.split(':').length > 2
    add(isBareIPv6 ? `[${name}]` : name)
  }
  return out
}

export interface InstallCommands {
  linux: string
  macos: string
  windows: string
}

/** PowerShell single-quoted string literal, always quoted (for use as a value, not an argument). */
export function psLiteral(s: string): string {
  return `'${s.replace(/'/g, "''")}'`
}

/**
 * `updateKey` (the release key from the server settings) turns on signed automatic
 * updates on Linux and macOS. Windows agents cannot update themselves yet, so it is left
 * out there.
 *
 * The Windows command downloads windows.ps1 without checking the certificate (the CA is not
 * trusted yet, like `curl -k` on Linux) and runs it; the script then checks the CA against
 * the pin before it downloads the agent. Windows PowerShell 5.1 needs the
 * ServicePointManager callback, PowerShell 7 has -SkipCertificateCheck.
 */
export function buildInstallCommands(agentUrl: string, token: string, caPin: string, updateKey?: string): InstallCommands {
  const base = normalizeAgentUrl(agentUrl)
  const unix = (script: string) =>
    `curl -fsSLk ${shellQuote(base + '/v1/install/' + script)} | sudo sh -s -- ` +
    `--token ${shellQuote(token)} --ca-pin ${shellQuote(caPin)}` +
    (updateKey ? ` --update-key ${shellQuote(updateKey)}` : '')
  const spm = '[Net.ServicePointManager]'
  const windows =
    `$u=${psLiteral(base + '/v1/install/windows.ps1')}; ` +
    `if ($PSEdition -eq 'Core') { $s=Invoke-RestMethod $u -SkipCertificateCheck } else { ` +
    `${spm}::SecurityProtocol=${spm}::SecurityProtocol -bor 3072; ${spm}::ServerCertificateValidationCallback={$true}; ` +
    `try { $s=(New-Object Net.WebClient).DownloadString($u) } finally { ${spm}::ServerCertificateValidationCallback=$null } }; ` +
    `& ([scriptblock]::Create($s)) -Server ${psQuote(base)} -Token ${psQuote(token)} -CaPin ${psQuote(caPin)}`
  return {
    linux: unix('linux.sh'),
    macos: unix('macos.sh'),
    windows,
  }
}
