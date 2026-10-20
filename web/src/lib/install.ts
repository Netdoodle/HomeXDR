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
  windows: string
}

/**
 * `updateKey` (the release key from the server settings) turns on signed automatic
 * updates on Linux. Windows agents cannot update themselves yet, so it is left out there.
 */
export function buildInstallCommands(agentUrl: string, token: string, caPin: string, updateKey?: string): InstallCommands {
  const base = normalizeAgentUrl(agentUrl)
  return {
    linux:
      `curl -fsSLk ${shellQuote(base + '/v1/install/linux.sh')} | sudo sh -s -- ` +
      `--token ${shellQuote(token)} --ca-pin ${shellQuote(caPin)}` +
      (updateKey ? ` --update-key ${shellQuote(updateKey)}` : ''),
    windows:
      `homexdr-agent.exe install --server ${psQuote(base)} ` + `--token ${psQuote(token)} --ca-pin ${psQuote(caPin)}`,
  }
}
