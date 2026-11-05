// Known-exploited software: helpers for the page.

import type { VulnMatch, VulnReport } from '../api/vuln'

/** Plain sentences saying what data the page is missing. Empty when it has all it needs. */
export function missingData(r: Pick<VulnReport, 'kev' | 'hosts'>): string[] {
  const out: string[] = []
  if (!r.kev.enabled) {
    out.push('The CISA catalog is turned off, so nothing can be compared. Turn it on under Settings → Offline lists.')
  } else if (r.kev.error) {
    out.push(`The CISA catalog could not be downloaded: ${r.kev.error}`)
  } else if (!r.kev.entries) {
    out.push('The CISA catalog has not been downloaded yet. It downloads by itself within a few minutes of the server starting.')
  }
  if (r.hosts.length === 0) out.push('No agents are enrolled. Software lists come from endpoint agents.')
  for (const h of r.hosts) {
    if (h.packages > 0) continue
    out.push(
      h.note
        ? `${h.hostname} has sent no software list. The agent says: ${h.note}`
        : `${h.hostname} has sent no software list. The agent sends one every few hours; if it never does, update the agent.`,
    )
  }
  return out
}

/** A Docker image is labelled as one, so it is not mistaken for a package. */
export function packageLabel(m: Pick<VulnMatch, 'package' | 'package_type'>): string {
  if (m.package_type === 'docker') return `${m.package} (Docker image)`
  if (m.package_type === 'os') return `${m.package} (operating system)`
  return m.package
}
