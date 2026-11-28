import type { AuditGap, Host } from '../api/types'

/** Role value the Windows agent reports for a host running Active Directory Domain Services. */
export const DOMAIN_CONTROLLER_ROLE = 'domain_controller'

export function isDomainController(host: Pick<Host, 'roles'>): boolean {
  return (host.roles ?? []).includes(DOMAIN_CONTROLLER_ROLE)
}

/**
 * The auditpol command that turns on what a gap lacks. It uses the subcategory GUID so
 * it works on any display language. HomeXDR never runs it.
 */
export function auditpolFix(gap: Pick<AuditGap, 'guid' | 'wanted'>): string {
  const flag = (on: boolean) => (on ? 'enable' : 'disable')
  const wantsSuccess = gap.wanted.includes('success')
  const wantsFailure = gap.wanted.includes('failure')
  const parts = [`auditpol /set /subcategory:${gap.guid}`]
  if (wantsSuccess) parts.push(`/success:${flag(true)}`)
  if (wantsFailure) parts.push(`/failure:${flag(true)}`)
  return parts.join(' ')
}
