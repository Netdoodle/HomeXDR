import { describe, expect, it } from 'vitest'
import { auditpolFix, isDomainController } from './domainController'

describe('domain controller helpers', () => {
  it('detects the role', () => {
    expect(isDomainController({ roles: ['domain_controller'] })).toBe(true)
    expect(isDomainController({ roles: [] })).toBe(false)
    expect(isDomainController({})).toBe(false)
  })

  it('builds auditpol fixes from the GUID and the wanted outcomes', () => {
    const guid = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    expect(auditpolFix({ guid, wanted: 'success and failure' })).toBe(`auditpol /set /subcategory:${guid} /success:enable /failure:enable`)
    expect(auditpolFix({ guid, wanted: 'success' })).toBe(`auditpol /set /subcategory:${guid} /success:enable`)
  })
})
