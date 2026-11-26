import { describe, expect, it } from 'vitest'
import { filterProcs, sortProcs, toProcRows } from './processPicker'

const rows = [
  { pid: 4, ppid: 0, name: 'System', user: 'SYSTEM', start: '2026-11-20T08:00:00Z' },
  { pid: 812, ppid: 4, entity_id: 'e-812', name: 'svchost.exe', executable: 'C:\\Windows\\System32\\svchost.exe', command_line: 'svchost.exe -k netsvcs', user: 'SYSTEM', start: '2026-11-20T08:00:05Z' },
  { pid: 7712, ppid: 812, entity_id: 'e-7712', name: '', executable: 'C:\\Users\\alex\\AppData\\evil.exe', command_line: 'evil.exe --beacon', user: 'alex', start: '2026-11-26T10:00:00Z' },
  { pid: 0, name: 'Idle' },
  { pid: 'x', name: 'broken' },
]

describe('toProcRows', () => {
  it('drops rows without a usable PID and counts children', () => {
    const p = toProcRows(rows)
    expect(p.map((x) => x.pid)).toEqual([4, 812, 7712])
    expect(p.find((x) => x.pid === 4)!.children).toBe(1)
    expect(p.find((x) => x.pid === 812)!.children).toBe(1)
    expect(p.find((x) => x.pid === 7712)!.children).toBe(0)
  })
  it('falls back to the executable file name when the name is empty', () => {
    expect(toProcRows(rows).find((x) => x.pid === 7712)!.name).toBe('evil.exe')
  })
})

describe('filterProcs', () => {
  const p = toProcRows(rows)
  it('matches every word across name, PID, user and command line', () => {
    expect(filterProcs(p, 'beacon alex').map((x) => x.pid)).toEqual([7712])
    expect(filterProcs(p, '812').map((x) => x.pid)).toEqual([812])
    expect(filterProcs(p, 'SVCHOST').map((x) => x.pid)).toEqual([812])
    expect(filterProcs(p, '  ')).toHaveLength(3)
  })
})

describe('sortProcs', () => {
  const p = toProcRows(rows)
  it('sorts by name case-insensitively, and by PID, user or start', () => {
    expect(sortProcs(p, 'name').map((x) => x.name)).toEqual(['evil.exe', 'svchost.exe', 'System'])
    expect(sortProcs(p, 'pid', true).map((x) => x.pid)).toEqual([7712, 812, 4])
    expect(sortProcs(p, 'user').map((x) => x.pid)).toEqual([7712, 812, 4])
    expect(sortProcs(p, 'start', true)[0].pid).toBe(7712)
  })
})
