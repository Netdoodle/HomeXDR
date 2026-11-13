import { describe, expect, it } from 'vitest'
import { alertBlockNote, blockProblem } from './firewall'

describe('blockProblem', () => {
  it('accepts addresses and narrow enough networks', () => {
    for (const ok of ['203.0.113.7', ' 203.0.113.0/24 ', '10.0.0.0/8', '2001:db8::1', '2001:db8::/32', '192.168.1.50']) {
      expect(blockProblem(ok), ok).toBeNull()
    }
  })

  it('refuses networks that are too broad', () => {
    expect(blockProblem('0.0.0.0/0')).toMatch(/Too broad/)
    expect(blockProblem('8.0.0.0/7')).toMatch(/Too broad/)
    expect(blockProblem('::/0')).toMatch(/Too broad/)
    expect(blockProblem('2001:db8::/31')).toMatch(/Too broad/)
  })

  it('refuses ranges that are never blocked', () => {
    expect(blockProblem('127.0.0.1')).toMatch(/Loopback/)
    expect(blockProblem('::1')).toMatch(/Loopback/)
    expect(blockProblem('169.254.1.1')).toMatch(/Link-local/)
    expect(blockProblem('fe80::1')).toMatch(/Link-local/)
    expect(blockProblem('224.0.0.251')).toMatch(/Multicast/)
    expect(blockProblem('ff02::fb')).toMatch(/Multicast/)
    expect(blockProblem('255.255.255.255')).toMatch(/broadcast/)
    expect(blockProblem('0.1.2.3')).toMatch(/unspecified/)
  })

  it('refuses things that are not addresses', () => {
    for (const bad of ['', 'example.com', '1.2.3', '1.2.3.256', '203.0.113.0/33', '1.2.3.4/x', '1::2::3', '1.2.3.4/24/1']) {
      expect(blockProblem(bad), bad).not.toBeNull()
    }
  })
})

describe('alertBlockNote', () => {
  it('names the alert', () => {
    expect(alertBlockNote({ id: 'a1', rule: { title: 'Beacon to known C2' }, hostname: 'desk' })).toBe('Alert: Beacon to known C2 on desk (a1)')
  })
  it('stays within the note limit', () => {
    expect(alertBlockNote({ id: 'a1', rule: { title: 'x'.repeat(400) } }).length).toBe(300)
  })
})
