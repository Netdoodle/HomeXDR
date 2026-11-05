// Mock network visibility: NetFlow intake, device inventory and behaviour detection.

import type { NetFlowStats } from '../api/types'

const NOW = Date.now()
const SEC = 1000
const ago = (ms: number) => new Date(NOW - ms).toISOString()

export const netflowStats: NetFlowStats = {
  enabled: true,
  listening: true,
  addr: ':2055',
  packets: 48213,
  records: 391877,
  dropped: 0,
  refused: 12,
  malformed: 0,
  waiting: 3,
  discarded: 0,
  failed: 0,
  exporters: [{ ip: '192.168.1.1', version: 9, packets: 48213, records: 391877, templates: 2, last_seen: ago(4 * SEC) }],
}
