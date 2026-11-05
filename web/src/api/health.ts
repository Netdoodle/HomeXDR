// Data health: feed health, doctor and self-check. Types and calls in one place, so the
// shared api files stay as they are.

import { http } from './client'

export type FeedStatus = 'ok' | 'silent' | 'learning' | 'never_seen' | 'quiet' | 'muted' | 'host_offline'

export interface FeedView {
  host_id: string
  hostname: string
  /** Module and dataset are empty on the row about the host as a whole. */
  module: string
  dataset: string
  status: FeedStatus
  explanation?: string
  first_seen?: string
  last_seen?: string
  arrivals: number
  usual_gap_sec: number
  allowance_sec: number
  silent_sec: number
  muted: boolean
  expected: boolean
  can_alert: boolean
}

export interface FeedReport {
  sources: FeedView[]
  bootstrapped: boolean
  grace_until?: string
  note?: string
}

export interface FeedPatch {
  host_id: string
  module: string
  dataset: string
  muted?: boolean
  expected?: boolean
}

export const healthKeys = {
  feeds: ['health', 'feeds'] as const,
}

export const getFeeds = () => http.get<FeedReport>('/api/health/feeds')
export const patchFeed = (p: FeedPatch) => http.patch<FeedReport>('/api/health/feeds', p)
