// Data health: labels and small helpers.

import type { FeedStatus, FeedView } from '../api/health'

export const FEED_STATUS_LABEL: Record<FeedStatus, string> = {
  ok: 'OK',
  silent: 'Silent',
  learning: 'Learning',
  never_seen: 'Never seen',
  quiet: 'Quiet feed',
  muted: 'Muted',
  host_offline: 'Host offline',
}

/** Uses the alert status badge colours: red-ish for problems, amber for waiting, green for fine. */
export const FEED_STATUS_BADGE: Record<FeedStatus, string> = {
  ok: 'resolved',
  silent: 'new',
  learning: 'false_positive',
  never_seen: 'in_progress',
  quiet: 'false_positive',
  muted: 'false_positive',
  host_offline: 'in_progress',
}

const STATUS_ORDER: FeedStatus[] = ['silent', 'host_offline', 'never_seen', 'learning', 'quiet', 'ok', 'muted']

/** Problems first, then by host and source. */
export function sortFeeds(list: FeedView[]): FeedView[] {
  const rank = (s: FeedStatus) => STATUS_ORDER.indexOf(s)
  return [...list].sort(
    (a, b) => rank(a.status) - rank(b.status) || a.hostname.localeCompare(b.hostname) || a.dataset.localeCompare(b.dataset),
  )
}

export function feedName(f: Pick<FeedView, 'dataset' | 'module'>): string {
  return f.dataset || f.module || 'Anything from this host'
}

/** A gap as a person would say it: 45 s, 12 min, 6 h, 3 d. */
export function formatGap(sec: number | undefined | null): string {
  if (!sec || sec <= 0) return '—'
  if (sec < 60) return 'under a minute'
  if (sec < 3600) return `${Math.round(sec / 60)} min`
  if (sec < 48 * 3600) return `${Math.round(sec / 3600)} h`
  return `${Math.round(sec / 86400)} d`
}
