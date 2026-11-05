// What the offline lists say about an indicator, as short plain phrases.

import { useQuery } from '@tanstack/react-query'
import { lookupOffline, type OfflineFacts as Facts } from '../api/lists'
import { factPhrases } from '../lib/lists'

export function OfflineFacts({ facts }: { facts?: Facts | null }) {
  const phrases = factPhrases(facts)
  if (!phrases.length) return null
  return <div className="xsmall muted">{phrases.join(' · ')}</div>
}

/** Looks one indicator up in the offline lists. This stays on the server: nothing goes to the internet. */
export function IndicatorFacts({ value }: { value: string }) {
  const q = useQuery({ queryKey: ['lists', 'lookup', value], queryFn: () => lookupOffline([value]), staleTime: 5 * 60_000 })
  return <OfflineFacts facts={q.data?.results[value]} />
}
