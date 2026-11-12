// Inbound threats: internet sources trying to reach the firewall.

import { http } from './client'

export interface InboundCountry {
  code: string
  attempts: number
  sources: number
  allowed: number
}

export interface InboundSource {
  ip: string
  country?: string
  asn?: number
  as_name?: string
  attempts: number
  allowed: number
  ports: number
  first: string
  last: string
}

export interface InboundNetwork {
  asn: number
  name: string
  country?: string
  attempts: number
  sources: number
}

export interface InboundPort {
  port: number
  transport: string
  attempts: number
  sources: number
}

export interface InboundView {
  hours: number
  span_sec: number
  attempts: number
  blocked: number
  allowed: number
  sources: number
  countries: InboundCountry[]
  top_sources: InboundSource[]
  allowed_sources: InboundSource[]
  networks: InboundNetwork[]
  ports: InboundPort[]
  timeline: { t: string; blocked: number; allowed: number; sources: number }[]
  prev_attempts: number
  prev_blocked: number
  prev_sources: number
  no_geo?: boolean
  truncated?: boolean
}

export const inboundKeys = { view: (hours: number) => ['stats', 'inbound', hours] as const }

export const getInbound = (hours: number) => http.get<InboundView>(`/api/stats/inbound?hours=${hours}`)

export type InboundKind = 'all' | 'blocked' | 'allowed'

export interface InboundEvents {
  events: import('./types').Event[]
  total: number
  sources: number
  /** The same selection as a Search query; absent when it names too many addresses. */
  query?: string
}

export const getInboundEvents = (hours: number, country: string, kind: InboundKind, offset = 0) =>
  http.get<InboundEvents>(`/api/stats/inbound/events?hours=${hours}&country=${encodeURIComponent(country)}&kind=${kind}&offset=${offset}`)
