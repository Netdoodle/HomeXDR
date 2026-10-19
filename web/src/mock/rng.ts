// Deterministic pseudo-random helpers so fixtures look the same on every load.

export function mulberry32(seed: number) {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export const rand = mulberry32(0x5eed)

export function pick<T>(xs: readonly T[], r: () => number = rand): T {
  return xs[Math.floor(r() * xs.length)]
}

export function int(lo: number, hi: number, r: () => number = rand): number {
  return lo + Math.floor(r() * (hi - lo + 1))
}

const B32 = '0123456789abcdefghjkmnpqrstvwxyz'

/** Wall-clock time the fixtures are generated relative to. */
export const NOW = Date.now()
// IDs encode time relative to a fixed epoch instead of NOW, so fixture IDs (and URLs
// that contain them) stay the same across page reloads.
const ID_EPOCH = Date.UTC(2026, 0, 1)

/** 26-char, time-ordered, lowercase Crockford base32 ID (same shape as event.NewID). */
export function makeId(ms: number, r: () => number = rand): string {
  let out = ''
  let t = Math.max(0, Math.floor(ms - NOW + ID_EPOCH))
  const time: string[] = []
  for (let i = 0; i < 10; i++) {
    time.unshift(B32[t % 32])
    t = Math.floor(t / 32)
  }
  out = time.join('')
  for (let i = 0; i < 16; i++) out += B32[Math.floor(r() * 32)]
  return out
}

export function hex(n: number, r: () => number = rand): string {
  let s = ''
  for (let i = 0; i < n; i++) s += '0123456789abcdef'[Math.floor(r() * 16)]
  return s
}
