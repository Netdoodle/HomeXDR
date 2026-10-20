/**
 * Returns a random RFC 4122 version 4 UUID.
 *
 * `crypto.randomUUID` only exists in secure contexts (HTTPS or localhost), and the console
 * is often opened over plain HTTP on a LAN address, so fall back to
 * `crypto.getRandomValues`, which is available everywhere.
 */
export function uuid(): string {
  if (typeof crypto.randomUUID === 'function') {
    try {
      return crypto.randomUUID()
    } catch {
      // Some browsers expose the function but throw outside a secure context.
    }
  }
  const b = crypto.getRandomValues(new Uint8Array(16))
  b[6] = (b[6] & 0x0f) | 0x40 // version 4
  b[8] = (b[8] & 0x3f) | 0x80 // variant 10
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`
}
