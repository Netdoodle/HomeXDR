// Low-level HTTP client: JSON in/out, CSRF header on every non-GET, same-origin cookies,
// `{"error": "..."}` bodies turned into ApiError, and 401 → login redirect.

export class ApiError extends Error {
  readonly status: number
  readonly body: unknown

  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 403) return err.message || 'You do not have permission to do that.'
    return err.message
  }
  if (err instanceof Error) return err.message
  return String(err)
}

export const CSRF_HEADER = 'X-HomeXDR-CSRF'

type UnauthorizedHandler = () => void

let onUnauthorized: UnauthorizedHandler = () => {
  if (!window.location.pathname.startsWith('/login')) {
    const next = window.location.pathname + window.location.search
    window.location.assign('/login?next=' + encodeURIComponent(next))
  }
}

/** Replace the default 401 behaviour (a full-page redirect) with a router-aware one. */
export function setUnauthorizedHandler(fn: UnauthorizedHandler) {
  onUnauthorized = fn
}

// Paths whose 401 is an expected answer (bad credentials), not an expired session.
const NO_REDIRECT_401 = ['/api/auth/login', '/api/auth/mfa', '/api/setup']

export type Query = Record<string, string | number | boolean | undefined | null>

export function buildQuery(params?: Query): string {
  if (!params) return ''
  const sp = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    sp.set(k, String(v))
  }
  const s = sp.toString()
  return s ? '?' + s : ''
}

export interface RequestOptions {
  query?: Query
  body?: unknown
  signal?: AbortSignal
}

export async function rawRequest(method: string, path: string, opts: RequestOptions = {}): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET' && method !== 'HEAD') headers[CSRF_HEADER] = '1'
  let body: BodyInit | undefined
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(opts.body)
  }
  const res = await fetch(path + buildQuery(opts.query), {
    method,
    headers,
    body,
    credentials: 'same-origin',
    signal: opts.signal,
  })
  if (res.status === 401 && !NO_REDIRECT_401.some((p) => path.startsWith(p))) {
    onUnauthorized()
  }
  if (!res.ok) {
    let parsed: unknown
    let message = `${res.status} ${res.statusText || 'request failed'}`
    try {
      const text = await res.text()
      if (text) {
        try {
          parsed = JSON.parse(text)
          if (parsed && typeof parsed === 'object' && 'error' in parsed && typeof parsed.error === 'string') {
            message = parsed.error
          }
        } catch {
          parsed = text
          if (text.length < 300) message = text
        }
      }
    } catch {
      // ignore unreadable bodies
    }
    throw new ApiError(res.status, message, parsed)
  }
  return res
}

export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const res = await rawRequest(method, path, opts)
  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

export const http = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>('GET', path, { query, signal }),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, { body }),
  put: <T>(path: string, body?: unknown) => request<T>('PUT', path, { body }),
  patch: <T>(path: string, body?: unknown) => request<T>('PATCH', path, { body }),
  del: <T = void>(path: string) => request<T>('DELETE', path),
}
