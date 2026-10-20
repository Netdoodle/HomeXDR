// Client-side model of the event query language in docs/api.md.
//
//   field:value          exact match (case-insensitive for strings); also field=value
//   field!=value         not equal
//   field:val* / *val    wildcards (unquoted values only)
//   field:"quoted value" exact, literal match
//   field:>10 field:<=443 comparisons; also field>10, field<=443
//   AND, OR, NOT, ( )    boolean logic (also &&, ||, !, -term); adjacent terms are ANDed
//   bare words           substring match on message, process.command_line, file.path
//   ... | command ...    Splunk-style pipeline commands (see PIPE_COMMANDS)
//
// The server does the real translation to SQL. The UI uses this module to validate input
// before sending it, to append `field:value` terms safely, and (in mock mode) to filter
// fixture events.

export type CompareOp = ':' | '>' | '>=' | '<' | '<='

export interface TermNode {
  type: 'term'
  field?: string
  op: CompareOp
  value: string
  quoted: boolean
}

export type QueryNode =
  | TermNode
  | { type: 'and'; children: QueryNode[] }
  | { type: 'or'; children: QueryNode[] }
  | { type: 'not'; child: QueryNode }

export class QuerySyntaxError extends Error {
  readonly pos: number
  constructor(message: string, pos: number) {
    super(message)
    this.name = 'QuerySyntaxError'
    this.pos = pos
  }
}

type Token =
  | { kind: 'lparen' | 'rparen' | 'and' | 'or' | 'not'; pos: number }
  | { kind: 'term'; term: TermNode; pos: number }

const FIELD_RE = /^[@A-Za-z_][\w.@-]*$/
const KEYWORDS: Record<string, 'and' | 'or' | 'not'> = { AND: 'and', OR: 'or', NOT: 'not', '&&': 'and', '||': 'or', '!': 'not' }

/** Splunk-style operators inside a word, in the order the server checks them. */
const WORD_OPS = /:|!=|<=|>=|=|<|>/

function readQuoted(q: string, start: number): { value: string; end: number } {
  // q[start] === '"'
  let i = start + 1
  let out = ''
  while (i < q.length) {
    const c = q[i]
    if (c === '\\' && i + 1 < q.length && (q[i + 1] === '"' || q[i + 1] === '\\')) {
      out += q[i + 1]
      i += 2
      continue
    }
    if (c === '"') return { value: out, end: i + 1 }
    out += c
    i++
  }
  throw new QuerySyntaxError('Unterminated quoted string', start)
}

function isBoundary(c: string | undefined): boolean {
  return c === undefined || /\s/.test(c) || c === '(' || c === ')'
}

export function tokenize(q: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  while (i < q.length) {
    const c = q[i]
    if (/\s/.test(c)) {
      i++
      continue
    }
    if (c === '(') {
      tokens.push({ kind: 'lparen', pos: i })
      i++
      continue
    }
    if (c === ')') {
      tokens.push({ kind: 'rparen', pos: i })
      i++
      continue
    }
    if (c === '"') {
      const { value, end } = readQuoted(q, i)
      tokens.push({ kind: 'term', pos: i, term: { type: 'term', op: ':', value, quoted: true } })
      i = end
      continue
    }
    if (c === '-' && i + 1 < q.length && !/\s/.test(q[i + 1]) && (i === 0 || /[\s(]/.test(q[i - 1]))) {
      tokens.push({ kind: 'not', pos: i })
      i++
      continue
    }
    // A word runs until whitespace, a paren or a quote.
    const start = i
    while (i < q.length && !/\s/.test(q[i]) && q[i] !== '(' && q[i] !== ')' && q[i] !== '"') i++
    const word = q.slice(start, i)
    const kw = KEYWORDS[word]
    if (kw) {
      tokens.push({ kind: kw, pos: start })
      continue
    }
    const opMatch = WORD_OPS.exec(word)
    const at = opMatch ? opMatch.index : -1
    const splunkOp = opMatch && opMatch[0] !== ':' ? opMatch[0] : ''
    if (splunkOp && at > 0 && FIELD_RE.test(word.slice(0, at))) {
      // field=value, field!=value, field>N ... (a bare word when the parts don't fit)
      const field = word.slice(0, at)
      const rest = word.slice(at + splunkOp.length)
      if (splunkOp === '=' || splunkOp === '!=') {
        let value = rest
        let quoted = false
        if (rest === '' && q[i] === '"') {
          const r = readQuoted(q, i)
          i = r.end
          if (!isBoundary(q[i])) throw new QuerySyntaxError('Unexpected text after quoted value', i)
          value = r.value
          quoted = true
        }
        if (value !== '' || quoted) {
          if (splunkOp === '!=') tokens.push({ kind: 'not', pos: start })
          tokens.push({ kind: 'term', pos: start, term: { type: 'term', field, op: ':', value, quoted } })
          continue
        }
      } else if (isNumeric(rest)) {
        tokens.push({ kind: 'term', pos: start, term: { type: 'term', field, op: splunkOp as CompareOp, value: rest, quoted: false } })
        continue
      }
    }
    const colon = opMatch && opMatch[0] === ':' ? at : -1
    const field = colon > 0 ? word.slice(0, colon) : ''
    if (colon > 0 && FIELD_RE.test(field)) {
      let rest = word.slice(colon + 1)
      let op: CompareOp = ':'
      const m = /^(>=|<=|>|<)/.exec(rest)
      if (m) {
        op = m[1] as CompareOp
        rest = rest.slice(m[1].length)
      }
      if (rest === '' && q[i] === '"') {
        const { value, end } = readQuoted(q, i)
        i = end
        if (!isBoundary(q[i])) throw new QuerySyntaxError('Unexpected text after quoted value', i)
        tokens.push({ kind: 'term', pos: start, term: { type: 'term', field, op, value, quoted: true } })
        continue
      }
      if (rest === '') throw new QuerySyntaxError(`Missing value for field "${field}"`, start)
      tokens.push({ kind: 'term', pos: start, term: { type: 'term', field, op, value: rest, quoted: false } })
      continue
    }
    if (q[i] === '"') throw new QuerySyntaxError('Unexpected quote', i)
    tokens.push({ kind: 'term', pos: start, term: { type: 'term', op: ':', value: word, quoted: false } })
  }
  return tokens
}

/** Parses a query into an AST. Returns null for an empty query. Throws QuerySyntaxError. */
export function parseQuery(q: string): QueryNode | null {
  const tokens = tokenize(q)
  if (tokens.length === 0) return null
  let pos = 0
  const peek = () => tokens[pos]
  const endPos = () => (pos < tokens.length ? tokens[pos].pos : q.length)

  function parseOr(): QueryNode {
    const children = [parseAnd()]
    while (peek()?.kind === 'or') {
      pos++
      children.push(parseAnd())
    }
    return children.length === 1 ? children[0] : { type: 'or', children }
  }

  function parseAnd(): QueryNode {
    const children = [parseNot()]
    for (;;) {
      const t = peek()
      if (!t || t.kind === 'or' || t.kind === 'rparen') break
      if (t.kind === 'and') pos++
      children.push(parseNot())
    }
    return children.length === 1 ? children[0] : { type: 'and', children }
  }

  function parseNot(): QueryNode {
    if (peek()?.kind === 'not') {
      pos++
      return { type: 'not', child: parseNot() }
    }
    return parsePrimary()
  }

  function parsePrimary(): QueryNode {
    const t = peek()
    if (!t) throw new QuerySyntaxError('Query ends unexpectedly', q.length)
    if (t.kind === 'lparen') {
      pos++
      if (peek()?.kind === 'rparen') throw new QuerySyntaxError('Empty parentheses', t.pos)
      const inner = parseOr()
      if (peek()?.kind !== 'rparen') throw new QuerySyntaxError('Missing closing parenthesis', t.pos)
      pos++
      return inner
    }
    if (t.kind === 'term') {
      pos++
      return t.term
    }
    if (t.kind === 'rparen') throw new QuerySyntaxError('Unexpected closing parenthesis', t.pos)
    throw new QuerySyntaxError(`Unexpected ${t.kind.toUpperCase()}`, t.pos)
  }

  const node = parseOr()
  if (pos < tokens.length) {
    const t = tokens[pos]
    throw new QuerySyntaxError(
      t.kind === 'rparen' ? 'Unexpected closing parenthesis' : 'Unexpected token',
      endPos(),
    )
  }
  return node
}

/** Returns null when the query is valid, or the syntax error. Commands after | are checked
 * for a known name only; the server reports anything else. */
export function validateQuery(q: string): QuerySyntaxError | null {
  try {
    const { filter, commands } = splitPipeline(q)
    parseQuery(filter)
    for (const c of commands) {
      if (!c.text) throw new QuerySyntaxError('Missing command after |', c.pos)
      const name = commandName(c.text)
      if (!(PIPE_COMMANDS as readonly string[]).includes(name)) {
        throw new QuerySyntaxError(`Unknown command "${name}" (commands: ${PIPE_COMMANDS.join(', ')})`, c.pos)
      }
    }
    return null
  } catch (e) {
    if (e instanceof QuerySyntaxError) return e
    throw e
  }
}

// ---------------------------------------------------------------------------------------
// Pipelines

/** Commands the server accepts after |. */
export const PIPE_COMMANDS = [
  'stats',
  'timechart',
  'top',
  'rare',
  'table',
  'fields',
  'sort',
  'head',
  'limit',
  'dedup',
  'where',
  'eval',
  'rename',
  'rex',
  'search',
] as const

/** Commands whose result is a table rather than events. */
export const TABLE_COMMANDS = new Set(['stats', 'timechart', 'top', 'rare', 'table', 'fields'])

export interface PipelineParts {
  /** The filter before the first |. */
  filter: string
  /** Index of the first | (or the query length). */
  pipeAt: number
  /** Each command's trimmed text and where it starts in the query. */
  commands: { text: string; pos: number }[]
}

/** Splits a search at unquoted | like the server: || is OR, and single quotes (field
 * names) only quote after the first |. */
export function splitPipeline(q: string): PipelineParts {
  const cuts: number[] = []
  let inDouble = false
  let inSingle = false
  for (let i = 0; i < q.length; i++) {
    const c = q[i]
    if (c === '\\' && i + 1 < q.length) {
      i++
    } else if (c === '"' && !inSingle) {
      inDouble = !inDouble
    } else if (c === "'" && !inDouble && cuts.length > 0) {
      inSingle = !inSingle
    } else if (c === '|' && q[i + 1] === '|') {
      i++
    } else if (c === '|' && !inDouble && !inSingle) {
      cuts.push(i)
    }
  }
  const pipeAt = cuts.length ? cuts[0] : q.length
  const commands = cuts.map((at, k) => {
    const end = k + 1 < cuts.length ? cuts[k + 1] : q.length
    const raw = q.slice(at + 1, end)
    const lead = raw.length - raw.trimStart().length
    return { text: raw.trim(), pos: at + 1 + lead }
  })
  return { filter: q.slice(0, pipeAt), pipeAt, commands }
}

export function commandName(text: string): string {
  return (/^\S*/.exec(text)?.[0] ?? '').toLowerCase()
}

/** True when the search ends in a table (stats, timechart, top, rare, table, fields). */
export function isTableSearch(q: string): boolean {
  return splitPipeline(q).commands.some((c) => TABLE_COMMANDS.has(commandName(c.text)))
}

/** A field name as a pipeline command argument: quoted when it is not a plain name. */
export function fieldRef(field: string): string {
  return /^[A-Za-z_@][\w@.]*$/.test(field) ? field : `'${field.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
}

/** Splunk and CIM-style names the server accepts for HomeXDR's fields. */
export const FIELD_ALIASES: Record<string, string> = {
  index: 'event.module',
  sourcetype: 'event.dataset',
  host: 'host.name',
  category: 'event.category',
  outcome: 'event.outcome',
  bytes: 'network.bytes',
  packets: 'network.packets',
  src: 'source.ip',
  src_ip: 'source.ip',
  src_port: 'source.port',
  dest: 'destination.ip',
  dest_ip: 'destination.ip',
  dest_port: 'destination.port',
  user: 'user.name',
  action: 'event.action',
  process: 'process.name',
  _time: '@timestamp',
}

export function canonicalField(f: string): string {
  return FIELD_ALIASES[f] ?? f
}

/** Values of a field, with aliases and the server's data.* lookup for bare names. */
export function fieldValues(obj: unknown, field: string): Primitive[] {
  const f = canonicalField(field)
  const vals = resolvePath(obj, f)
  if (vals.length === 0 && !f.includes('.')) return resolvePath(obj, 'data.' + f)
  return vals
}

// ---------------------------------------------------------------------------------------
// Building queries

const SAFE_UNQUOTED = /^[^\s()"*<>]+$/

/** Formats a value for use after `field:`. Quotes anything that would not round-trip. */
export function quoteValue(value: string): string {
  if (value !== '' && SAFE_UNQUOTED.test(value) && !KEYWORDS[value]) return value
  return '"' + value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'
}

export function formatTerm(field: string, value: unknown): string {
  const v = value === null || value === undefined ? '' : String(value)
  return `${field}:${quoteValue(v)}`
}

function topLevelHasOr(q: string): boolean {
  try {
    return parseQuery(q)?.type === 'or'
  } catch {
    return true // unknown shape: be safe and parenthesize
  }
}

/**
 * Appends a `field:value` term to an existing query, ANDed with whatever is there.
 * Queries with a top-level OR are parenthesized so the new term applies to all of it.
 * Returns the query unchanged if the term is already one of its top-level AND terms.
 */
export function addTerm(query: string, field: string, value: unknown, opts: { negate?: boolean } = {}): string {
  const term = (opts.negate ? 'NOT ' : '') + formatTerm(field, value)
  const { filter, pipeAt, commands } = splitPipeline(query)
  const q = filter.trim()
  let next: string
  if (!q) next = term
  else if (topLevelTerms(q).includes(term)) next = q
  else next = `${topLevelHasOr(q) ? `(${q})` : q} AND ${term}`
  if (commands.length === 0) return next
  const gap = /\s*$/.exec(filter)?.[0] || ' '
  return next + gap + query.slice(pipeAt).trimEnd()
}

function nodeToString(n: QueryNode): string {
  switch (n.type) {
    case 'term': {
      const v = n.quoted ? '"' + n.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"' : n.value
      if (!n.field) return v
      return `${n.field}:${n.op === ':' ? '' : n.op}${v}`
    }
    case 'not':
      return 'NOT ' + wrap(n.child)
    case 'and':
      return n.children.map(wrap).join(' AND ')
    case 'or':
      return n.children.map(wrap).join(' OR ')
  }
}

function wrap(n: QueryNode): string {
  return n.type === 'and' || n.type === 'or' ? `(${nodeToString(n)})` : nodeToString(n)
}

/** Canonical string form of a query (explicit AND, minimal parentheses). */
export function formatQuery(q: string): string {
  const n = parseQuery(q)
  return n ? nodeToString(n) : ''
}

function topLevelTerms(q: string): string[] {
  try {
    const n = parseQuery(q)
    if (!n) return []
    if (n.type === 'and') return n.children.map(nodeToString)
    return [nodeToString(n)]
  } catch {
    return []
  }
}

// ---------------------------------------------------------------------------------------
// Evaluation (used by the mock backend and for client-side highlighting)

type Primitive = string | number | boolean

/**
 * Resolves a dotted path against a JSON object. Arrays are flattened, so
 * `event.category` on ["process","file"] yields both values. Keys that themselves
 * contain dots (e.g. `data["suricata.sid"]`) are matched by trying the longest key first.
 */
export function resolvePath(obj: unknown, path: string): Primitive[] {
  const out: Primitive[] = []
  const walk = (cur: unknown, parts: string[]) => {
    if (cur === null || cur === undefined) return
    if (Array.isArray(cur)) {
      for (const item of cur) walk(item, parts)
      return
    }
    if (parts.length === 0) {
      if (typeof cur === 'string' || typeof cur === 'number' || typeof cur === 'boolean') out.push(cur)
      return
    }
    if (typeof cur !== 'object') return
    const rec = cur as Record<string, unknown>
    for (let i = parts.length; i >= 1; i--) {
      const key = parts.slice(0, i).join('.')
      if (key in rec) {
        walk(rec[key], parts.slice(i))
        return
      }
      // case-insensitive fallback for data.* style keys
      const ci = Object.keys(rec).find((k) => k.toLowerCase() === key.toLowerCase())
      if (ci !== undefined) {
        walk(rec[ci], parts.slice(i))
        return
      }
    }
  }
  walk(obj, path.split('.'))
  return out
}

function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')
  return new RegExp('^' + escaped + '$', 'is')
}

const isNumeric = (s: string) => s.trim() !== '' && !Number.isNaN(Number(s))

function compare(a: Primitive, op: Exclude<CompareOp, ':'>, b: string): boolean {
  let x: number
  let y: number
  if (typeof a === 'number' || (isNumeric(String(a)) && isNumeric(b))) {
    x = Number(a)
    y = Number(b)
  } else {
    const da = Date.parse(String(a))
    const db = Date.parse(b)
    if (!Number.isNaN(da) && !Number.isNaN(db)) {
      x = da
      y = db
    } else {
      const c = String(a).toLowerCase().localeCompare(b.toLowerCase())
      x = c
      y = 0
    }
  }
  switch (op) {
    case '>':
      return x > y
    case '>=':
      return x >= y
    case '<':
      return x < y
    case '<=':
      return x <= y
  }
}

export function matchValue(v: Primitive, term: TermNode): boolean {
  if (term.op !== ':') return compare(v, term.op, term.value)
  if (!term.quoted && term.value.includes('*')) return globToRegExp(term.value).test(String(v))
  if (typeof v === 'number') return isNumeric(term.value) && Number(term.value) === v
  if (typeof v === 'boolean') return term.value.toLowerCase() === String(v)
  return v.toLowerCase() === term.value.toLowerCase()
}

export const BARE_WORD_FIELDS = ['message', 'process.command_line', 'file.path']

function matchTerm(obj: unknown, term: TermNode): boolean {
  if (!term.field) {
    const needle = term.value.replace(/\*/g, '').toLowerCase()
    if (!needle) return true
    return BARE_WORD_FIELDS.some((f) => resolvePath(obj, f).some((v) => String(v).toLowerCase().includes(needle)))
  }
  return fieldValues(obj, term.field).some((v) => matchValue(v, term))
}

export function evaluate(node: QueryNode | null, obj: unknown): boolean {
  if (!node) return true
  switch (node.type) {
    case 'term':
      return matchTerm(obj, node)
    case 'not':
      return !evaluate(node.child, obj)
    case 'and':
      return node.children.every((c) => evaluate(c, obj))
    case 'or':
      return node.children.some((c) => evaluate(c, obj))
  }
}

/** Convenience: compile once, test many. */
export function compileQuery(q: string): (obj: unknown) => boolean {
  const node = parseQuery(q)
  return (obj) => evaluate(node, obj)
}
