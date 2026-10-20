# Search

The console's **Search** page, the `POST /api/events/search` API and the AI analyst's
`search_events` tool share one search language, modelled on Splunk's SPL: a filter,
optionally followed by commands separated by `|`.

```
index=opnsense action=block | stats count by src | sort -count | head 10
```

The whole search runs as a single SQL query against the event store (ClickHouse, or
SQLite in lite mode). Values typed in a search are passed to the database as query
parameters and never become SQL text.

## Filter

| Syntax | Matches |
|---|---|
| `field=value`, `field:value` | Equal, ignoring case. |
| `field!=value` | Not equal (same as `NOT field=value`). |
| `field=val*`, `field=*val*`, `field=a?c` | Wildcards: `*` is any run of characters, `?` one character. |
| `field="two words"` | Quoted values match literally (`*` and `?` are not wildcards); `\"` and `\\` escape. |
| `field>1024`, `field<=443`, `field:>=10` | Numeric comparison. |
| `field=*` | The field is present and not empty. |
| `word`, `"two words"` | Substring of `message`, `process.command_line` or `file.path`. |
| `AND`, `OR`, `NOT`, `&&`, `\|\|`, `!`, `-term`, `( )` | Boolean logic. Adjacent terms are ANDed. |

A field name ends at the first operator, so `file.path:C:\Temp\x.exe` needs no quotes. A
word whose parts don't fit a field and a value (`a<b`, `=x`) is searched as a bare word.

### Field names

Fields are the ECS-style paths of the event (`process.name`, `destination.ip`,
`event.category`, `host.name`, `data.LogonType`, ...). Some short names work too:

| Name | Field | | Name | Field |
|---|---|---|---|---|
| `index` | `event.module` (`opnsense`, `suricata`, `procconn`, ...) | | `dest`, `dest_ip` | `destination.ip` |
| `sourcetype` | `event.dataset` | | `dest_port` | `destination.port` |
| `host` | `host.name` | | `user` | `user.name` |
| `src`, `src_ip` | `source.ip` | | `action` | `event.action` |
| `src_port` | `source.port` | | `process` | `process.name` |
| `category` | `event.category` | | `outcome` | `event.outcome` |
| `bytes` | `network.bytes` | | `packets` | `network.packets` |
| `_time` | `@timestamp` | | `_raw` | the whole event as JSON |

A name without a dot that is not a top-level event field is looked up under `data`,
where parsed log fields are kept: `LogonType` means `data.LogonType`.

## Commands

A search that ends in `stats`, `timechart`, `top`, `rare`, `table` or `fields` returns a
table; otherwise it returns events.

| Command | What it does |
|---|---|
| `stats <agg> [as name], ... [by field, ...]` | Aggregates. `count`, `count(f)`, `dc(f)` (distinct count), `sum(f)`, `avg(f)`, `min(f)`, `max(f)`, `values(f)` (up to 100 distinct values). Rows are sorted by the by-fields. Events without a by-field are left out; array fields such as `event.category` count once per element. |
| `timechart [span=5m] [limit=8] <agg> [by field]` | An aggregate per time bucket, one column per value of the by-field. The span is chosen for about 100 buckets unless given (`30s`, `5m`, `1h`, `1d`, `1w`). The top `limit` series (default 8) are kept; for `count` and `sum` the rest are added up as `OTHER`. Must be the last command. |
| `top [limit=10] field, ...` / `rare ...` | The most (least) common values with `count` and `percent`. |
| `table field, ...` / `fields field, ...` | A table of those fields, in event order. |
| `sort [N] [-]field, ...` | Sort; `-` is descending. `N` keeps the first N. |
| `head [N]` / `limit N` | The first N rows (default 10). |
| `dedup [N] field, ...` | Keep the first N rows (default 1) for each combination of values. |
| `where <expression>` | Keep rows where the expression is true. |
| `eval name = <expression>, ...` | Add or replace fields. |
| `rename field as name, ...` | Rename fields or columns. |
| `rex [field=f] "regex with (?<name>...)"` | Extract named groups into fields (default field `_raw`). |
| `search <filter>` | More filtering with the filter syntax above, before a table command. |

### Expressions

`where` and `eval` take expressions:

- Literals: numbers, `"strings"`, `true`, `false`, `null()`. Field names as above; quote
  unusual names with single quotes: `'max(dest_port)'`.
- Operators: `+ - * / %`, `.` joins strings, `= == != < <= > >=` (`=` ignores case for
  strings; comparing an array field with `=` tests any element), `AND OR NOT`, parentheses.
- Functions: `if(cond, a, b)`, `case(cond, value, ...)`, `coalesce(a, b, ...)`,
  `lower(s)`, `upper(s)`, `len(s)`, `substr(s, start[, length])` (1-based),
  `round(x[, digits])`, `abs(x)`, `tonumber(s)`, `tostring(x)`, `like(s, "pattern%")`,
  `match(s, "regex")`, `isnull(x)`, `isnotnull(x)`.

## Examples

```
index=opnsense action=block | stats count by src | sort -count | head 10
index=opnsense | timechart count by action
index=suricata | stats count, dc(src) as sources by rule.name | sort -count
event.category=authentication event.outcome=failure | stats count by user.name, source.ip
event.category=process | top limit=15 process.name
index=suricata bytes>0 | eval kb = round(bytes / 1024, 1) | sort -kb | head 20 | table _time, src, dest, dest_port, kb
| rex field=message "user (?<account>\w+) from (?<ip>[\d.]+)" | stats count by account, ip
dns.question.name=*.example | dedup dns.question.name | table _time, host.name, dns.question.name
```

## Limits

- Events are paged (100 per page in the console, up to 1,000 per API call).
- Tables return at most 10,000 rows (`truncated` is set when there are more); timecharts
  at most 10,000 buckets.
- On ClickHouse each search may use 1.5 GB of memory and 120 seconds; large groupings and
  sorts spill to disk rather than compete with ingestion.

## The search page

- **Histogram.** Matching events over time; click a bar to zoom into that period.
- **Events.** The events, newest first, with a fields sidebar: click a field for its top
  values across the whole search (not just the page), add a value to the filter or exclude
  it, or jump to its top values, rare values or values over time.
- **Statistics.** The table, sortable by any column, with CSV export (cells that look like
  spreadsheet formulas are prefixed with `'`).
- **Visualization.** Time charts as stacked columns or lines; other tables as bars of a
  number column; a single row of numbers as figures.
