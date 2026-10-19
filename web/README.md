# HomeXDR web console

React 19 + TypeScript (strict) + Vite single-page app for the HomeXDR server. It talks only
to the REST API in [`docs/api.md`](../docs/api.md). The server embeds `dist/` and serves
`index.html` for unknown routes.

## Requirements

Node 20+ (developed on Node 24 / npm 11).

```bash
cd web
npm ci
```

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Dev server on <http://localhost:5173>. `/api` and `/healthz` are proxied to `http://localhost:8080`. |
| `npm run dev:mock` | Same, but every API call is answered in the browser from fixtures (no server needed). |
| `npm run build` | Typecheck (`tsc -b`) and production build into `dist/`. |
| `npm run build:mock` | A static demo build with the mock backend included. |
| `npm test` | Vitest unit tests (`src/**/*.test.ts`). |
| `npm run typecheck` | Typecheck only. |
| `npm run preview` | Serve `dist/` locally. |

To proxy to a server on another address, set `HOMEXDR_API`:

```bash
HOMEXDR_API=http://127.0.0.1:28080 npm run dev     # bash
$env:HOMEXDR_API='http://127.0.0.1:28080'; npm run dev   # PowerShell
```

## Mock mode

`npm run dev:mock` (or `VITE_MOCK=1`) installs a small fetch interceptor
(`src/mock/`) that implements every endpoint in `docs/api.md` over in-memory fixtures:

- hosts: a Windows 11 desktop, an Ubuntu Docker server (one degraded sensor, `file.get`
  blocked by local policy), an OPNsense firewall (`kind: network`), an offline laptop and an
  isolated Raspberry Pi;
- a process tree `winlogon.exe → userinit.exe → explorer.exe → powershell.exe →
  whoami.exe / net.exe → net1.exe / reg.exe` with network, DNS, file and registry activity;
- alerts at every severity with MITRE mappings, notes and assignees; Sigma rules; hunts;
  command history with artifact rows; tokens, users, audit log and syslog sources.

Mutations work (triage, bulk updates, notes, response actions that move through
queued → delivered → running → completed, hunts, rules, tokens, users, agent config) and
reset on reload. The mock enforces the same CSRF header, session and role rules as the
server.

URL flags (stored for the browser tab):

- `?mock_role=viewer` / `analyst` / `admin`: see the UI as that role;
- `?mock_setup=1`: start from the first-run "create admin" screen;
- `?mock_logout=1`: start signed out. The mock login accepts any listed user (`admin`,
  `sam`, `guest`) with any password of 10+ characters.

Mock code is gated by a build-time constant (`__HOMEXDR_MOCK__` in `vite.config.ts`). In a
normal build it is `false`, the dynamic import is dropped, and no fixtures ship in `dist/`.

## Layout

```
src/
  api/         typed client (client.ts), endpoints, types matching docs/api.md, query keys
  components/  layout, badges, tables helpers, dialogs, field tree, charts, ...
  pages/       one file per route (Dashboard, Alerts, Hosts, ProcessTree, Search, ...)
  lib/         pure logic: query language, time ranges, process-tree flattening, ...
  mock/        fixtures and the in-browser API (mock mode only)
  theme.css    design tokens (dark default, light via prefers-color-scheme or the user menu)
  app.css      component styles, written against the tokens only
```

API client conventions: JSON in/out, `credentials: 'same-origin'`, `X-HomeXDR-CSRF: 1` on
every non-GET request, `{"error": "..."}` bodies become `ApiError`, and a 401 sends the
user to `/login?next=...`.

## Routes

| Path | Page |
|---|---|
| `/login`, `/setup` | First-run admin creation or sign-in |
| `/` | Dashboard |
| `/alerts`, `/alerts/:id` | Alert queue (filters, bulk status) and alert detail |
| `/hosts`, `/hosts/:id?tab=` | Hosts; detail tabs overview, timeline, alerts, commands, actions |
| `/hosts/:id/process/:entityId` | Process tree with per-process activity |
| `/search?q=&range=` | Event search |
| `/rules`, `/rules/:id`, `/rules/new`, `/rules/:id/edit` | Rules and the custom rule editor |
| `/hunts`, `/hunts/new`, `/hunts/:id` | Hunts |
| `/settings/:tab` | tokens, users, agent-config, integrations, audit, account |
