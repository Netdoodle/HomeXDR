import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router'
import { api, queryKeys } from '../api'
import { ROLE_LABEL } from '../lib/roles'
import { useUser } from './Auth'
import { Icon, type IconName } from './Icon'
import { useTheme, type ThemeChoice } from './Theme'

const NAV: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/alerts', label: 'Alerts', icon: 'alert' },
  { to: '/hosts', label: 'Hosts', icon: 'hosts' },
  { to: '/search', label: 'Search', icon: 'search' },
]
const NAV2: { to: string; label: string; icon: IconName }[] = [
  { to: '/rules', label: 'Rules', icon: 'rules' },
  { to: '/hunts', label: 'Hunts', icon: 'hunts' },
  { to: '/settings', label: 'Settings', icon: 'settings' },
]

function BrandMark() {
  return (
    <svg className="brand-mark" width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
      <path
        d="M16 3 5 7.5v7.7c0 6.8 4.6 12 11 14.3 6.4-2.3 11-7.5 11-14.3V7.5L16 3Z"
        fill="none"
        stroke="var(--accent)"
        strokeWidth="2.4"
        strokeLinejoin="round"
      />
      <path d="m11.5 12 9 9m0-9-9 9" stroke="var(--text)" strokeWidth="2.4" strokeLinecap="round" />
    </svg>
  )
}

function useOutsideClose(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) close()
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, close])
  return ref
}

function UserMenu() {
  const user = useUser()
  const [open, setOpen] = useState(false)
  const ref = useOutsideClose(open, () => setOpen(false))
  const { choice, setChoice } = useTheme()
  const qc = useQueryClient()
  const navigate = useNavigate()

  const doLogout = async () => {
    setOpen(false)
    try {
      await api.logout()
    } catch {
      // the session may already be gone
    }
    qc.clear()
    navigate('/login', { replace: true })
  }

  const themes: { id: ThemeChoice; label: string; icon: IconName }[] = [
    { id: 'system', label: 'System theme', icon: 'monitor' },
    { id: 'dark', label: 'Dark', icon: 'moon' },
    { id: 'light', label: 'Light', icon: 'sun' },
  ]

  return (
    <div className="menu" ref={ref}>
      <button
        type="button"
        className="btn ghost"
        onClick={() => setOpen(!open)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account menu for ${user.username} (${ROLE_LABEL[user.role]})`}
      >
        <Icon name="user" size={14} />
        <span>{user.username}</span>
        <span className="faint xsmall">{ROLE_LABEL[user.role]}</span>
        <Icon name="chevronDown" size={12} />
      </button>
      {open ? (
        <div className="menu-pop" role="menu">
          <div className="menu-label">Signed in as {user.username}</div>
          <div className="menu-sep" />
          <div className="menu-label">Theme</div>
          {themes.map((t) => (
            <button
              key={t.id}
              type="button"
              role="menuitemradio"
              aria-checked={choice === t.id}
              className="menu-item"
              onClick={() => setChoice(t.id)}
            >
              <Icon name={t.icon} size={14} />
              <span className="grow">{t.label}</span>
              {choice === t.id ? <Icon name="check" size={14} /> : null}
            </button>
          ))}
          <div className="menu-sep" />
          <button
            type="button"
            role="menuitem"
            className="menu-item"
            onClick={() => {
              setOpen(false)
              navigate('/settings/account')
            }}
          >
            <Icon name="key" size={14} /> Change password
          </button>
          <button type="button" role="menuitem" className="menu-item" onClick={doLogout}>
            <Icon name="logout" size={14} /> Sign out
          </button>
        </div>
      ) : null}
    </div>
  )
}

function QuickSearch() {
  const navigate = useNavigate()
  const loc = useLocation()
  const [q, setQ] = useState('')
  if (loc.pathname === '/search') return <div className="topbar-search" />
  const submit = (e: FormEvent) => {
    e.preventDefault()
    navigate(`/search?q=${encodeURIComponent(q.trim())}`)
    setQ('')
  }
  return (
    <form className="topbar-search" onSubmit={submit} role="search">
      <input
        className="input mono"
        style={{ width: '100%' }}
        placeholder="Search events: process.name:powershell.exe"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        aria-label="Search events"
      />
    </form>
  )
}

function HealthIndicator() {
  const health = useQuery({
    queryKey: queryKeys.health,
    queryFn: api.health,
    refetchInterval: 60_000,
    retry: false,
  })
  const ok = health.data?.status === 'ok' && health.data.event_store === 'ok'
  const label = health.isPending
    ? 'Checking server health'
    : health.isError
      ? 'Server health check failed'
      : ok
        ? 'Server healthy'
        : `Event store: ${health.data?.event_store ?? 'unknown'}`
  return (
    <span className="row nowrap small muted" title={label}>
      <span className={`dot ${health.isPending ? 'offline' : ok ? 'online' : 'revoked'}`} aria-hidden="true" />
      <span className="sr-only">{label}</span>
      <span aria-hidden="true">{health.isPending ? '' : ok ? 'Healthy' : 'Degraded'}</span>
    </span>
  )
}

function NewAlertsCount() {
  const q = useQuery({
    queryKey: queryKeys.alerts({ status: 'new', limit: 1 }),
    queryFn: () => api.listAlerts({ status: 'new', limit: 1 }),
    refetchInterval: 60_000,
  })
  const n = q.data?.total ?? 0
  if (!n) return null
  return (
    <span className="count" title={`${n} new alerts`}>
      {n > 99 ? '99+' : n}
    </span>
  )
}

export function Layout() {
  const setup = useQuery({ queryKey: queryKeys.setup, queryFn: api.setupStatus, staleTime: Infinity })
  return (
    <div className="app">
      <aside className="sidebar">
        <NavLink to="/" className="brand" aria-label="HomeXDR home">
          <BrandMark />
          <span className="brand-text">
            HomeXDR <small>console</small>
          </span>
        </NavLink>
        <nav className="nav" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} title={n.label}>
              <Icon name={n.icon} />
              <span className="label">{n.label}</span>
              {n.to === '/alerts' ? <NewAlertsCount /> : null}
            </NavLink>
          ))}
          <div className="nav-section">Detection &amp; response</div>
          {NAV2.map((n) => (
            <NavLink key={n.to} to={n.to} title={n.label}>
              <Icon name={n.icon} />
              <span className="label">{n.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className="text">{setup.data?.version ? `v${setup.data.version}` : ''}</span>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <QuickSearch />
          <div className="spacer" />
          <HealthIndicator />
          <UserMenu />
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="page-header">
      <div className="title">
        <h1>{title}</h1>
        {subtitle ? <div className="subtitle">{subtitle}</div> : null}
      </div>
      {actions ? <div className="actions">{actions}</div> : null}
    </div>
  )
}
