import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useEffect } from 'react'
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router'
import { isApiError, setUnauthorizedHandler } from './api'
import { RequireAuth } from './components/Auth'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Layout } from './components/Layout'
import { ThemeProvider } from './components/Theme'
import { ToastProvider } from './components/Toast'
import { AlertDetailPage } from './pages/AlertDetail'
import { AlertsPage } from './pages/Alerts'
import { DashboardPage } from './pages/Dashboard'
import { HostDetailPage } from './pages/HostDetail'
import { HostsPage } from './pages/Hosts'
import { HuntCreatePage } from './pages/HuntCreate'
import { HuntDetailPage } from './pages/HuntDetail'
import { HuntsPage } from './pages/Hunts'
import { LoginPage } from './pages/Login'
import { NotFoundPage } from './pages/NotFound'
import { ProcessTreePage } from './pages/ProcessTree'
import { RuleDetailPage } from './pages/RuleDetail'
import { RuleEditorPage } from './pages/RuleEditor'
import { RulesPage } from './pages/Rules'
import { SearchPage } from './pages/Search'
import { SettingsPage } from './pages/Settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (count, err) => {
        if (isApiError(err) && err.status < 500) return false
        return count < 2
      },
    },
  },
})

/** Routes 401s through the router (no full reload) and drops cached data. */
function UnauthorizedBridge() {
  const navigate = useNavigate()
  const loc = useLocation()
  useEffect(() => {
    setUnauthorizedHandler(() => {
      if (window.location.pathname.startsWith('/login')) return
      queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== 'setup' })
      const next = window.location.pathname + window.location.search
      navigate(`/login?next=${encodeURIComponent(next)}`, { replace: true })
    })
  }, [navigate, loc])
  return null
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <BrowserRouter>
          <ToastProvider>
            <UnauthorizedBridge />
            <ErrorBoundary>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/setup" element={<LoginPage />} />
              <Route
                element={
                  <RequireAuth>
                    <Layout />
                  </RequireAuth>
                }
              >
                <Route index element={<DashboardPage />} />
                <Route path="alerts" element={<AlertsPage />} />
                <Route path="alerts/:id" element={<AlertDetailPage />} />
                <Route path="hosts" element={<HostsPage />} />
                <Route path="hosts/:id" element={<HostDetailPage />} />
                <Route path="hosts/:id/process/:entityId" element={<ProcessTreePage />} />
                <Route path="search" element={<SearchPage />} />
                <Route path="rules" element={<RulesPage />} />
                <Route path="rules/new" element={<RuleEditorPage />} />
                <Route path="rules/:id" element={<RuleDetailPage />} />
                <Route path="rules/:id/edit" element={<RuleEditorPage />} />
                <Route path="hunts" element={<HuntsPage />} />
                <Route path="hunts/new" element={<HuntCreatePage />} />
                <Route path="hunts/:id" element={<HuntDetailPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="settings/:tab" element={<SettingsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
            </ErrorBoundary>
          </ToastProvider>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  )
}
