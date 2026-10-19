import { Component, type ErrorInfo, type ReactNode } from 'react'

interface State {
  error: Error | null
}

/** Last-resort boundary so a rendering bug shows a message instead of a blank page. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[HomeXDR] render error', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="auth-page">
        <div className="auth-card">
          <div className="state error" role="alert">
            <span className="state-title">The console hit an unexpected error</span>
            <span className="small mono" style={{ overflowWrap: 'anywhere' }}>
              {this.state.error.message}
            </span>
            <div className="row" style={{ justifyContent: 'center' }}>
              <button type="button" className="btn" onClick={() => this.setState({ error: null })}>
                Try again
              </button>
              <button type="button" className="btn primary" onClick={() => window.location.assign('/')}>
                Reload dashboard
              </button>
            </div>
          </div>
        </div>
      </div>
    )
  }
}
