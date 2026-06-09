import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  error: Error | null
}

/**
 * Catches render-time errors in the subtree so one broken component (often
 * triggered by unexpected scan-result shapes) doesn't blank the whole app.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Unhandled UI error:', error, info)
  }

  handleReset = () => this.setState({ error: null })

  render() {
    if (this.state.error) {
      if (this.props.fallback) return this.props.fallback
      return (
        <div style={{ padding: '2rem', maxWidth: 640, margin: '4rem auto', textAlign: 'center' }}>
          <h2>Something went wrong</h2>
          <p style={{ color: '#9aa', marginTop: '0.5rem' }}>
            An unexpected error occurred while rendering this view.
          </p>
          <pre
            style={{
              textAlign: 'left',
              overflow: 'auto',
              background: 'rgba(0,0,0,0.3)',
              padding: '1rem',
              borderRadius: 8,
              marginTop: '1rem',
              fontSize: 12,
            }}
          >
            {this.state.error.message}
          </pre>
          <button onClick={this.handleReset} style={{ marginTop: '1rem' }}>
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
