import { useEffect, useRef, useState } from 'react'
import QrScanner from 'qr-scanner'

function readTokenFromPath() {
  const match = window.location.pathname.match(/^\/(?:c|claim)\/([0-9a-fA-F]+)$/)
  return match ? match[1].toLowerCase() : null
}

function isSuperAdminPath() {
  return window.location.pathname === '/superadmin' || window.location.pathname.startsWith('/superadmin/')
}

function extractToken(rawValue) {
  const value = String(rawValue || '').trim()
  if (!value) return null

  const direct = value.match(/^[0-9a-fA-F]{64,}$/)
  if (direct) return direct[0].toLowerCase()

  const fromPath = value.match(/\/(?:c|claim)\/([0-9a-fA-F]{64,})/i)
  if (fromPath) return fromPath[1].toLowerCase()

  try {
    const parsed = new URL(value)
    const pathMatch = parsed.pathname.match(/^\/(?:c|claim)\/([0-9a-fA-F]{64,})$/i)
    return pathMatch ? pathMatch[1].toLowerCase() : null
  } catch {
    return null
  }
}

function ResultCard({ result, error, loading }) {
  const accepted = Boolean(result?.true)
  const statusClass = accepted ? 'is-accepted' : 'is-rejected'

  if (loading) {
    return (
      <section className="card scan-card">
        <div className="status-ring is-loading" aria-hidden="true">
          <span />
        </div>
        <h2>Checking QR...</h2>
      </section>
    )
  }

  if (!result && !error) return null

  return (
    <section className="card scan-card">
      <div className={`status-ring ${statusClass}`} aria-hidden="true">
        <span>{accepted ? 'OK' : 'NO'}</span>
      </div>
      <h2>{accepted ? 'Accepted' : 'Not Accepted'}</h2>
      <p className="muted">{result?.message || error || 'Unable to process this QR'}</p>
      <div className="scan-meta">
        <strong>{result?.count ?? '-'}</strong>
        <small>Accepted</small>
        <strong>{result?.total ?? '-'}</strong>
        <small>Total</small>
      </div>
    </section>
  )
}

function SubmitOnlyScreen({ token }) {
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true

    async function submit() {
      try {
        const response = await fetch('/scan_hash', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ hash: token }),
          cache: 'no-store',
        })
        const data = await response.json()
        if (active) setResult(data)
      } catch (submitError) {
        if (active) setError(String(submitError))
      }
    }

    submit()
    return () => {
      active = false
    }
  }, [token])

  return (
    <main className="app-shell">
      <ResultCard result={result} error={error} loading={!result && !error} />
    </main>
  )
}

function LandingScannerScreen() {
  const videoRef = useRef(null)
  const busyRef = useRef(false)
  const cooldownRef = useRef({ token: '', at: 0 })

  const [result, setResult] = useState(null)
  const [scanError, setScanError] = useState('')
  const [cameraError, setCameraError] = useState('')
  const [cameraReady, setCameraReady] = useState(false)
  const [loading, setLoading] = useState(false)

  async function handleToken(token) {
    const now = Date.now()
    if (cooldownRef.current.token === token && now - cooldownRef.current.at < 2200) {
      return
    }
    cooldownRef.current = { token, at: now }

    busyRef.current = true
    setLoading(true)
    setScanError('')
    try {
      const response = await fetch('/scan_hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hash: token }),
        cache: 'no-store',
      })
      const data = await response.json()
      setResult(data)
    } catch (submitError) {
      setScanError(String(submitError))
    } finally {
      setLoading(false)
      busyRef.current = false
    }
  }

  useEffect(() => {
    let active = true
    const video = videoRef.current
    if (!video) return undefined

    const scanner = new QrScanner(
      video,
      async (scanResult) => {
        if (!active || busyRef.current) return
        const raw = typeof scanResult === 'string' ? scanResult : scanResult?.data
        const token = extractToken(raw)
        if (!token) return
        await handleToken(token)
      },
      {
        preferredCamera: 'environment',
        maxScansPerSecond: 8,
        highlightScanRegion: false,
        highlightCodeOutline: false,
      },
    )

    scanner
      .start()
      .then(() => {
        if (active) setCameraReady(true)
      })
      .catch((error) => {
        if (active) setCameraError(String(error))
      })

    return () => {
      active = false
      scanner.stop()
      scanner.destroy()
    }
  }, [])

  return (
    <main className="app-shell">
      <section className="card compact">
        <h1>QR Scan</h1>
        <p className="muted">Scan QR and get instant OK or Not Accepted.</p>
        <div className="camera-wrap">
          <video ref={videoRef} muted playsInline />
          {!cameraReady && !cameraError && <p className="camera-overlay">Opening camera...</p>}
        </div>
        {cameraError && <p className="error-text">{cameraError}</p>}
      </section>
      <ResultCard result={result} error={scanError} loading={loading} />
    </main>
  )
}

function ScanTimelineChart({ points }) {
  if (!Array.isArray(points) || points.length === 0) {
    return <p className="muted">No scans yet.</p>
  }

  const width = 360
  const height = 170
  const left = 20
  const right = width - 16
  const top = 14
  const bottom = height - 24
  const graphWidth = right - left
  const graphHeight = bottom - top
  const xStep = points.length > 1 ? graphWidth / (points.length - 1) : 0
  const maxY = Math.max(
    1,
    ...points.map((point) => Math.max(Number(point?.total || 0), Number(point?.accepted || 0))),
  )

  function yFor(value) {
    return bottom - (Number(value || 0) / maxY) * graphHeight
  }

  function lineFor(key) {
    return points
      .map((point, index) => `${left + index * xStep},${yFor(point?.[key] || 0)}`)
      .join(' ')
  }

  const startLabel = String(points[0]?.time || '').replace('T', ' ')
  const endLabel = String(points[points.length - 1]?.time || '').replace('T', ' ')

  return (
    <div className="timeline-wrap">
      <svg viewBox={`0 0 ${width} ${height}`} className="timeline-svg" aria-label="Scan timeline graph">
        {[0, 0.25, 0.5, 0.75, 1].map((part) => {
          const y = top + graphHeight * part
          return <line key={part} x1={left} y1={y} x2={right} y2={y} stroke="#dce9f2" strokeWidth="1" />
        })}
        <polyline fill="none" stroke="#2c8fcc" strokeWidth="2.5" points={lineFor('total')} />
        <polyline fill="none" stroke="#1b9a58" strokeWidth="2.5" points={lineFor('accepted')} />
      </svg>
      <div className="timeline-legend">
        <span className="legend-item">
          <i className="legend-dot legend-total" />
          Scans
        </span>
        <span className="legend-item">
          <i className="legend-dot legend-accepted" />
          Accepted
        </span>
      </div>
      <div className="timeline-axis">
        <small>{startLabel || '-'}</small>
        <small>{endLabel || '-'}</small>
      </div>
    </div>
  )
}

function SuperAdminScreen() {
  const [stateData, setStateData] = useState(null)
  const [timelinePoints, setTimelinePoints] = useState([])
  const [error, setError] = useState('')

  async function loadDashboard() {
    try {
      const [stateResponse, graphResponse] = await Promise.all([
        fetch('/qr_state.json', { cache: 'no-store' }),
        fetch('/scan_metrics', { cache: 'no-store' }),
      ])
      const state = await stateResponse.json()
      const graph = await graphResponse.json()
      setStateData(state)
      setTimelinePoints(Array.isArray(graph?.points) ? graph.points : [])
      setError('')
    } catch (dashboardError) {
      setError(String(dashboardError))
    }
  }

  useEffect(() => {
    loadDashboard()
    const timer = window.setInterval(loadDashboard, 3000)
    return () => window.clearInterval(timer)
  }, [])

  const total = Number(stateData?.total_qr || 0)
  const accepted = Number(stateData?.true_count || 0)
  const remaining = Math.max(total - accepted, 0)
  const over = total > 0 && accepted >= total

  return (
    <main className="admin-shell">
      <section className="card compact">
        <div className="status-head">
          <h1>Status</h1>
          <a className="logout-link" href="/superadmin/logout">
            Logout
          </a>
        </div>
      </section>

      {stateData && (
        <section className="card compact">
          <div className="status-head">
            <h2>Current Status</h2>
            <p className={`status-pill ${over ? 'pill-over' : 'pill-live'}`}>
              {over ? 'Over' : 'Live'}
            </p>
          </div>
          <div className="admin-status-grid">
            <article className="status-tile">
              <small>Total Generated QR</small>
              <strong>{total}</strong>
            </article>
            <article className="status-tile">
              <small>Accepted</small>
              <strong>{accepted}</strong>
            </article>
            <article className="status-tile">
              <small>Remaining</small>
              <strong>{remaining}</strong>
            </article>
            <article className="status-tile">
              <small>Next Serial</small>
              <strong>{stateData?.next_serial ?? '-'}</strong>
            </article>
          </div>
        </section>
      )}

      <section className="card compact">
        <h2>Scan Timeline</h2>
        <ScanTimelineChart points={timelinePoints} />
      </section>

      {error && (
        <section className="card compact error-box">
          <p>{error}</p>
        </section>
      )}
    </main>
  )
}

function App() {
  const [token] = useState(() => readTokenFromPath())
  const [superadmin] = useState(() => isSuperAdminPath())

  if (token) return <SubmitOnlyScreen token={token} />
  if (superadmin) return <SuperAdminScreen />
  return <LandingScannerScreen />
}

export default App
