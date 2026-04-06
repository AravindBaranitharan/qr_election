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
        const response = await fetch(`/s/${token}`, { method: 'POST', cache: 'no-store' })
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
      const response = await fetch(`/s/${token}`, { method: 'POST', cache: 'no-store' })
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

function SuperAdminScreen() {
  const [stateData, setStateData] = useState(null)
  const [error, setError] = useState('')

  async function loadState() {
    try {
      const response = await fetch('/qr_state.json', { cache: 'no-store' })
      const data = await response.json()
      setStateData(data)
    } catch (stateError) {
      setError(String(stateError))
    }
  }

  useEffect(() => {
    loadState()
    const timer = window.setInterval(loadState, 3000)
    return () => window.clearInterval(timer)
  }, [])

  const total = Number(stateData?.total_qr || 0)
  const accepted = Number(stateData?.true_count || 0)
  const remaining = Math.max(total - accepted, 0)
  const over = total > 0 && accepted >= total

  return (
    <main className="admin-shell">
      <section className="card compact hero-card">
        <p className="badge">Local Mode</p>
        <h1>Superadmin</h1>
        <p className="muted">Use endpoint <code>/generate_qr_local</code> with count. This screen reads from <code>qr_state.json</code>.</p>
        <a className="logout-link" href="/superadmin/logout">
          Logout
        </a>
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
          <p className="mini muted">Output: {stateData?.output_dir || '-'}</p>
          <p className="mini muted">Manifest: {stateData?.manifest_file || '-'}</p>
          <div className="admin-links">
            <a href="/download.zip" target="_blank" rel="noreferrer">
              Download ZIP
            </a>
            <a href="/manifest.json" target="_blank" rel="noreferrer">
              Open Manifest
            </a>
            <a href="/qr/1.png" target="_blank" rel="noreferrer">
              First QR Image
            </a>
          </div>
        </section>
      )}

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
