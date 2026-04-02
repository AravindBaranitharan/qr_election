import { useEffect, useRef, useState } from 'react'
import QrScanner from 'qr-scanner'

function readTokenFromPath() {
  const match = window.location.pathname.match(/^\/(?:c|claim)\/([0-9a-fA-F]+)$/)
  return match ? match[1].toLowerCase() : null
}

function extractToken(rawValue) {
  const value = String(rawValue || '').trim()
  if (!value) return null

  const direct = value.match(/^[0-9a-fA-F]{42}$/)
  if (direct) return direct[0].toLowerCase()

  const fromPath = value.match(/\/(?:c|claim)\/([0-9a-fA-F]{42})/i)
  if (fromPath) return fromPath[1].toLowerCase()

  try {
    const parsed = new URL(value)
    const pathMatch = parsed.pathname.match(/^\/(?:c|claim)\/([0-9a-fA-F]{42})$/i)
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

function ScannerScreen() {
  const videoRef = useRef(null)
  const scannerRef = useRef(null)
  const busyRef = useRef(false)
  const cooldownRef = useRef({ token: '', at: 0 })

  const [status, setStatus] = useState(null)
  const [result, setResult] = useState(null)
  const [scanError, setScanError] = useState('')
  const [cameraError, setCameraError] = useState('')
  const [cameraReady, setCameraReady] = useState(false)
  const [loading, setLoading] = useState(false)

  async function refreshStatus() {
    try {
      const response = await fetch('/status', { cache: 'no-store' })
      const data = await response.json()
      setStatus(data)
    } catch (statusError) {
      setScanError(String(statusError))
    }
  }

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
      await refreshStatus()
    } catch (submitError) {
      setScanError(String(submitError))
    } finally {
      setLoading(false)
      busyRef.current = false
    }
  }

  useEffect(() => {
    refreshStatus()
    const timer = window.setInterval(refreshStatus, 4000)
    return () => window.clearInterval(timer)
  }, [])

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

    scannerRef.current = scanner
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
      scannerRef.current = null
    }
  }, [])

  return (
    <main className="app-shell">
      <section className="card compact">
        <h1>QR Scan</h1>
        <p className="muted mini">Status from backend</p>
        <div className="status-grid">
          <div>
            <strong>{status?.true_count ?? 0}</strong>
            <small>Accepted</small>
          </div>
          <div>
            <strong>{status?.total_qr ?? 0}</strong>
            <small>Total</small>
          </div>
          <div>
            <strong>{status?.remaining ?? 0}</strong>
            <small>Remaining</small>
          </div>
        </div>
        <p className={`chip ${status?.over ? 'chip-over' : 'chip-live'}`}>
          {status?.over ? 'Batch Over' : 'Live'}
        </p>
      </section>

      <section className="card compact">
        <h2>Camera</h2>
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

function App() {
  const [token] = useState(() => readTokenFromPath())
  return token ? <SubmitOnlyScreen token={token} /> : <ScannerScreen />
}

export default App
