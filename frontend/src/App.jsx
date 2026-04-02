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

function LandingScannerScreen() {
  const videoRef = useRef(null)
  const scannerRef = useRef(null)
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
  const [count, setCount] = useState('17')
  const [batchIdInput, setBatchIdInput] = useState('')
  const [status, setStatus] = useState(null)
  const [batchData, setBatchData] = useState(null)
  const [manifestData, setManifestData] = useState(null)
  const [loadingGenerate, setLoadingGenerate] = useState(false)
  const [loadingManifest, setLoadingManifest] = useState(false)
  const [error, setError] = useState('')

  async function loadStatus() {
    try {
      const response = await fetch('/status', { cache: 'no-store' })
      const data = await response.json()
      setStatus(data)
    } catch (statusError) {
      setError(String(statusError))
    }
  }

  useEffect(() => {
    loadStatus()
  }, [])

  async function generateBatch(event) {
    event.preventDefault()
    setError('')
    setLoadingGenerate(true)
    setManifestData(null)
    try {
      const safeCount = Math.max(parseInt(count, 10) || 0, 1)
      const response = await fetch('/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: safeCount }),
        cache: 'no-store',
      })
      const data = await response.json()
      setBatchData(data)
      setBatchIdInput(data.batch_id || '')
      await loadStatus()
    } catch (generateError) {
      setError(String(generateError))
    } finally {
      setLoadingGenerate(false)
    }
  }

  async function fetchManifest(event) {
    event.preventDefault()
    setError('')
    setLoadingManifest(true)
    try {
      const cleaned = String(batchIdInput || '').trim()
      if (!cleaned) throw new Error('Enter a batch id first')
      const response = await fetch(`/batch/${cleaned}/manifest.json?t=${Date.now()}`, { cache: 'no-store' })
      if (!response.ok) throw new Error(`Manifest request failed (${response.status})`)
      const data = await response.json()
      setManifestData(data)
    } catch (manifestError) {
      setError(String(manifestError))
      setManifestData(null)
    } finally {
      setLoadingManifest(false)
    }
  }

  const activeBatchId = String(batchIdInput || batchData?.batch_id || status?.active_batch_id || '')

  return (
    <main className="admin-shell">
      <section className="card compact">
        <h1>Superadmin</h1>
        <p className="muted">Generate QR batches and download all files from here.</p>
      </section>

      <section className="card compact">
        <h2>Create Batch</h2>
        <form className="admin-form" onSubmit={generateBatch}>
          <label htmlFor="count">QR count</label>
          <div className="row">
            <input
              id="count"
              type="number"
              min="1"
              value={count}
              onChange={(event) => setCount(event.target.value)}
            />
            <button type="submit" disabled={loadingGenerate}>
              {loadingGenerate ? 'Generating...' : 'Generate'}
            </button>
          </div>
        </form>
      </section>

      <section className="card compact">
        <h2>Batch Manage</h2>
        <form className="admin-form" onSubmit={fetchManifest}>
          <label htmlFor="batchId">Batch ID</label>
          <div className="row">
            <input
              id="batchId"
              value={batchIdInput}
              onChange={(event) => setBatchIdInput(event.target.value)}
              placeholder="e.g. 8161f717"
            />
            <button type="submit" disabled={loadingManifest}>
              {loadingManifest ? 'Loading...' : 'Load'}
            </button>
          </div>
        </form>

        {activeBatchId && (
          <div className="admin-links">
            <a href={`/batch/${activeBatchId}/download.zip`} target="_blank" rel="noreferrer">
              Download ZIP
            </a>
            <a href={`/batch/${activeBatchId}/manifest.json`} target="_blank" rel="noreferrer">
              Open Manifest
            </a>
            <a href={`/batch/${activeBatchId}/qr/1.png`} target="_blank" rel="noreferrer">
              First QR Image
            </a>
          </div>
        )}
      </section>

      {status && (
        <section className="card compact">
          <h2>Current Status</h2>
          <pre>{JSON.stringify(status, null, 2)}</pre>
        </section>
      )}

      {batchData && (
        <section className="card compact">
          <h2>Generated Response</h2>
          <pre>{JSON.stringify(batchData, null, 2)}</pre>
        </section>
      )}

      {manifestData && (
        <section className="card compact">
          <h2>Manifest Details</h2>
          <pre>{JSON.stringify(manifestData, null, 2)}</pre>
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
