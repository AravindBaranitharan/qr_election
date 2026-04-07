import { useEffect, useRef, useState } from 'react'
import QrScanner from 'qr-scanner'

function readTokenFromPath() {
  const match = window.location.pathname.match(/^\/(?:c|claim)\/([0-9a-fA-F]+)$/)
  return match ? match[1].toLowerCase() : null
}

function isSuperAdminPath() {
  return window.location.pathname === '/superadmin' || window.location.pathname.startsWith('/superadmin/')
}

function isDatabasePath() {
  return window.location.pathname === '/database' || window.location.pathname === '/database/'
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

function toPrettyJson(value) {
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
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
        <strong>{result?.remaining ?? '-'}</strong>
        <small>Remaining</small>
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

      <section className="card compact">
        <h2>Dashboard Routes</h2>
        <div className="admin-links">
          <a href="/database">Database Details</a>
        </div>
      </section>

      {error && (
        <section className="card compact error-box">
          <p>{error}</p>
        </section>
      )}
    </main>
  )
}

function DatabaseScreen() {
  const [details, setDetails] = useState(null)
  const [error, setError] = useState('')
  const [saveMessage, setSaveMessage] = useState('')
  const [saving, setSaving] = useState(false)
  const [formInitialized, setFormInitialized] = useState(false)
  const [formData, setFormData] = useState({
    total_qr: '',
    next_serial: '',
    add_serials: '',
    remove_serials: '',
    remove_range_start: '',
    remove_range_end: '',
  })

  async function loadDatabaseDetails() {
    try {
      const response = await fetch('/database_details', { cache: 'no-store' })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error(payload?.message || 'unable to load database details')
      }
      setDetails(payload)
      setError('')
    } catch (detailsError) {
      setError(String(detailsError))
    }
  }

  function applyFormFromState(state) {
    setFormData({
      total_qr: String(Number(state?.total_qr || 0)),
      next_serial: String(Number(state?.next_serial || 1)),
      add_serials: '',
      remove_serials: '',
      remove_range_start: '',
      remove_range_end: '',
    })
    setFormInitialized(true)
  }

  function onFieldChange(key, value) {
    setFormData((prev) => ({ ...prev, [key]: value }))
  }

  async function saveLiveState(event) {
    event.preventDefault()
    setSaving(true)
    setSaveMessage('')
    try {
      const response = await fetch('/database_state_update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        body: JSON.stringify({
          total_qr: Number(formData.total_qr || 0),
          next_serial: Number(formData.next_serial || 1),
          add_serials: formData.add_serials,
          remove_serials: formData.remove_serials,
          remove_range_start: formData.remove_range_start,
          remove_range_end: formData.remove_range_end,
        }),
      })
      const payload = await response.json()
      if (!response.ok || !payload?.true) {
        throw new Error(payload?.message || 'unable to save state')
      }
      setSaveMessage(
        `Live database state updated. Added ${Number(payload?.added_count || 0)}, removed ${Number(payload?.removed_count || 0)}.`,
      )
      setDetails((prev) => ({ ...prev, state: payload?.state || prev?.state }))
      applyFormFromState(payload?.state || {})
      await loadDatabaseDetails()
    } catch (saveError) {
      setSaveMessage(String(saveError))
    } finally {
      setSaving(false)
    }
  }

  useEffect(() => {
    loadDatabaseDetails()
    const timer = window.setInterval(loadDatabaseDetails, 4000)
    return () => window.clearInterval(timer)
  }, [])

  useEffect(() => {
    if (details?.state && !formInitialized) {
      applyFormFromState(details.state)
    }
  }, [details?.state, formInitialized])

  const storage = details?.storage || {}
  const environment = details?.environment || {}
  const database = details?.database || {}
  const connection = database?.connection || {}
  const state = details?.state || {}

  return (
    <main className="admin-shell">
      <section className="card compact">
        <div className="status-head">
          <h1>Database</h1>
          <div className="admin-links">
            <a href="/superadmin">Back</a>
            <a href="/database/logout">Lock</a>
          </div>
        </div>
        <p className="muted">Full database diagnostics and current QR state.</p>
      </section>

      {details && (
        <>
          <section className="card compact">
            <h2>Connection Summary</h2>
            <div className="admin-status-grid">
              <article className="status-tile">
                <small>Storage Mode</small>
                <strong>{storage?.mode || '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Environment</small>
                <strong>{environment?.name || '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Connected</small>
                <strong>{connection?.connected ? 'yes' : 'no'}</strong>
              </article>
              <article className="status-tile">
                <small>Host</small>
                <strong>{database?.host || '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Database</small>
                <strong>{database?.database || '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Table</small>
                <strong>{storage?.table_name || '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Ping Interval</small>
                <strong>{connection?.ping_interval_seconds ? `${connection.ping_interval_seconds}s` : '-'}</strong>
              </article>
              <article className="status-tile">
                <small>Last Ping</small>
                <strong>{connection?.last_checked_at || '-'}</strong>
              </article>
            </div>
          </section>

          <section className="card compact">
            <h2>State Snapshot</h2>
            <div className="admin-status-grid">
              <article className="status-tile">
                <small>Total QR</small>
                <strong>{Number(state?.total_qr || 0)}</strong>
              </article>
              <article className="status-tile">
                <small>Accepted</small>
                <strong>{Number(state?.true_count || 0)}</strong>
              </article>
              <article className="status-tile">
                <small>Next Serial</small>
                <strong>{Number(state?.next_serial || 0)}</strong>
              </article>
              <article className="status-tile">
                <small>Scanned Serials</small>
                <strong>{Array.isArray(state?.scanned_serials) ? state.scanned_serials.length : 0}</strong>
              </article>
              <article className="status-tile">
                <small>Manifest Count</small>
                <strong>{Number(details?.manifest_count || 0)}</strong>
              </article>
              <article className="status-tile">
                <small>Updated At</small>
                <strong>{details?.updated_at || '-'}</strong>
              </article>
            </div>
          </section>

          <section className="card compact">
            <h2>Edit Serials</h2>
            <p className="muted">
              Add or remove serials with commas, and remove a range by start/end. No full array editing.
            </p>
            <form className="admin-form" onSubmit={saveLiveState}>
              <label htmlFor="total_qr">Total QR</label>
              <input
                id="total_qr"
                value={formData.total_qr}
                onChange={(event) => onFieldChange('total_qr', event.target.value)}
                inputMode="numeric"
              />

              <label htmlFor="next_serial">Next Serial</label>
              <input
                id="next_serial"
                value={formData.next_serial}
                onChange={(event) => onFieldChange('next_serial', event.target.value)}
                inputMode="numeric"
              />

              <label htmlFor="add_serials">Add Serials (comma-separated)</label>
              <input
                id="add_serials"
                value={formData.add_serials}
                onChange={(event) => onFieldChange('add_serials', event.target.value)}
                placeholder="1, 2, 7, 22"
              />

              <label htmlFor="remove_serials">Remove Serials (comma-separated)</label>
              <input
                id="remove_serials"
                value={formData.remove_serials}
                onChange={(event) => onFieldChange('remove_serials', event.target.value)}
                placeholder="3, 4, 8"
              />

              <label htmlFor="remove_range_start">Remove Range Start</label>
              <input
                id="remove_range_start"
                value={formData.remove_range_start}
                onChange={(event) => onFieldChange('remove_range_start', event.target.value)}
                inputMode="numeric"
                placeholder="100"
              />

              <label htmlFor="remove_range_end">Remove Range End</label>
              <input
                id="remove_range_end"
                value={formData.remove_range_end}
                onChange={(event) => onFieldChange('remove_range_end', event.target.value)}
                inputMode="numeric"
                placeholder="150"
              />

              <button type="submit" disabled={saving}>
                {saving ? 'Applying...' : 'Apply Changes'}
              </button>
              {saveMessage && <p className="mini">{saveMessage}</p>}
            </form>
          </section>

          <section className="card compact">
            <h2>Raw Details</h2>
            <pre>{toPrettyJson(details)}</pre>
          </section>
        </>
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
  const [database] = useState(() => isDatabasePath())
  const [superadmin] = useState(() => isSuperAdminPath())

  if (token) return <SubmitOnlyScreen token={token} />
  if (database) return <DatabaseScreen />
  if (superadmin) return <SuperAdminScreen />
  return <LandingScannerScreen />
}

export default App
