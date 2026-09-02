import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionsPage } from './pages/SessionsPage'

const MapPage = lazy(async () => {
  const module = await import('./pages/MapPage')
  return { default: module.MapPage }
})

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<RouteLoading />}>
        <Routes>
          <Route path="/" element={<SessionsPage />} />
          <Route path="/map/:sessionID" element={<MapPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}

function RouteLoading() {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 text-sm font-semibold text-white">
      Loading map…
    </main>
  )
}
