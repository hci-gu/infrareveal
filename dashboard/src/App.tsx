import { lazy, Suspense } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { SessionsPage } from './pages/SessionsPage'
import { DisplayModeProvider } from './display/DisplayMode'
import { DisplayPage } from './pages/DisplayPage'

const StoragePage = lazy(() => import('./pages/StoragePage').then(module => ({ default: module.StoragePage })))

const DemoPage = lazy(() => import("./pages/DemoPage").then(module => ({ default: module.DemoPage })))

const MapPage = lazy(async () => {
  const module = await import('./pages/MapPage')
  return { default: module.MapPage }
})

export default function App() {
  return (
    <BrowserRouter>
      <DisplayModeProvider>
      <Suspense fallback={<RouteLoading />}>
        <Routes>
          <Route path="/" element={<SessionsPage />} />
          <Route path="/storage" element={<StoragePage />} />
          <Route path="/display" element={<DisplayPage />} />
          <Route path="/demo" element={<DemoPage />} />
          <Route path="/map/:sessionID" element={<MapPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
      </DisplayModeProvider>
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
