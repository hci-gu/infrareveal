export function BackToLatest({ paused, onClick }: { paused: boolean; onClick: () => void }) {
  return paused ? <button type="button" className="atlas-back-latest" onClick={onClick}>Back to latest ↑</button> : null
}
