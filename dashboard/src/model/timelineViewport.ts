export type TimelineFocusBounds = {
  start: number
  end: number
}

export function resolveTimelineViewport({
  currentFrame,
  durationInFrames,
  focusBounds,
  followLive,
  zoomFrames,
}: {
  currentFrame: number
  durationInFrames: number
  focusBounds?: TimelineFocusBounds | null
  followLive: boolean
  zoomFrames: number | 'all'
}) {
  const duration = Math.max(1, durationInFrames)
  const scope = normalizeBounds(focusBounds, duration)

  if (zoomFrames === 'all' || zoomFrames >= scope.end - scope.start) {
    return scope
  }

  const requestedAnchor = followLive ? scope.end : currentFrame
  const anchor = requestedAnchor >= scope.start && requestedAnchor <= scope.end
    ? requestedAnchor
    : scope.end
  const start = Math.max(
    scope.start,
    Math.min(anchor - zoomFrames * 0.82, scope.end - zoomFrames),
  )
  return {
    start,
    end: Math.min(scope.end, start + zoomFrames),
  }
}

export function activityVisualMetrics(domainFocused: boolean) {
  return domainFocused
    ? { columnWidth: 3, packetOnlyHeight: 3, minimumPayloadHeight: 5, maxDirectionalHeight: 25 }
    : { columnWidth: 1, packetOnlyHeight: 1, minimumPayloadHeight: 2, maxDirectionalHeight: 15 }
}

function normalizeBounds(bounds: TimelineFocusBounds | null | undefined, duration: number) {
  if (!bounds) return { start: 0, end: duration }
  const start = Math.max(0, Math.min(bounds.start, duration - 1))
  const end = Math.max(start + 1, Math.min(bounds.end, duration))
  return { start, end }
}
