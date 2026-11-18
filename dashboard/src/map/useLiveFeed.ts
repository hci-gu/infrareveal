import { useMemo, useState } from 'react'
import type { TrafficChunk } from '@infrareveal/session-state'
import type { WorkspaceState } from './mapWorkspace'
import type { TrackColors } from './mapTracks'
import { FEED_JUMP_MS, FEED_LIMIT, FEED_SPAN_MS, feedLines, feedRate, mergeFeed } from './liveFeed'
import type { FeedLine } from './liveFeed'

export type LiveFeedState = ReturnType<typeof useLiveFeed> & { clientColors: TrackColors }

const clientHidden = (state: WorkspaceState) => {
  const hidden = new Set((state.hiddenClients ?? []).map(client => client.key))
  return hidden.size ? (chunk: TrafficChunk) => hidden.has(chunk.client_id) || hidden.has(`ip:${chunk.client_ip}`) : undefined
}

export function useLiveFeed(chunks: readonly TrafficChunk[], cursorMs: number, sessionId: string, state: WorkspaceState) {
  const scope = `${sessionId}|${(state.hiddenClients ?? []).map(client => client.key).join(',')}`
  const hiddenKey = (state.hiddenClients ?? []).map(client => client.key).join('|')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const computed = useMemo(() => feedLines(chunks, cursorMs - FEED_SPAN_MS, cursorMs + 1, clientHidden(state)), [chunks, cursorMs, hiddenKey])
  const [feed, setFeed] = useState({ scope, cursorMs, source: null as FeedLine[] | null, lines: [] as FeedLine[] })
  if (feed.source !== computed) {
    // Scrubbing or switching session restarts the stream; playback appends to it.
    const restart = feed.scope !== scope || cursorMs < feed.cursorMs - 1_000 || cursorMs - feed.cursorMs > FEED_JUMP_MS
    setFeed({ scope, cursorMs, source: computed, lines: restart ? computed.slice(0, FEED_LIMIT) : mergeFeed(feed.lines, computed) })
  }
  return { lines: feed.lines, rate: feedRate(computed, cursorMs) }
}

