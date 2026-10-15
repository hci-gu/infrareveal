import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it } from 'vitest'
import { DEMO_EPOCH_MS } from '../constants'
import { demoPipelineEvents } from '../data/demoTransport'
import { GraphViewport } from './GraphViewport'

it.each([0, 1000, 4200, 5500, 6800])('preserves graph geometry and traffic at %i ms', async offset => {
  const markup = renderToStaticMarkup(<GraphViewport
    events={demoPipelineEvents} cursorMs={DEMO_EPOCH_MS + offset}
    selectedEventId={null} path={null} selectedNode={null} branches
    transform={{ x: 0, y: 0, zoom: 1 }} onTransform={() => {}} onSelect={() => {}} reduceMotion={false}
  />)
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(markup))
  expect(Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')).toMatchSnapshot()
})
