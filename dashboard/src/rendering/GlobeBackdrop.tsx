import { memo } from 'react'
import type { CSSProperties } from 'react'

/**
 * Space behind the globe: two parallax star layers, a sparse twinkling layer,
 * a faint Milky Way band and nebula wash, and an atmosphere glow hugging the
 * globe's rim. Star tiles are generated once (seeded, so they never change
 * between visits) and repeat as CSS backgrounds; moving them costs a repaint,
 * not a redraw, so it stays cheap on the Raspberry Pi.
 */
type Star = { x: number; y: number; r: number; alpha: number; tint: string; glow: boolean }

const TILE = 1024
/** Star colour temperatures, from blue-white to warm. */
const TINTS = ['#dfe8ff', '#cfdcff', '#ffffff', '#fff4e6', '#ffe6c7', '#c8f0ff']

function seeded(seed: number) {
  // mulberry32: small, fast and deterministic.
  return () => {
    seed = (seed + 0x6d2b79f5) | 0
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function stars(seed: number, count: number, size: [number, number], alpha: [number, number], glowShare: number): Star[] {
  const random = seeded(seed)
  return Array.from({ length: count }, () => ({
    x: random() * TILE, y: random() * TILE,
    // Most stars are faint; a few are bright (a power curve, as in the real sky).
    r: size[0] + (size[1] - size[0]) * random() ** 3,
    alpha: alpha[0] + (alpha[1] - alpha[0]) * random() ** 2,
    tint: TINTS[Math.floor(random() * TINTS.length)],
    glow: random() < glowShare,
  }))
}

function tile(list: Star[]): string {
  if (typeof document === 'undefined') return ''
  const scale = 2 // crisp on high-density displays; the tile is shown at TILE css px
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = TILE * scale
  const context = canvas.getContext('2d')
  if (!context) return ''
  context.scale(scale, scale)
  for (const star of list) {
    // Draw wrapped copies near the edges so the repeating tile has no seams.
    for (const dx of [0, -TILE, TILE]) for (const dy of [0, -TILE, TILE]) {
      const x = star.x + dx, y = star.y + dy
      if (x < -12 || x > TILE + 12 || y < -12 || y > TILE + 12) continue
      if (star.glow) {
        const halo = context.createRadialGradient(x, y, 0, x, y, star.r * 3.5)
        halo.addColorStop(0, `${star.tint}40`)
        halo.addColorStop(1, `${star.tint}00`)
        context.fillStyle = halo
        context.beginPath(); context.arc(x, y, star.r * 3.5, 0, Math.PI * 2); context.fill()
      }
      context.globalAlpha = star.alpha
      context.fillStyle = star.tint
      context.beginPath(); context.arc(x, y, star.r, 0, Math.PI * 2); context.fill()
      context.globalAlpha = 1
    }
  }
  return `url(${canvas.toDataURL('image/png')})`
}

let tiles: { far: string; near: string; twinkle: string } | null = null
function starTiles() {
  tiles ??= {
    far: tile(stars(7, 900, [0.25, 0.9], [0.18, 0.75], 0)),
    near: tile(stars(19, 110, [0.6, 1.7], [0.45, 1], 0.35)),
    twinkle: tile(stars(31, 28, [0.8, 1.5], [0.7, 1], 1)),
  }
  return tiles
}

export type GlobeFrame = { longitude: number; latitude: number; center: [number, number]; radius: number }

export const GlobeBackdrop = memo(function GlobeBackdrop({ frame }: { frame: GlobeFrame }) {
  const { far, near, twinkle } = starTiles()
  // Parallax: turning the globe slides the sky, the near layer faster than the far one.
  const shift = (factor: number) => `${-frame.longitude * factor}px ${frame.latitude * factor}px`
  const [x, y] = frame.center, r = frame.radius
  return <div className="atlas-space" aria-hidden="true">
    <div className="atlas-space-sky" />
    <div className="atlas-space-stars" style={{ backgroundImage: far, backgroundPosition: shift(1.5) } as CSSProperties} />
    <div className="atlas-space-stars" style={{ backgroundImage: near, backgroundPosition: shift(4) } as CSSProperties} />
    <div className="atlas-space-stars atlas-space-twinkle" style={{ backgroundImage: twinkle, backgroundPosition: shift(4) } as CSSProperties} />
    {/* Atmosphere: a thin bright rim fading outwards, centred on the globe as drawn. */}
    <div className="atlas-space-atmosphere" style={{
      background: `radial-gradient(circle at ${x}px ${y}px, transparent ${r * 0.965}px, rgba(110, 222, 199, 0.32) ${r}px, rgba(90, 160, 230, 0.12) ${r * 1.045}px, rgba(70, 110, 200, 0.04) ${r * 1.12}px, transparent ${r * 1.28}px)`,
    }} />
  </div>
})
