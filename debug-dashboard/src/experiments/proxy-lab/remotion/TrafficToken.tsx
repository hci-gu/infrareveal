import { positionSceneToken, type SceneToken } from '../model/projectProxyScene'

export function TrafficToken({ token, cursorMs }: { token: SceneToken; cursorMs: number }) {
  const position = positionSceneToken(token, cursorMs)
  const edgeFade = Math.min(1, position.progress * 8, (1 - position.progress) * 8)
  const radius = 8 * token.scale
  return (
    <g
      aria-label={`${token.count} ${token.direction ?? 'status'} event${token.count === 1 ? '' : 's'}`}
      opacity={Math.max(0, edgeFade)}
      style={{ transform: `translate(${position.x}px, ${position.y}px)` }}
    >
      <circle fill={token.color} r={radius} stroke="#020617" strokeWidth={3} />
      {token.count > 1 ? (
        <text fill="#020617" fontFamily="ui-monospace, monospace" fontSize={9} fontWeight={800} textAnchor="middle" y={3}>
          {token.count > 99 ? '99+' : token.count}
        </text>
      ) : null}
    </g>
  )
}
