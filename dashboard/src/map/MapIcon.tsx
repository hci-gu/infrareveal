export type MapIconName = 'globe' | 'back' | 'play' | 'pause' | 'rewind' | 'forward' | 'expand' | 'plus' | 'minus' | 'target' | 'layers' | 'route' | 'close' | 'arrow' | 'activity' | 'pin' | 'settings'

const paths: Record<MapIconName, string> = {
  settings: 'M4 7h16M4 17h16M9 4v6M15 14v6',
  globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18Z',
  back: 'm14 6-6 6 6 6M8 12h12',
  play: 'm8 5 11 7-11 7V5Z',
  pause: 'M8 5v14M16 5v14',
  rewind: 'M4 9a8 8 0 1 1 0 6M4 3v6h6M10 10v5M13 10h3v5h-3v-5Z',
  forward: 'M20 9a8 8 0 1 0 0 6M20 3v6h-6M9 10v5M12 10h3v5h-3v-5Z',
  expand: 'M8 3H3v5M16 3h5v5M21 16v5h-5M3 16v5h5',
  plus: 'M12 5v14M5 12h14',
  minus: 'M5 12h14',
  target: 'M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM12 2v3M12 19v3M2 12h3M19 12h3M20 12a8 8 0 1 1-16 0 8 8 0 0 1 16 0Z',
  layers: 'm12 3 9 5-9 5-9-5 9-5ZM3 12l9 5 9-5M3 16l9 5 9-5',
  route: 'M7 5a2 2 0 1 1-4 0 2 2 0 0 1 4 0ZM21 19a2 2 0 1 1-4 0 2 2 0 0 1 4 0ZM7 5h10a4 4 0 0 1 0 8H7a3 3 0 0 0 0 6h10',
  close: 'm6 6 12 12M6 18 18 6',
  arrow: 'M5 12h14m-5-5 5 5-5 5',
  activity: 'M2 12h5l3-8 4 16 3-8h5',
  pin: 'M19 10c0 5-7 11-7 11S5 15 5 10a7 7 0 1 1 14 0ZM14 10a2 2 0 1 1-4 0 2 2 0 0 1 4 0Z',
}

export function MapIcon({ name, size = 18 }: { name: MapIconName; size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>
}
