import type { ServiceGroup } from './sessionModel'

export type TreemapNode = {
  group: ServiceGroup
  x: number
  y: number
  width: number
  height: number
}

type Rect = {
  x: number
  y: number
  width: number
  height: number
}

export function buildTreemap(groups: ServiceGroup[], width: number, height: number): TreemapNode[] {
  const items = groups
    .filter((group) => group.totalBytes > 0 || group.flowCount > 0)
    .sort((a, b) => groupWeight(b) - groupWeight(a) || a.label.localeCompare(b.label))

  if (items.length === 0) {
    return []
  }

  return layoutSlice(items, { x: 0, y: 0, width, height }, true)
}

function layoutSlice(groups: ServiceGroup[], rect: Rect, splitVertical: boolean): TreemapNode[] {
  if (groups.length === 0) {
    return []
  }

  if (groups.length === 1) {
    return [{ group: groups[0], ...rect }]
  }

  const total = sumWeight(groups)
  const half = total / 2
  let running = 0
  let splitIndex = 1

  for (let index = 0; index < groups.length; index += 1) {
    const next = running + groups[index].totalBytes
    if (index > 0 && Math.abs(half - running) <= Math.abs(half - next)) {
      splitIndex = index
      break
    }
    running = next
    splitIndex = index + 1
  }

  splitIndex = Math.min(Math.max(splitIndex, 1), groups.length - 1)
  const first = groups.slice(0, splitIndex)
  const second = groups.slice(splitIndex)
  const firstRatio = sumWeight(first) / total

  if (splitVertical) {
    const firstWidth = rect.width * firstRatio
    return [
      ...layoutSlice(first, { ...rect, width: firstWidth }, false),
      ...layoutSlice(
        second,
        {
          x: rect.x + firstWidth,
          y: rect.y,
          width: rect.width - firstWidth,
          height: rect.height,
        },
        false,
      ),
    ]
  }

  const firstHeight = rect.height * firstRatio
  return [
    ...layoutSlice(first, { ...rect, height: firstHeight }, true),
    ...layoutSlice(
      second,
      {
        x: rect.x,
        y: rect.y + firstHeight,
        width: rect.width,
        height: rect.height - firstHeight,
      },
      true,
    ),
  ]
}

function sumWeight(groups: ServiceGroup[]) {
  return groups.reduce((total, group) => total + groupWeight(group), 0)
}

function groupWeight(group: ServiceGroup) {
  return group.totalBytes || group.flowCount
}
