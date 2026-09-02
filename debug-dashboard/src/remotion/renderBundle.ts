import type { SceneWindow } from './SessionComposition'

export type RecordedRenderBundle = {
  version: 1
  sessionId: string
  createdAt: string
  sceneWindow: SceneWindow
}

export function createRecordedRenderBundle(
  sessionId: string,
  sceneWindow: SceneWindow,
  createdAt = new Date().toISOString(),
): RecordedRenderBundle {
  const frozenScene = JSON.parse(JSON.stringify(sceneWindow)) as SceneWindow
  return { version: 1, sessionId, createdAt, sceneWindow: frozenScene }
}

export function parseRecordedRenderBundle(value: string): RecordedRenderBundle {
  const parsed = JSON.parse(value) as Partial<RecordedRenderBundle>
  if (parsed.version !== 1 || !parsed.sessionId || !parsed.sceneWindow) {
    throw new Error('Unsupported or malformed InfraReveal render bundle.')
  }
  return parsed as RecordedRenderBundle
}
