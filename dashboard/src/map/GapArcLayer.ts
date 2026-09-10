import { ArcLayer } from '@deck.gl/layers'

/** A broken line marks the span between located hops when routers did not answer or could not be located. */
export class GapArcLayer<T> extends ArcLayer<T> {
  static layerName = 'GapArcLayer'
  getShaders() {
    const shaders = super.getShaders()
    return { ...shaders, inject: { ...shaders.inject, 'fs:#main-end': 'if (fract(uv.x / max(fwidth(uv.x) * 12.0, 0.0001)) > 0.55) discard;' } }
  }
}
