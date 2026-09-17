import { ArcLayer, SolidPolygonLayer } from '@deck.gl/layers'
import { FlowArcLayer } from './FlowArcLayer'

/** Screen-space hatching remains legible at every zoom and is clipped by the country polygon. */
export class CountryFootprintLayer<T> extends SolidPolygonLayer<T> {
  static layerName = 'CountryFootprintLayer'
  getShaders(type: string) {
    const shaders = super.getShaders(type)
    return { ...shaders, inject: { ...shaders.inject, 'fs:DECKGL_FILTER_COLOR': 'color.a *= mix(0.45, 1.0, step(8.5, mod(gl_FragCoord.x + gl_FragCoord.y, 10.0)));' } }
  }
}

/** Country connections dissolve into an area without terminating at a map pin. */
export class CountryArcLayer<T> extends ArcLayer<T> {
  static layerName = 'CountryArcLayer'
  getShaders() {
    const shaders = super.getShaders()
    return { ...shaders, inject: { ...shaders.inject, 'fs:#main-end': 'if (fract(uv.x / max(fwidth(uv.x) * 12.0, 0.0001)) > 0.55) discard; fragColor.a *= 1.0 - smoothstep(0.65, 0.95, uv.x);' } }
  }
}

export class CountryFlowArcLayer<T> extends FlowArcLayer<T> {
  static layerName = 'CountryFlowArcLayer'
  getShaders() {
    const shaders = super.getShaders()
    return { ...shaders, inject: { ...shaders.inject, 'vs:#main-end': 'vColor.a *= 1.0 - smoothstep(0.65, 0.95, positions.x);' } }
  }
}
