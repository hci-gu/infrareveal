import { PathLayer } from '@deck.gl/layers'
import type { PathLayerProps } from '@deck.gl/layers'
import type { Accessor, DefaultProps } from '@deck.gl/core'
import type { ShaderModule } from '@luma.gl/shadertools'
import { trafficAnimationTime } from './mapPlaybackClock'
import type { TrafficAnimation } from './mapPlaybackClock'
import { trafficShaderClock, TRAFFIC_BUCKET_MS, TRAFFIC_HISTORY_LENGTH, TRAFFIC_TRAVEL_SECONDS } from './mapTraffic'

/** Largest traffic tube radius (`trafficRadius` caps at 16 px), plus the gap between the two directions. */
export const FLOW_PATH_MAX_RADIUS = 17
/** Each direction keeps to its own side, so the stroke must hold two full tubes. */
export const FLOW_PATH_WIDTH = FLOW_PATH_MAX_RADIUS * 4

const uniformBlock = `layout(std140) uniform flowPathUniforms {
  float phase;
  float clock;
  float lift;
} flowPath;`
const flowPathUniforms = {
  name: 'flowPath', vs: uniformBlock, fs: uniformBlock,
  uniformTypes: { phase: 'f32', clock: 'f32', lift: 'f32' },
} as const satisfies ShaderModule<{ phase: number; clock: number; lift: number }>

/**
 * WebGL guarantees only 16 vertex attributes and PathLayer already uses 13, so
 * each vertex's progress and the path's direction ride in its z coordinate:
 * z = lift + (progress + (direction < 0 ? 2 : 0)) * FLOW_Z_SCALE metres. A few
 * metres are invisible at map scale; `lift` raises paths above the globe's
 * surface (0 on flat maps) and must match the layer's `lift` prop. The scale
 * keeps the code well above float32 precision at globe altitudes. Use
 * `flowPathPosition` to build positions.
 */
const FLOW_Z_SCALE = 1
/** A path vertex carrying `progress` (0 at the path's start, 1 at its end) and the traffic direction. */
export const flowPathPosition = ([lon, lat]: readonly number[], progress: number, direction: number, lift = 0): [number, number, number] =>
  [lon, lat, lift + (progress + (direction < 0 ? 2 : 0)) * FLOW_Z_SCALE]

type FlowPathProps<T> = {
  animation: TrafficAnimation
  /** Altitude (m) the positions were built with by `flowPathPosition`. */
  lift: number
  getRadii0: Accessor<T, number[]>
  getRadii1: Accessor<T, number[]>
  getRadii2: Accessor<T, number[]>
}

/**
 * Traffic travelling along arbitrary paths (cable sections, route segments),
 * matching the arc streams: the recent rate history enters at the sending end
 * and moves along the path as a shaded tube whose thickness follows the rate,
 * with the same travelling accent. Sent and downloaded traffic keep to
 * opposite sides of the path. Only shader uniforms read the playback clock.
 */
export class FlowPathLayer<T> extends PathLayer<T, FlowPathProps<T>> {
  static layerName = 'FlowPathLayer'
  static defaultProps = {
    ...PathLayer.defaultProps,
    animation: { type: 'object', value: null, compare: false },
    lift: { type: 'number', value: 0 },
    getRadii0: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii1: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii2: { type: 'accessor', value: [0, 0, 0, 0] },
    widthUnits: 'pixels',
    getWidth: { type: 'accessor', value: FLOW_PATH_WIDTH },
    // The stroke is far wider than the visible tubes; mitred corners on sharp turns
    // (a branch meeting its trunk) would extend into long pixel-sized spikes.
    jointRounded: true,
    capRounded: true,
  } as unknown as DefaultProps<PathLayerProps>

  initializeState() {
    super.initializeState()
    this.getAttributeManager()!.addInstanced({
      instanceRadii0: { size: 4, accessor: 'getRadii0' },
      instanceRadii1: { size: 4, accessor: 'getRadii1' },
      instanceRadii2: { size: 4, accessor: 'getRadii2' },
    })
  }

  getShaders() {
    const shaders = super.getShaders()
    const travelBuckets = `${TRAFFIC_TRAVEL_SECONDS * 1000 / TRAFFIC_BUCKET_MS}.0`
    return {
      ...shaders,
      modules: [...shaders.modules, flowPathUniforms],
      inject: {
        ...shaders.inject,
        'vs:#decl': `
          in vec4 instanceRadii0;
          in vec4 instanceRadii1;
          in vec4 instanceRadii2;
          out float vProgress;
          out float vSegmentY;
          out vec2 vCorner;
          flat out float vSegmentLength;
          flat out vec4 vRadii0;
          flat out vec4 vRadii1;
          flat out vec4 vRadii2;
          flat out float vDirection;`,
        'vs:#main-end': `
          float startCode = (instanceStartPositions.z - flowPath.lift) / ${FLOW_Z_SCALE.toFixed(4)}, endCode = (instanceEndPositions.z - flowPath.lift) / ${FLOW_Z_SCALE.toFixed(4)};
          vDirection = startCode > 1.5 ? -1.0 : 1.0;
          float offset = vDirection < 0.0 ? 2.0 : 0.0;
          vProgress = mix(startCode - offset, endCode - offset, clamp(vPathPosition.y / max(vPathLength, 0.0001), 0.0, 1.0));
          vRadii0 = instanceRadii0; vRadii1 = instanceRadii1; vRadii2 = instanceRadii2;
          vSegmentY = vPathPosition.y; vSegmentLength = vPathLength; vCorner = vCornerOffset;`,
        'fs:#decl': `
          in float vProgress;
          in float vSegmentY;
          in vec2 vCorner;
          flat in float vSegmentLength;
          flat in vec4 vRadii0;
          flat in vec4 vRadii1;
          flat in vec4 vRadii2;
          flat in float vDirection;
          float flowHistory(int i) {
            if (i < 4) return vRadii0[clamp(i, 0, 3)];
            if (i < 8) return vRadii1[i - 4];
            return vRadii2[clamp(i - 8, 0, 3)];
          }
          float flowRadius(float progress) {
            // New measurements enter at the sending end; older samples continue in flight.
            float distance = vDirection > 0.0 ? progress : 1.0 - progress;
            float index = clamp(1.0 + distance * ${travelBuckets} - flowPath.phase, 0.0, ${TRAFFIC_HISTORY_LENGTH - 1}.999);
            int bucket = int(floor(index));
            float amount = mix(flowHistory(bucket), flowHistory(min(bucket + 1, ${TRAFFIC_HISTORY_LENGTH - 1})), smoothstep(0.0, 1.0, fract(index)));
            float wave = pow(0.5 + 0.5 * cos((progress * vDirection * 2.0 - flowPath.clock * 0.5) * 6.2831853), 2.0);
            float ends = smoothstep(0.0, 0.018, progress) * (1.0 - smoothstep(0.982, 1.0, progress));
            return amount * (0.12 + 0.88 * wave) * ends;
          }`,
        'fs:DECKGL_FILTER_COLOR': `
          float radius = flowRadius(vProgress);
          // uv.x runs -1..1 across the stroke; each direction's tube sits on its own side.
          float scale = ${FLOW_PATH_WIDTH / 2}.0;
          float side = vDirection * (radius + 1.0);
          float across = abs(geometry.uv.x * scale - side) / max(radius, 0.0001);
          if (radius < 0.18 || across > 1.0) discard;
          // Joints and caps extend each segment past its vertex by half the (wide) stroke.
          // There, keep only what the tube itself reaches around the vertex; otherwise a
          // sharp turn shows a straight, pixel-sized stub continuing the segment.
          bool beyondSegment = vSegmentY < 0.0 || vSegmentY > vSegmentLength;
          if (beyondSegment && length(vCorner) * scale > abs(side) + radius) discard;
          float shade = sqrt(1.0 - across * across);
          color.rgb = color.rgb * (0.35 + 0.65 * shade) + mix(color.rgb, vec3(1.0), 0.7) * pow(shade, 24.0) * 0.5;
          color.a *= smoothstep(0.18, 0.65, radius);`,
      },
    }
  }

  draw(options: Parameters<PathLayer<T>['draw']>[0]) {
    const { time, phase } = trafficAnimationTime(this.props.animation, TRAFFIC_BUCKET_MS)
    this.state.model?.shaderInputs.setProps({ flowPath: { clock: trafficShaderClock(time), phase, lift: this.props.lift } })
    super.draw(options)
  }
}
