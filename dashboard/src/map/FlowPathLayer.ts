import { ArcLayer } from '@deck.gl/layers'
import { Geometry, Model } from '@luma.gl/engine'
import type { Accessor } from '@deck.gl/core'
import { trafficFragmentShader, trafficUniforms } from './FlowArcLayer'
import { TRAFFIC_TRAVEL_SECONDS } from './mapTraffic'

type Props<T> = {
  time: number; phase: number; motion: number
  getRadii0: Accessor<T, number[]>; getRadii1: Accessor<T, number[]>; getRadii2: Accessor<T, number[]>
  getDirection: Accessor<T, number>
  getProgress: Accessor<T, number[]>
  getPreviousPosition: Accessor<T, number[]>
  getNextPosition: Accessor<T, number[]>
}
const SIDES = 12
const vs = `#version 300 es
#define SHADER_NAME traffic-path-vertex
in vec2 positions;
in vec3 instanceSourcePositions;
in vec3 instanceSourcePositions64Low;
in vec3 instanceTargetPositions;
in vec3 instanceTargetPositions64Low;
in vec3 instancePreviousPositions;
in vec3 instanceNextPositions;
in vec4 instanceSourceColors;
in vec4 instanceTargetColors;
in vec4 instanceRadii0;
in vec4 instanceRadii1;
in vec4 instanceRadii2;
in vec2 instanceProgress;
in float instanceDirection;
out vec4 vColor;
out vec3 vNormal;
out vec3 vEye;
out float vRadius;
out float vValid;

float historyValue(int i) {
  if (i < 4) return instanceRadii0[clamp(i, 0, 3)];
  if (i < 8) return instanceRadii1[i - 4];
  return instanceRadii2[clamp(i - 8, 0, 3)];
}
float radiusAt(float progress) {
  float age = 0.0; // Apply the newest observed volume across every hop immediately.
  float index = clamp(age, 0.0, 10.999);
  float amount = mix(historyValue(int(floor(index))), historyValue(int(floor(index)) + 1), smoothstep(0.0, 1.0, fract(index)));
  float phase = progress * instanceDirection - traffic.clock * traffic.motion / ${TRAFFIC_TRAVEL_SECONDS}.0;
  float wave = pow(0.5 + 0.5 * cos(phase * 2.0 * PI), 4.0);
  // Only the two ends of the entire itinerary taper. Routers retain the passing volume.
  float ends = smoothstep(0.0, 0.015, progress) * (1.0 - smoothstep(0.985, 1.0, progress));
  return amount * (0.06 + 0.94 * wave) * ends;
}
void main() {
  float t = positions.x;
  vec3 world = mix(instanceSourcePositions, instanceTargetPositions, t);
  vec3 prevWorld = t < 0.5 ? instancePreviousPositions : instanceSourcePositions;
  vec3 nextWorld = t < 0.5 ? instanceTargetPositions : instanceNextPositions;
  vValid = abs(prevWorld.x - world.x) > 180.0 || abs(nextWorld.x - world.x) > 180.0 ? 0.0 : 1.0;
  vec3 low = mix(instanceSourcePositions64Low, instanceTargetPositions64Low, t);
  vec3 center = project_position(world, low);
  vec3 before = project_position(prevWorld);
  vec3 after = project_position(nextWorld);
  vec3 incoming = normalize(center - before + vec3(0.0000001, 0.0, 0.0));
  vec3 outgoing = normalize(after - center + vec3(0.0000001, 0.0, 0.0));
  vec3 tangent = normalize(incoming + outgoing + vec3(0.0000001, 0.0, 0.0));
  vec3 side = normalize(cross(tangent, vec3(0.0, 0.0, 1.0)) + vec3(0.0000001, 0.0, 0.0));
  vec3 up = normalize(cross(side, tangent));
  vec3 radial = cos(positions.y) * side + sin(positions.y) * up;
  float progress = mix(instanceProgress.x, instanceProgress.y, t);
  float radius = radiusAt(progress);
  float slope = (radiusAt(instanceProgress.y) - radiusAt(instanceProgress.x)) / max(0.00001, length(after - before) * project.scale);
  vNormal = normalize(radial - tangent * slope);
  vRadius = radius;
  vec3 position = center + side * project_pixel_size(instanceDirection * (radius + 1.0)) + radial * project_pixel_size(radius);
  vEye = project.cameraPosition - position;
  geometry.worldPosition = world;
  geometry.position = vec4(position, 1.0);
  gl_Position = project_common_position_to_clipspace(geometry.position);
  vColor = mix(instanceSourceColors, instanceTargetColors, t);
  vColor.a *= layer.opacity;
}
`

/** Joined tube rings along one sampled itinerary, with one source-to-destination clock. */
export class FlowPathLayer<T> extends ArcLayer<T, Props<T>> {
  static layerName = 'FlowPathLayer'
  static defaultProps = {
    ...ArcLayer.defaultProps, time: 0, phase: 0, motion: 1,
    getRadii0: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii1: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii2: { type: 'accessor', value: [0, 0, 0, 0] },
    getProgress: { type: 'accessor', value: [0, 1] },
    getDirection: { type: 'accessor', value: 1 },
    getPreviousPosition: { type: 'accessor', value: [0, 0, 0] },
    getNextPosition: { type: 'accessor', value: [0, 0, 0] },
  }
  initializeState() {
    super.initializeState()
    this.getAttributeManager()!.addInstanced({
      instanceRadii0: { size: 4, accessor: 'getRadii0' },
      instanceRadii1: { size: 4, accessor: 'getRadii1' },
      instanceRadii2: { size: 4, accessor: 'getRadii2' },
      instanceProgress: { size: 2, accessor: 'getProgress' },
      instanceDirection: { size: 1, accessor: 'getDirection' },
      instancePreviousPositions: { size: 3, accessor: 'getPreviousPosition' },
      instanceNextPositions: { size: 3, accessor: 'getNextPosition' },
    })
  }
  getShaders() {
    const shaders = super.getShaders()
    return { ...shaders, vs, fs: trafficFragmentShader, modules: [...shaders.modules, trafficUniforms] }
  }
  protected _getModel(): Model {
    const positions = new Float32Array(2 * (SIDES + 1) * 2)
    const indices = new Uint16Array(SIDES * 6)
    for (let ring = 0; ring < 2; ring++) {
      for (let side = 0; side <= SIDES; side++) {
        positions.set([ring, side / SIDES * Math.PI * 2], (ring * (SIDES + 1) + side) * 2)
        if (ring === 0 && side < SIDES) {
          const next = side + SIDES + 1
          indices.set([side, next, side + 1, side + 1, next, next + 1], side * 6)
        }
      }
    }
    return new Model(this.context.device, {
      ...this.getShaders(), id: this.props.id, bufferLayout: this.getAttributeManager()!.getBufferLayouts(), isInstanced: true,
      geometry: new Geometry({ topology: 'triangle-list', attributes: { positions: { size: 2, value: positions } }, indices }),
    })
  }
  draw() {
    const model = this.state.model
    if (!model) return
    model.shaderInputs.setProps({ traffic: { clock: this.props.time, phase: this.props.phase, motion: this.props.motion } })
    model.draw(this.context.renderPass)
  }
}
