import { ArcLayer } from '@deck.gl/layers'
import type { Accessor } from '@deck.gl/core'
import { Geometry, Model } from '@luma.gl/engine'
import type { ShaderModule } from '@luma.gl/shadertools'

const SEGMENTS = 160
const SIDES = 12
export const trafficUniforms = {
  name: 'traffic',
  vs: `layout(std140) uniform trafficUniforms {
    float phase;
    float motion;
    float clock;
  } traffic;`,
  uniformTypes: { phase: 'f32', motion: 'f32', clock: 'f32' },
} as const satisfies ShaderModule<{ phase: number; motion: number; clock: number }>

type VolumeProps<T> = {
  time: number
  phase: number
  motion: number
  getRadii0: Accessor<T, number[]>
  getRadii1: Accessor<T, number[]>
  getRadii2: Accessor<T, number[]>
  getDirection: Accessor<T, number>
  getProgress: Accessor<T, number[]>
}

const vertexShader = `#version 300 es
#define SHADER_NAME traffic-volume-vertex
in vec2 positions;
in vec3 instanceSourcePositions;
in vec3 instanceSourcePositions64Low;
in vec3 instanceTargetPositions;
in vec3 instanceTargetPositions64Low;
in vec4 instanceSourceColors;
in vec4 instanceTargetColors;
in float instanceHeights;
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

vec3 sphere(vec2 lngLat) {
  vec2 r = radians(lngLat);
  return vec3(cos(r.y) * cos(r.x), cos(r.y) * sin(r.x), sin(r.y));
}
vec3 pointOnArc(float t) {
  vec3 a = sphere(instanceSourcePositions.xy);
  vec3 b = sphere(instanceTargetPositions.xy);
  float angle = acos(clamp(dot(a, b), -1.0, 1.0));
  vec2 lngLat;
  if (angle < 0.00001 || abs(angle - PI) < 0.001) {
    float delta = mod(instanceTargetPositions.x - instanceSourcePositions.x + 540.0, 360.0) - 180.0;
    lngLat = vec2(instanceSourcePositions.x + delta * t, mix(instanceSourcePositions.y, instanceTargetPositions.y, t));
    lngLat.x = mod(lngLat.x + 540.0, 360.0) - 180.0;
  } else {
    vec3 p = a * sin((1.0 - t) * angle) + b * sin(t * angle);
    lngLat = degrees(vec2(atan(p.y, p.x), atan(p.z, length(p.xy))));
  }
  float height = sqrt(max(0.0, t * (1.0 - t))) * angle * EARTH_RADIUS * instanceHeights;
  return vec3(lngLat, mix(instanceSourcePositions.z, instanceTargetPositions.z, t) + height);
}
float historyValue(int i) {
  if (i < 4) return instanceRadii0[clamp(i, 0, 3)];
  if (i < 8) return instanceRadii1[i - 4];
  return instanceRadii2[clamp(i - 8, 0, 3)];
}
float radiusAt(float t) {
  // Accent motion stays on the timeline clock, independent of sample updates.
  float pathProgress = mix(instanceProgress.x, instanceProgress.y, t);
  // Smooth width over one bucket without resetting the travelling accent.
  float amount = mix(historyValue(1), historyValue(0), smoothstep(0.0, 1.0, traffic.phase));
  float phase = pathProgress * instanceDirection * 2.0 - traffic.clock * traffic.motion * 0.5;
  float wave = pow(0.5 + 0.5 * cos(phase * 2.0 * PI), 2.0);
  float envelope = 0.12 + 0.88 * wave;
  float ends = smoothstep(0.0, 0.018, t) * (1.0 - smoothstep(0.982, 1.0, t));
  return amount * envelope * ends;
}
void main() {
  float t = positions.x;
  float dt = 1.0 / ${SEGMENTS}.0;
  vec3 world = pointOnArc(t);
  vec3 prevWorld = pointOnArc(max(0.0, t - dt));
  vec3 nextWorld = pointOnArc(min(1.0, t + dt));
  // Omit the seam cell instead of drawing a triangle across the world.
  vValid = abs(prevWorld.x - world.x) > 180.0 || abs(nextWorld.x - world.x) > 180.0 ? 0.0 : 1.0;
  vec3 low = mix(instanceSourcePositions64Low, instanceTargetPositions64Low, t);
  vec3 center = project_position(world, low);
  vec3 before = project_position(prevWorld, low);
  vec3 after = project_position(nextWorld, low);
  vec3 tangent = normalize(after - before + vec3(0.0000001, 0.0, 0.0));
  vec3 side = normalize(cross(tangent, vec3(0.0, 0.0, 1.0)) + vec3(0.0000001, 0.0, 0.0));
  vec3 up = normalize(cross(side, tangent));
  vec3 radial = cos(positions.y) * side + sin(positions.y) * up;
  float radius = radiusAt(t);
  float slope = (radiusAt(min(1.0, t + dt)) - radiusAt(max(0.0, t - dt))) / max(0.00001, length(after - before) * project.scale);
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

export const trafficFragmentShader = `#version 300 es
#define SHADER_NAME traffic-volume-fragment
precision highp float;
in vec4 vColor;
in vec3 vNormal;
in vec3 vEye;
in float vRadius;
in float vValid;
out vec4 fragColor;
void main() {
  if (vValid < 0.99 || vRadius < 0.18) discard;
  vec3 normal = normalize(vNormal);
  vec3 light = normalize(vec3(-0.35, -0.65, 0.9));
  vec3 eye = normalize(vEye);
  float diffuse = max(0.0, dot(normal, light));
  float shine = pow(max(0.0, dot(normalize(light + eye), normal)), 36.0);
  vec3 color = vColor.rgb * (0.3 + diffuse * 0.7) + mix(vColor.rgb, vec3(1.0), 0.7) * shine * 0.65;
  fragColor = vec4(color, vColor.a * smoothstep(0.18, 0.65, vRadius));
  DECKGL_FILTER_COLOR(fragColor, geometry);
}
`

/** A real round mesh: light and depth reveal the swelling volume from any camera angle. */
export class FlowArcLayer<T> extends ArcLayer<T, VolumeProps<T>> {
  static layerName = 'FlowArcLayer'
  static defaultProps = {
    ...ArcLayer.defaultProps, time: 0, phase: 0, motion: 1,
    getRadii0: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii1: { type: 'accessor', value: [0, 0, 0, 0] },
    getRadii2: { type: 'accessor', value: [0, 0, 0, 0] },
    getProgress: { type: 'accessor', value: [0, 1] },
    getDirection: { type: 'accessor', value: 1 },
  }

  initializeState() {
    super.initializeState()
    this.getAttributeManager()!.addInstanced({
      instanceRadii0: { size: 4, accessor: 'getRadii0' },
      instanceRadii1: { size: 4, accessor: 'getRadii1' },
      instanceRadii2: { size: 4, accessor: 'getRadii2' },
      instanceProgress: { size: 2, accessor: 'getProgress' },
      instanceDirection: { size: 1, accessor: 'getDirection' },
    })
  }

  getShaders() {
    const shaders = super.getShaders()
    return { ...shaders, vs: vertexShader, fs: trafficFragmentShader, modules: [...shaders.modules, trafficUniforms] }
  }

  protected _getModel(): Model {
    const positions = new Float32Array((SEGMENTS + 1) * (SIDES + 1) * 2)
    const indices = new Uint16Array(SEGMENTS * SIDES * 6)
    for (let i = 0; i <= SEGMENTS; i += 1) {
      for (let j = 0; j <= SIDES; j += 1) {
        const offset = (i * (SIDES + 1) + j) * 2
        positions[offset] = i / SEGMENTS
        positions[offset + 1] = j / SIDES * Math.PI * 2
        if (i === SEGMENTS || j === SIDES) continue
        const a = i * (SIDES + 1) + j
        const b = a + SIDES + 1
        indices.set([a, b, a + 1, a + 1, b, b + 1], (i * SIDES + j) * 6)
      }
    }
    return new Model(this.context.device, {
      ...this.getShaders(), id: this.props.id,
      bufferLayout: this.getAttributeManager()!.getBufferLayouts(), isInstanced: true,
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
