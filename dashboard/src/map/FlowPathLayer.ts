import type { Accessor } from '@deck.gl/core'
import { TrafficLayer, trafficHistoryShader } from './FlowArcLayer'
import { TRAFFIC_TRAVEL_SECONDS } from './mapTraffic'

type Props<T> = {
  getPreviousPosition: Accessor<T, number[]>
  getNextPosition: Accessor<T, number[]>
}
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

${trafficHistoryShader}
float radiusAt(float progress) {
  float amount = transportedRadius(progress);
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
#ifdef LOW_DETAIL
  vNormal = radial;
#else
  float slope = (radiusAt(instanceProgress.y) - radiusAt(instanceProgress.x)) / max(0.00001, length(after - before) * project.scale);
  vNormal = normalize(radial - tangent * slope);
#endif
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
export class FlowPathLayer<T> extends TrafficLayer<T, Props<T>> {
  static layerName = 'FlowPathLayer'
  static defaultProps = {
    ...TrafficLayer.defaultProps,
    getPreviousPosition: { type: 'accessor', value: [0, 0, 0] },
    getNextPosition: { type: 'accessor', value: [0, 0, 0] },
  }
  initializeState() {
    super.initializeState()
    this.getAttributeManager()!.addInstanced({
      instancePreviousPositions: { size: 3, accessor: 'getPreviousPosition' },
      instanceNextPositions: { size: 3, accessor: 'getNextPosition' },
    })
  }
  getShaders() {
    return { ...super.getShaders(), vs }
  }
  protected meshResolution() {
    return { segments: 1, sides: this.props.numSegments <= 48 ? 4 : 12 }
  }
}
