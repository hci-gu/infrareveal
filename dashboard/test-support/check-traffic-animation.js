// Browser regression check. With `pnpm --dir dashboard dev` running, execute:
// await (await import('/test-support/check-traffic-animation.js')).checkTrafficAnimation()
// in the browser console (or via Playwright page.evaluate).
import { FlowArcLayer } from '../src/map/FlowArcLayer.ts'
import { CountryFlowArcLayer } from '../src/map/CountryLayers.ts'
import { seriesKey } from '@infrareveal/session-state'
import fixture from '../../testdata/aggregate-window-v2.json'
import { indexMapTraffic, projectTrafficProfiles, directionalVolumeArcs, trafficShaderClock, TRAFFIC_TRAVEL_SECONDS } from '../src/map/mapTraffic.ts'

export function checkTrafficAnimation(additionalLayers = []) {
  const gl = document.createElement('canvas').getContext('webgl2')
  if (!gl) throw new Error('WebGL2 is required')
  const failures = []
  const results = []
  const start = fixture.window.from_ms
  const chunk = { ...fixture.window.series[0], start_ms: start, bucket_ms: 500, chunk_ms: 5000,
    samples: [[1000, 500_000, 500_000, 500_000, 500_000, 10, 10]],
  }
  const coverage = [{ ...fixture.window.coverage[0], start_ms: start, end_ms: start + 10_000 }]
  const scene = { endpoints: [{ id: 'a', availableFromMs: start, series: [{ id: seriesKey(chunk), startMs: start, endMs: start + 10_000 }] }] }
  const burstIndex = indexMapTraffic([chunk], coverage)
  const burstLanes = ms => directionalVolumeArcs([{ endpointIds: ['a'] }], projectTrafficProfiles(scene, burstIndex, start + ms))
  const transit = []
  for (const Layer of [FlowArcLayer, CountryFlowArcLayer, ...additionalLayers]) {
    // Compile the production radius function, including its history lookup, without
    // the unrelated map projection. Transform feedback reads the actual GPU result.
    const layer = new Layer({ id: 'check' })
    layer.context = { defaultShaderModules: [] }
    const source = layer.getShaders().vs
    const functions = source.slice(source.indexOf('float historyValue'), source.indexOf('void main()'))
    const program = gl.createProgram()
    const shaders = []
    function compile(type, text) {
      const shader = gl.createShader(type)
      gl.shaderSource(shader, text)
      gl.compileShader(shader)
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader))
      gl.attachShader(program, shader)
      shaders.push(shader)
    }
    compile(gl.VERTEX_SHADER, `#version 300 es
precision highp float;
#define PI 3.141592653589793
uniform vec4 instanceRadii0;
uniform vec4 instanceRadii1;
uniform vec4 instanceRadii2;
uniform float instanceDirection;
uniform float probeProgress;
struct Traffic { float phase; float clock; };
uniform Traffic traffic;
out float result;
${functions}
void main() { result = radiusAt(probeProgress); gl_Position = vec4(0.0); }
`)
    compile(gl.FRAGMENT_SHADER, '#version 300 es\nprecision highp float; out vec4 color; void main() { color = vec4(1.0); }')
    gl.transformFeedbackVaryings(program, ['result'], gl.INTERLEAVED_ATTRIBS)
    gl.linkProgram(program)
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program))
    gl.useProgram(program)
    const buffer = gl.createBuffer()
    gl.bindBuffer(gl.TRANSFORM_FEEDBACK_BUFFER, buffer)
    gl.bufferData(gl.TRANSFORM_FEEDBACK_BUFFER, 4, gl.DYNAMIC_READ)
    gl.bindBufferBase(gl.TRANSFORM_FEEDBACK_BUFFER, 0, buffer)
    gl.enable(gl.RASTERIZER_DISCARD)
    function radius(lane, phase, clock = 0, progress = .5) {
      const radii = lane?.radii ?? Array(12).fill(0)
      for (let i = 0; i < 3; i++) gl.uniform4fv(gl.getUniformLocation(program, `instanceRadii${i}`), radii.slice(i * 4, i * 4 + 4))
      gl.uniform1f(gl.getUniformLocation(program, 'instanceDirection'), lane?.direction ?? 1)
      gl.uniform1f(gl.getUniformLocation(program, 'probeProgress'), progress)
      gl.uniform1f(gl.getUniformLocation(program, 'traffic.phase'), phase)
      gl.uniform1f(gl.getUniformLocation(program, 'traffic.clock'), trafficShaderClock(clock))
      gl.beginTransformFeedback(gl.POINTS)
      gl.drawArrays(gl.POINTS, 0, 1)
      gl.endTransformFeedback()
      const result = new Float32Array(1)
      gl.getBufferSubData(gl.TRANSFORM_FEEDBACK_BUFFER, 0, result)
      return result[0]
    }
    for (const direction of [1, -1]) {
      // Seeking depends only on capture history and the absolute clock.
      const lane = burstLanes(4000).find(lane => lane.direction === direction)
      const first = radius(lane, 0.4, 4.2)
      radius(burstLanes(4500).find(lane => lane.direction === direction), 0.8, 4.9)
      if (radius(lane, 0.4, 4.2) !== first) failures.push('Seeking changed the radius')
      // A long-running lab must retain smooth float32 phase and wrap seamlessly.
      const steady = { direction, radii: Array(12).fill(8) }
      const week = 7 * 24 * 3600
      const late = radius(steady, .5, week * 12 + .1)
      if (Math.abs(late - radius(steady, .5, .1)) > .001) failures.push(`${Layer.layerName} loses phase precision after weeks of uptime`)
      const wrapJump = Math.abs(radius(steady, .5, 1024 - .0001) - radius(steady, .5, 1024 + .0001))
      if (wrapJump > .001) failures.push(`${Layer.layerName} resets at the GPU clock wrap`)
      // A brief measured burst must finish travelling after the source is silent.
      for (const distance of [.2, .4, .6, .8]) {
        const seconds = 2 + distance * TRAFFIC_TRAVEL_SECONDS
        const anchor = Math.floor(seconds * 2) * 500
        const phase = (seconds * 1000 - anchor) / 500
        const lane = burstLanes(anchor).find(lane => lane.direction === direction)
        const progress = direction === 1 ? distance : 1 - distance
        const value = radius(lane, phase, seconds, progress)
        transit.push({ layer: Layer.layerName, direction, distance, radius: value })
        if (value < .18) failures.push(`${Layer.layerName} direction ${direction} erases a travelling burst at ${distance * 100}% of its path`)
        const behind = direction === 1 ? Math.max(.02, progress - .3) : Math.min(.98, progress + .3)
        const ahead = direction === 1 ? Math.min(.98, progress + .3) : Math.max(.02, progress - .3)
        if (distance >= .4 && radius(lane, phase, seconds, behind) > .001) failures.push(`${Layer.layerName} leaves the burst behind instead of transporting it`)
        if (distance <= .6 && radius(lane, phase, seconds, ahead) > .001) failures.push(`${Layer.layerName} shows a burst before it arrives`)
      }
      for (const progress of [.2, .5, .8]) for (let boundary = 1500; boundary <= 6500; boundary += 500) {
        const before = radius(burstLanes(boundary - 500).find(lane => lane.direction === direction), 1 - 1e-5, boundary / 1000 - .000005, progress)
        const after = radius(burstLanes(boundary).find(lane => lane.direction === direction), 0, boundary / 1000, progress)
        const jump = Math.abs(after - before)
        results.push({ layer: Layer.layerName, direction, boundary, progress, jump })
        if (jump > .001) failures.push(`${Layer.layerName} travelling history resets at ${boundary}ms`)
      }
      const quiet = burstLanes(7000).find(lane => lane.direction === direction)
      for (const progress of [.2, .5, .8]) if (radius(quiet, 0, 7, progress) !== 0) failures.push(`${Layer.layerName} retains a burst after it finishes`)
    }
    gl.disable(gl.RASTERIZER_DISCARD)
    gl.deleteBuffer(buffer)
    for (const shader of shaders) gl.deleteShader(shader)
    gl.deleteProgram(program)
  }
  gl.getExtension('WEBGL_lose_context')?.loseContext()
  return { passed: failures.length === 0, failures, maxBoundaryJump: Math.max(...results.map(result => result.jump)), checks: results.length, transit }
}
