import { Layer, _LayersPass } from '@deck.gl/core'
import type { Effect, EffectContext, LayerContext, PreRenderOptions, Viewport } from '@deck.gl/core'
import type { Device, Framebuffer } from '@luma.gl/core'
import { ClipSpace } from '@luma.gl/engine'

// Only ground/background geometry is cached. Columns, points, labels and
// animated streams retain their ordinary depth, picking and draw order.
const backgroundIds = new Set([
  'base-geography', 'country-footprints', 'country-outlines', 'country-connections',
  'atlas-grid', 'connection-strips', 'unknown-route-spans', 'traceroute-strips',
])

export class MercatorBackground implements Effect {
  id = 'mercator-background-cache'
  props = {}
  private device?: Device
  private pass?: _LayersPass
  framebuffer?: Framebuffer
  private layers: Layer[] = []
  private viewports: Viewport[] = []
  private loaded = false

  // Original geometry stays available to picking, including country footprints.
  filter = ({ layer, isPicking }: { layer: Layer; isPicking: boolean }) =>
    isPicking ? layer.id !== 'cached-background' : !backgroundIds.has(layer.id)

  setup({ device }: EffectContext) {
    this.device = device
    this.pass = new _LayersPass(device, { id: this.id })
  }

  preRender(options: PreRenderOptions) {
    if (options.isPicking || !this.device || !this.pass) return
    const layers = options.layers.filter(layer => backgroundIds.has(layer.id) && layer.props.visible)
    if (!layers.length) return
    const [width, height] = this.device.canvasContext!.getDrawingBufferSize()
    const resized = !this.framebuffer || this.framebuffer.width !== width || this.framebuffer.height !== height
    const loaded = layers.every(layer => layer.isLoaded)
    const changed = !this.loaded || resized || layers.length !== this.layers.length || layers.some((layer, i) => layer !== this.layers[i])
      || options.viewports.length !== this.viewports.length || options.viewports.some((viewport, i) => !viewport.equals(this.viewports[i]))
    if (!changed) return
    this.framebuffer ??= this.device.createFramebuffer({
      id: this.id, width, height, colorAttachments: ['rgba8unorm'], depthStencilAttachment: 'depth24plus-stencil8',
    })
    if (resized) this.framebuffer.resize({ width, height })
    this.pass.render({ ...options, target: this.framebuffer, layers,
      effects: options.effects?.filter(effect => effect !== this),
      layerFilter: null, clearCanvas: true, pass: 'mercator-background',
    })
    this.layers = layers
    this.viewports = options.viewports.slice()
    this.loaded = loaded
  }

  cleanup() {
    this.framebuffer?.destroy()
    this.pass?.cleanup()
    this.framebuffer = undefined
    this.pass = undefined
    this.device = undefined
    this.layers = []
    this.viewports = []
    this.loaded = false
  }
}

/** One cached screen texture, in the same WebGL context as the traffic. */
export class MercatorBackgroundLayer extends Layer<{ cache: MercatorBackground }> {
  static layerName = 'MercatorBackgroundLayer'
  static defaultProps = { cache: { type: 'object', value: null, compare: false } }

  initializeState() {
    // This screen quad has no geographic attributes/uniforms. Keep it outside
    // Layer.getModels(), which updates those inputs for ordinary map models.
    this.setState({ backgroundModel: new ClipSpace(this.context.device, {
      id: this.id,
      fs: `#version 300 es
        precision highp float;
        uniform sampler2D background;
        in vec2 uv;
        out vec4 fragColor;
        void main() { fragColor = texture(background, uv); }
      `,
      parameters: { depthCompare: 'always', depthWriteEnabled: false,
        // The transparent framebuffer already contains premultiplied RGB.
        blendColorSrcFactor: 'one', blendColorDstFactor: 'one-minus-src-alpha',
      },
    }) })
  }

  finalizeState(context: LayerContext) {
    ;(this.state.backgroundModel as ClipSpace | undefined)?.destroy()
    super.finalizeState(context)
  }

  draw() {
    const texture = this.props.cache.framebuffer?.colorAttachments[0]
    const model = this.state.backgroundModel as ClipSpace
    if (!texture) return
    model.setBindings({ background: texture })
    model.draw(this.context.renderPass)
  }
}
