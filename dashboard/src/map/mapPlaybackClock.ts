export type PlaybackEventName = 'animationframe' | 'frameupdate' | 'seeked' | 'play' | 'pause' | 'ended' | 'ratechange'
export type PlaybackListener = (event: { detail: { frame: number; playbackRate: number } }) => void
type Scheduler = { now: () => number; request: (callback: FrameRequestCallback) => number; cancel: (id: number) => void }

/** Wall-clock playback. A slow paint skips frames instead of slowing down time. */
export class MapPlaybackClock {
  private frame = 0
  private anchor = 0
  private rate = 1
  private duration = 1
  private playing = false
  private request = 0
  private published = 0
  private listeners = new Map<PlaybackEventName, Set<PlaybackListener>>()
  constructor(readonly fps: number, private scheduler: Scheduler = {
    now: () => performance.now(), request: callback => requestAnimationFrame(callback), cancel: id => cancelAnimationFrame(id),
  }) {}

  configure({ durationInFrames, rate }: { durationInFrames: number; rate: number }) {
    this.duration = Math.max(1, durationInFrames)
    if (rate !== this.rate) {
      this.frame = this.exactFrame(); this.anchor = this.scheduler.now()
      this.rate = Math.max(.1, rate)
      this.emit('ratechange')
    }
  }
  private exactFrame() {
    return Math.min(this.duration - 1, this.frame + (this.playing ? Math.max(0, this.scheduler.now() - this.anchor) * this.fps * this.rate / 1000 : 0))
  }
  getCurrentFrame = () => Math.floor(this.exactFrame() + 1e-7)
  getTimeSeconds = () => this.exactFrame() / this.fps
  isPlaying = () => this.playing
  seekTo(frame: number) {
    this.frame = Math.max(0, Math.min(this.duration - 1, Math.round(frame)))
    this.anchor = this.scheduler.now()
    this.emit('seeked'); this.publish()
  }
  play() {
    if (this.playing) return
    this.anchor = this.scheduler.now(); this.playing = true
    this.emit('play'); this.schedule()
  }
  pause() {
    if (!this.playing) return
    this.frame = this.exactFrame(); this.playing = false
    this.scheduler.cancel(this.request); this.request = 0
    this.publish(); this.emit('pause')
  }
  private schedule() {
    if (!this.request && this.playing) this.request = this.scheduler.request(() => {
      this.request = 0
      this.publish()
      // Painting has its own cadence. Quantized timeline events must not gate
      // it a second time, or slow replay and offset frame boundaries stutter.
      this.emit('animationframe')
      if (this.getCurrentFrame() >= this.duration - 1) {
        this.frame = this.duration - 1; this.playing = false; this.emit('ended')
      }
      this.schedule()
    })
  }
  private publish() {
    const frame = this.getCurrentFrame()
    if (frame !== this.published) { this.published = frame; this.emit('frameupdate') }
  }
  private emit(type: PlaybackEventName) {
    const event = { detail: { frame: this.getCurrentFrame(), playbackRate: this.rate } }
    this.listeners.get(type)?.forEach(listener => listener(event))
  }
  addEventListener(type: PlaybackEventName, listener: PlaybackListener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set())
    this.listeners.get(type)!.add(listener)
  }
  removeEventListener(type: PlaybackEventName, listener: PlaybackListener) { this.listeners.get(type)?.delete(listener) }
  dispose() {
    this.frame = this.exactFrame(); this.playing = false
    this.scheduler.cancel(this.request); this.request = 0; this.listeners.clear()
  }
}

export type TrafficAnimation = { clock: MapPlaybackClock; epochMs: number; anchorMs: number }
export function trafficAnimationTime(animation: TrafficAnimation | null | undefined, time: number, phase: number, bucketMs: number) {
  if (!animation) return { time, phase }
  const seconds = animation.clock.getTimeSeconds()
  return { time: seconds, phase: (animation.epochMs + seconds * 1000 - animation.anchorMs) / bucketMs }
}
