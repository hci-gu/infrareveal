async (page) => {
  // Run with Playwright CLI on an open /map/:sessionID for an active session.
  // Reload so HMR or earlier shader probes cannot leave duplicate module versions.
  await page.reload();
  const speed = page.getByRole('combobox', { name: 'Playback speed' });
  const state = () => page.locator('main').getAttribute('data-playback-state');
  const live = () => page.getByRole('button', { name: /^(Go live|Live)$/ }).click();
  const assert = (condition, message) => { if (!condition) throw new Error(message); };
  await page.getByRole('button', { name: /^(Go live|Live)$/ }).waitFor();
  for (const rate of ['0.5', '4']) {
    await live();
    await speed.selectOption(rate);
    assert(await state() === 'playing', `${rate}x must leave live following`);
    await live();
    assert(await speed.inputValue() === '1', 'Go live must restore real-time speed');
    assert(await state() === 'following', 'Go live must resume following');
  }
  const measure = () => page.evaluate(async () => {
    const url = performance.getEntriesByType('resource').filter(entry => entry.name.includes('/src/map/FlowArcLayer.ts')).at(-1)?.name;
    if (!url) throw new Error('Run against the Vite dev server');
    const { FlowArcLayer } = await import(url);
    const draw = FlowArcLayer.prototype.draw;
    const samples = [];
    FlowArcLayer.prototype.draw = function (...args) {
      if (this.props.id === 'traffic-streams') samples.push({ wall: performance.now(), clock: this.props.time });
      return draw.apply(this, args);
    };
    try {
      await new Promise(resolve => setTimeout(resolve, 6000));
    } finally { FlowArcLayer.prototype.draw = draw; }
    if (samples.length < 2) throw new Error('No rendered animation frames were observed');
    const elapsed = (samples.at(-1).wall - samples[0].wall) / 1000;
    const advanced = samples.at(-1).clock - samples[0].clock;
    const jumps = samples.slice(1).filter((sample, i) => sample.clock < samples[i].clock || sample.clock - samples[i].clock > 0.3).length;
    return { elapsed, advanced, jumps, renders: samples.length };
  });
  const following = await measure();
  assert(following.jumps === 0, 'Live clock jumped during normal updates');
  assert(Math.abs(following.advanced - following.elapsed) < 0.25, 'Live clock drifted');
  await page.getByRole('button', { name: 'Back 10 seconds', exact: true }).click();
  assert(await state() === 'playing', 'Seeking back must leave live following');
  const playback = await measure();
  assert(playback.jumps === 0, 'Playback clock jumped during data updates');
  assert(Math.abs(playback.advanced - playback.elapsed) < 0.25, 'Playback clock drifted');
  await page.getByRole('button', { name: 'Pause playback' }).click();
  const paused = await page.evaluate(async () => {
    await new Promise(resolve => setTimeout(resolve, 200));
    const slider = document.querySelector('input[aria-label="Session timeline"]');
    const before = slider.value;
    await new Promise(resolve => setTimeout(resolve, 500));
    return { before, after: slider.value };
  });
  assert(paused.before === paused.after, 'Paused animation moved');
  await live();
  const shader = await page.evaluate(async () => (await import('/scripts/check-traffic-animation.js')).checkTrafficAnimation());
  assert(shader.passed, shader.failures.join('\n'));
  return { following, playback, paused, shader };
}
