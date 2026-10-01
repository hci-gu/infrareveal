// Open a /map/<session> page using Equal Earth, then run with Playwright CLI.
// Reproduce React processing queued pointer moves after release/cancellation.
async (page) => {
  const errors = [];
  const onError = error => errors.push(error.message);
  page.on('pageerror', onError);
  const map = page.locator('svg[aria-label="Equal Earth traffic map"]');
  try {
    await map.waitFor();
    for (const end of ['pointerup', 'pointercancel']) {
      await page.getByRole('button', { name: 'Fit world', exact: true }).click();
      const box = await map.boundingBox();
      const x = box.x + box.width * .45, y = box.y + box.height * .7;
      const before = await map.locator(':scope > g').getAttribute('transform');
      await page.mouse.move(x, y);
      await page.mouse.down();
      // One browser task keeps both updates queued until after drag cleanup.
      await map.evaluate((svg, { x, y, end }) => {
        for (const offset of [25, 60]) svg.dispatchEvent(new PointerEvent('pointermove', { bubbles: true, pointerId: 1, pointerType: 'mouse', buttons: 1, clientX: x + offset, clientY: y + 20 }));
        svg.dispatchEvent(new PointerEvent(end, { bubbles: true, pointerId: 1, pointerType: 'mouse', buttons: 0, clientX: x + 60, clientY: y + 20 }));
      }, { x, y, end });
      await page.mouse.up();
      await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
      if (errors.length) throw new Error(errors.join('\n'));
      if (!await map.count()) throw new Error(`${end} crashed the map`);
      const after = await map.locator(':scope > g').getAttribute('transform');
      if (after === before || /NaN/.test(after)) throw new Error(`${end} lost the final drag position`);
      await map.dispatchEvent('pointermove', { pointerId: 1, clientX: x + 200, clientY: y + 100 });
      if (await map.locator(':scope > g').getAttribute('transform') !== after) throw new Error(`${end} left dragging active`);
    }
    return { release: 'passed', cancellation: 'passed', errors };
  } finally {
    page.off('pageerror', onError);
  }
}
