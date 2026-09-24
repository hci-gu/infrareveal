// Open a production-built /map/<session> page with the gateway fixture first.
// Run with: playwright-cli run-code --filename dashboard/test-support/browser-map-worker.js
async (page) => {
  // Equal Earth uses bundled SVG geography; exercise the optional Mercator worker.
  await page.evaluate(() => {
    const key = 'infrareveal.map.display.v1';
    localStorage.setItem(key, JSON.stringify({ projection: 'mercator', theme: 'dark', labels: true }));
  });
  const workerStarted = page.waitForEvent('worker', { timeout: 15000 });
  await page.reload();
  const mapWorker = await workerStarted;
  const workerUrl = mapWorker.url();
  if (!workerUrl.includes('/assets/')) {
    throw new Error('This check requires a production build, not the Vite dev server');
  }

  // Import the actual emitted worker in a fresh module worker. A ready message
  // proves its entire dependency graph loaded and MapLibre initialized. Merely
  // waiting for a canvas or a Worker event misses failed module imports.
  const result = await page.evaluate(async (url) => {
    const source = `import ${JSON.stringify(url)}; self.postMessage({ ready: Boolean(self.worker) });`;
    const blobUrl = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }));
    const worker = new Worker(blobUrl, { type: 'module' });
    try {
      return await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Map worker did not initialize')), 10000);
        worker.onmessage = ({ data }) => {
          clearTimeout(timeout);
          resolve(data);
        };
        worker.onerror = (error) => {
          clearTimeout(timeout);
          reject(new Error(error.message || 'Map worker or a dependency failed to load'));
        };
      });
    } finally {
      worker.terminate();
      URL.revokeObjectURL(blobUrl);
    }
  }, workerUrl);
  if (!result.ready) throw new Error('MapLibre worker did not register its message handler');
  return { workerUrl, ready: result.ready };
}
