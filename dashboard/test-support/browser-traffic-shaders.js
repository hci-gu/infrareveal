// Run on the Vite dashboard. Tests the production GPU functions with captured bursts.
async (page) => {
  const result = await page.evaluate(async () => {
    const { CountryFlowArcLayer } = await import('/src/map/CountryLayers.ts');
    return (await import('/scripts/check-traffic-animation.js')).checkTrafficAnimation([CountryFlowArcLayer]);
  });
  if (!result.passed) throw new Error(JSON.stringify(result));
  return result;
}
