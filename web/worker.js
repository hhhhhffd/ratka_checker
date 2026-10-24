// Runs the wasm scanner off the main thread so large jars do not freeze the page.
import init, { scan } from './pkg/ratscan_wasm.js';

const ready = init();

self.onmessage = async ({ data }) => {
  try {
    await ready;
    const started = performance.now();
    const result = JSON.parse(scan(new Uint8Array(data)));
    self.postMessage({ ok: true, result, elapsedMs: performance.now() - started });
  } catch (error) {
    self.postMessage({ ok: false, error: String(error?.message ?? error) });
  }
};
