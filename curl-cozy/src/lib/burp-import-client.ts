import { parseBurpExport } from "./burp-import";
import type { PostmanImport } from "./postman-import";

/**
 * Parse a Burp export off the main thread. Environment without Worker support (and worker
 * startup failures) fall back to the same synchronous parser so importing always works.
 */
export function readBurpExport(fileName: string, source: string): Promise<PostmanImport> {
  return new Promise((resolve, reject) => {
    const fallback = () => {
      try {
        resolve(parseBurpExport(source, fileName));
      } catch (error) {
        reject(error instanceof Error ? error : Error("Could not parse the Burp export."));
      }
    };
    let worker: Worker;
    try {
      worker = new Worker(new URL("./burp-import.worker.ts", import.meta.url), {
        type: "module",
      });
    } catch {
      fallback();
      return;
    }
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (action: () => void) => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      worker.terminate();
      action();
    };
    timer = setTimeout(
      () => finish(() => reject(Error("Burp parsing timed out. Import a smaller export."))),
      20000,
    );
    worker.onmessage = (event: MessageEvent<{ result?: PostmanImport; error?: string }>) => {
      const error = event.data?.error;
      const result = event.data?.result;
      if (error) finish(() => reject(Error(error)));
      else if (result) finish(() => resolve(result));
      else finish(fallback);
    };
    // A worker that cannot load is not a parse failure: parse here instead.
    worker.onerror = () => finish(fallback);
    worker.postMessage({ source, fileName });
  });
}
