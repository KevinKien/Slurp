import { parseBurpExport } from "./burp-import";

self.onmessage = (event: MessageEvent<{ source: string; fileName: string }>) => {
  try {
    self.postMessage({ result: parseBurpExport(event.data.source, event.data.fileName) });
  } catch (error) {
    self.postMessage({
      error: error instanceof Error ? error.message : "Could not parse the Burp export.",
    });
  }
};
