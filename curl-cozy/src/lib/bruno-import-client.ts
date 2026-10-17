import type { BrunoFile } from "./bruno-import";
import type { PostmanImport, parsePostmanEnvironment } from "./postman-import";
export function readBrunoFiles(kind: "collection", files: BrunoFile[]): Promise<PostmanImport>;
export function readBrunoFiles(
  kind: "environment",
  files: BrunoFile[],
): Promise<ReturnType<typeof parsePostmanEnvironment>>;
export function readBrunoFiles(
  kind: "collection" | "environment",
  files: BrunoFile[],
): Promise<PostmanImport | ReturnType<typeof parsePostmanEnvironment>> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./bruno-import.worker.ts", import.meta.url), {
      type: "module",
    });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(Error("Bruno parsing timed out. Import fewer or smaller files."));
    }, 20000);
    const dispose = () => {
      clearTimeout(timer);
      worker.terminate();
    };
    worker.onmessage = (event) => {
      dispose();
      if (event.data.error) reject(Error(event.data.error));
      else resolve(event.data.result);
    };
    worker.onerror = () => {
      dispose();
      reject(Error("Could not load the Bruno parser."));
    };
    worker.postMessage({ kind, files });
  });
}
