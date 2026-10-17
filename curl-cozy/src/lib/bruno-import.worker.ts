import { parseBrunoFiles, parseBrunoEnvironment, type BrunoFile } from "./bruno-import";
self.onmessage = (
  event: MessageEvent<{ kind: "collection" | "environment"; files: BrunoFile[] }>,
) => {
  try {
    self.postMessage({
      result:
        event.data.kind === "environment"
          ? parseBrunoEnvironment(event.data.files[0]!)
          : parseBrunoFiles(event.data.files),
    });
  } catch (error) {
    self.postMessage({
      error: error instanceof Error ? error.message : "Could not parse Bruno files.",
    });
  }
};
