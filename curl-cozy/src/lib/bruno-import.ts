import parseRequest from "@usebruno/lang/v2/src/bruToJson.js";
import parseEnvironment from "@usebruno/lang/v2/src/envToJson.js";
import {
  MAX_POSTMAN_BYTES,
  parsePostmanCollection,
  parsePostmanEnvironment,
  type PostmanImport,
  type PostmanRequest,
} from "./postman-import";

export interface BrunoFile {
  name: string;
  source: string;
}
export const MAX_BRUNO_FILE_BYTES = 2_000_000;
const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
const text = (value: unknown) => (typeof value === "string" ? value : "");
const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
function checkSize(file: BrunoFile) {
  if (!file.name.toLowerCase().endsWith(".bru")) throw Error("Select a Bruno .bru file.");
  if (new TextEncoder().encode(file.source).length > MAX_BRUNO_FILE_BYTES)
    throw Error("Bruno files must be 2 MB or smaller.");
}
export function parseBrunoEnvironment(file: BrunoFile): ReturnType<typeof parsePostmanEnvironment> {
  checkSize(file);
  const data = record(parseEnvironment(file.source.replace(/^\uFEFF/, "")));
  if (!Array.isArray(data["variables"]))
    throw Error("Expected a Bruno environment with a vars block.");
  const warnings: string[] = [];
  if (data["extends"])
    warnings.push("Inherited Bruno environments are not loaded. Import their values manually.");
  if (data["externalSecrets"])
    warnings.push(
      "External secret providers are not imported. Add the required values in Variables.",
    );
  const values = list(data["variables"])
    .map(record)
    .filter((v) => {
      if (v["secret"] === true) {
        warnings.push(
          `Secret value is not stored in this file: ${text(v["name"])}. Add it manually.`,
        );
        return false;
      }
      return true;
    })
    .map((v) => ({ key: v["name"], value: v["value"], enabled: v["enabled"] }));
  const result = parsePostmanEnvironment(JSON.stringify({ values }));
  return { variables: result.variables, warnings: [...warnings, ...result.warnings] };
}
export function parseBrunoFiles(files: BrunoFile[]): PostmanImport {
  if (!files.length) throw Error("Select at least one Bruno request file.");
  if (files.length > 500) throw Error("Select at most 500 Bruno request files.");
  if (
    files.reduce((sum, file) => sum + new TextEncoder().encode(file.source).length, 0) >
    MAX_POSTMAN_BYTES
  )
    throw Error("Selected Bruno files exceed the 10 MB total limit.");
  const requests: PostmanRequest[] = files.map((file, id) => {
    const fallback = file.name.replace(/\.bru$/i, "").slice(0, 200);
    try {
      checkSize(file);
      const data = record(parseRequest(file.source.replace(/^\uFEFF/, ""))),
        meta = record(data["meta"]),
        http = record(data["http"]);
      const name = (text(meta["name"]) || fallback).slice(0, 200),
        warnings: string[] = [];
      if (!http["method"] || (meta["type"] && meta["type"] !== "http"))
        throw Error(
          "Only HTTP request .bru files are supported. Collection, folder, environment, WebSocket and gRPC files cannot be imported as request tabs.",
        );
      const pairs = (value: unknown) =>
        list(value)
          .map(record)
          .map((row) => ({
            key: row["name"],
            value: row["value"],
            disabled: row["enabled"] === false,
          }));
      const authType = text(http["auth"]),
        authData = record(data["auth"]);
      let auth: Record<string, unknown> = { type: "noauth" };
      if (authType && authType !== "none" && authType !== "noauth") {
        if (authType === "inherit")
          throw Error(
            "Inherited collection/folder authentication is not available in standalone .bru files. Set explicit authentication in Bruno before exporting.",
          );
        if (!["basic", "bearer"].includes(authType))
          throw Error(`Unsupported Bruno authentication: ${authType}`);
        auth = {
          type: authType,
          [authType]: Object.entries(record(authData[authType])).map(([key, value]) => ({
            key,
            value,
          })),
        };
      }
      const bodyMode = text(http["body"]),
        bodyData = record(data["body"]);
      let body: unknown;
      if (bodyMode && bodyMode !== "none") {
        if (!["json", "text", "xml", "sparql"].includes(bodyMode))
          throw Error(
            `Unsupported Bruno body mode: ${bodyMode}. Raw JSON, text, XML and SPARQL are supported.`,
          );
        body = {
          mode: "raw",
          raw: text(bodyData[bodyMode]),
          options: { raw: { language: bodyMode === "sparql" ? "text" : bodyMode } },
        };
      } else if (Object.keys(bodyData).length)
        throw Error(
          "A body block exists without an active body mode. Select an explicit body mode in Bruno before importing.",
        );
      const params = list(data["params"]).map(record),
        query = params.filter((p) => p["type"] === "query");
      const url: Record<string, unknown> = {
        raw: text(http["url"]),
        variable: params
          .filter((p) => p["type"] === "path")
          .map((p) => ({ key: p["name"], value: p["value"], disabled: p["enabled"] === false })),
      };
      if (query.length)
        url["query"] = query.map((p) => ({
          key: p["name"],
          value: p["value"],
          disabled: p["enabled"] === false,
        }));
      const headers = pairs(data["headers"]);
      if (
        bodyMode === "sparql" &&
        !headers.some((h) => text(h.key).toLowerCase() === "content-type" && !h.disabled)
      )
        headers.push({ key: "Content-Type", value: "application/sparql-query", disabled: false });
      const result = parsePostmanCollection(
        JSON.stringify({
          info: {
            name: "Bruno",
            schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
          },
          item: [
            {
              name,
              request: {
                method: text(http["method"]).toUpperCase(),
                url,
                header: headers,
                auth,
                ...(body ? { body } : {}),
              },
            },
          ],
        }),
      ).requests[0]!;
      const vars = record(data["vars"]);
      if (list(vars["req"]).some((v) => record(v)["enabled"] !== false))
        warnings.push(
          "Request-scoped variables are not imported into shared variables. Add their values manually before sending.",
        );
      if (list(vars["res"]).some((v) => record(v)["enabled"] !== false))
        warnings.push(
          "Bruno response variable extractors are not converted. Add an After response script in Replay.",
        );
      if (list(data["assertions"]).some((v) => record(v)["enabled"] !== false))
        warnings.push("Bruno assertions are not imported.");
      if (data["settings"])
        warnings.push("Bruno request settings are not imported; Replay send settings apply.");
      const scriptParts = [
        ...Object.entries(record(data["script"]))
          .filter(([, value]) => typeof value === "string" && value.trim())
          .map(([key, value]) => `${key}:\n${text(value).slice(0, 16000)}`),
        ...(text(data["tests"]).trim() ? [`tests:\n${text(data["tests"]).slice(0, 16000)}`] : []),
      ];
      if (scriptParts.length)
        warnings.push(
          "Bruno scripts and tests are shown for reference only; they are not converted or executed.",
        );
      return {
        ...result,
        id,
        warnings: [...result.warnings, ...warnings],
        scripts: scriptParts.length ? [scriptParts.join("\n\n").slice(0, 32000)] : [],
      };
    } catch (error) {
      return {
        id,
        name: fallback,
        request: null,
        warnings: [
          `${file.name}: ${error instanceof Error ? error.message.slice(0, 1000) : "Invalid Bruno file."}`,
        ],
        scripts: [],
      };
    }
  });
  return {
    name: files.length === 1 ? requests[0]!.name : `Bruno · ${files.length} files`,
    requests,
    variables: {},
    warnings: [
      "Only standalone request settings are imported. Collection/folder defaults are not loaded. Request-scoped variables, scripts and response extractors require manual migration.",
    ],
  };
}
