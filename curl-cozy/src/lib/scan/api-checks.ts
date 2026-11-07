import type { Exchange, ScanCheck, ScanCheckContext } from "./types";
import { ok, text, result, observation } from "./extended-checks";

function jsonBody(x: Exchange): unknown {
  if (!ok(x)) return undefined;
  try {
    return JSON.parse(text(x));
  } catch {
    return undefined;
  }
}

function sameOriginPath(requestUrl: string, path: string) {
  const url = new URL(requestUrl);
  url.pathname = path;
  url.search = "";
  return url.href;
}

function headersWithoutFraming(headers: Record<string, string>) {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !["content-length", "transfer-encoding"].includes(name.toLowerCase()),
    ),
  );
}

export const graphqlEndpoint: ScanCheck = {
  id: "graphql-endpoint",
  name: "GraphQL endpoint discovery",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable) return result("Stable baselines required.", true);
    for (const path of [
      "/graphql",
      "/api/graphql",
      "/v1/graphql",
      "/graphiql",
      "/altair",
      "/gql",
    ]) {
      const request = {
        method: "POST",
        url: sameOriginPath(ctx.request.url, path),
        headers: {
          ...headersWithoutFraming(ctx.request.headers),
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify({ query: "query SlurpProbe { __typename }" }),
      };
      const probe = await ctx.probe(request, `GraphQL endpoint discovery ${path}`);
      if (!ok(probe) || probe.response!.status < 200 || probe.response!.status >= 300) continue;
      const payload = jsonBody(probe) as { data?: { __typename?: unknown } } | undefined;
      if (typeof payload?.data?.__typename === "string" && payload.data.__typename) {
        return observation(
          "GraphQL endpoint discovered",
          `A read-only \`__typename\` query returned GraphQL data from ${path}. Endpoint discovery is informational; authorization, batching and field-level access require separate review. Only the captured origin was probed.`,
          [ctx.baselines[0]!, probe],
          [`Endpoint: ${path}`, `Type: ${payload.data.__typename}`],
          "info",
        );
      }
    }
    return result("No GraphQL endpoint answered a __typename probe on the captured origin.");
  },
};

function looksLikeSpec(body: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(body);
    if (parsed && typeof parsed === "object") {
      const record = parsed as Record<string, unknown>;
      const openapi = record["openapi"];
      const swagger = record["swagger"];
      if ((typeof openapi === "string" || typeof swagger === "string") && record["paths"])
        return typeof openapi === "string" ? `OpenAPI ${openapi}` : `Swagger ${swagger}`;
    }
  } catch {
    /* YAML below */
  }
  if (/^\s*openapi\s*:\s*\d/im.test(body) || /^\s*swagger\s*:\s*["']?\d/im.test(body))
    return "OpenAPI/Swagger YAML";
  return undefined;
}

export const openapiExposure: ScanCheck = {
  id: "openapi-exposure",
  name: "OpenAPI / Swagger specification exposure",
  active: true,
  perParameter: false,
  async run(ctx) {
    if (!ctx.stable) return result("Stable baselines required.", true);
    for (const path of [
      "/openapi.json",
      "/swagger.json",
      "/api-docs",
      "/v3/api-docs",
      "/swagger/v1/swagger.json",
      "/openapi.yaml",
    ]) {
      const request = {
        method: "GET",
        url: sameOriginPath(ctx.request.url, path),
        headers: { accept: "application/json, text/yaml" },
        body: "",
      };
      const probe = await ctx.probe(request, `API specification probe ${path}`);
      if (!ok(probe) || probe.response!.status < 200 || probe.response!.status >= 300) continue;
      const kind = looksLikeSpec(text(probe));
      if (kind) {
        return observation(
          "API specification exposed",
          `A public specification (${kind}) was returned from ${path}. This discloses endpoints, parameters and schemas; confirm whether the document is intentionally public and whether it includes internal or deprecated operations.`,
          [ctx.baselines[0]!, probe],
          [`Path: ${path}`, `Format: ${kind}`],
          "medium",
        );
      }
    }
    return result("No OpenAPI/Swagger specification was returned from the probed paths.");
  },
};

const tokenNames = /^(?:access_token|id_token|refresh_token|token|jwt)$/i;

export const jwtQuery: ScanCheck = {
  id: "jwt-query",
  name: "Access token in URL query",
  active: false,
  perParameter: false,
  async run(ctx) {
    const url = new URL(ctx.request.url);
    for (const [name, value] of url.searchParams) {
      if (tokenNames.test(name) && value.length >= 10) {
        return observation(
          "Access token placed in the URL query",
          "The captured request carries a token-like value in the query string. URLs are commonly written to access logs, proxies and Referer headers, so query tokens leak more easily than Authorization headers.",
          [ctx.baselines[0]!],
          [`Query parameter: ${name}`, `Value length: ${value.length}`],
          "low",
        );
      }
    }
    return result("No token-like query parameter observed.");
  },
};

export const apiChecks = [graphqlEndpoint, openapiExposure, jwtQuery];
