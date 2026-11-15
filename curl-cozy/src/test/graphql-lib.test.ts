import { expect, it } from "vitest";
import { buildOperation, sampleValue } from "@/lib/graphql/builder";
import { formatQuery } from "@/lib/graphql/format";
import { INTROSPECTION_QUERY } from "@/lib/graphql/introspection";
import {
  buildGraphqlRequest,
  formatHeaderLines,
  fromCapturedRequest,
  operationNames,
  parseHeaderLines,
  takeGraphqlSeed,
  setGraphqlSeed,
} from "@/lib/graphql/request";
import {
  namedType,
  operationsOf,
  parseIntrospection,
  printSchema,
  schemaStats,
  searchSchema,
  typeToString,
} from "@/lib/graphql/schema";

import { introspection } from "./fixtures/graphql-introspection";

const schema = parseIntrospection(introspection);

it("parses the response shapes servers return and explains a failed introspection", () => {
  expect(parseIntrospection(introspection.data).queryType).toBe("Query");
  expect(parseIntrospection(introspection.data.__schema).mutationType).toBe("Mutation");
  expect(() =>
    parseIntrospection({ errors: [{ message: "GraphQL introspection is not allowed" }] }),
  ).toThrow(/not allowed/);
  expect(() => parseIntrospection({ data: null })).toThrow(/no GraphQL schema/);
  expect(operationsOf(schema)).toEqual(["query", "mutation"]);
  expect(schemaStats(schema)).toMatchObject({
    queries: 4,
    mutations: 1,
    subscriptions: 0,
    enums: 1,
    inputs: 2,
  });
  expect(INTROSPECTION_QUERY).toContain("fragment TypeRef");
});

it("formats and unwraps type references", () => {
  const users = schema.types.get("Query")!.fields.find((f) => f.name === "users")!;
  expect(typeToString(users.type)).toBe("[User!]!");
  expect(namedType(users.type)).toBe("User");
  expect(schema.types.get("Query")!.fields.find((f) => f.name === "legacy")!.deprecated).toBe(true);
});

it("searches types, fields, arguments and enum values", () => {
  expect(searchSchema(schema, "role").map((h) => `${h.type}.${h.field ?? ""}:${h.kind}`)).toEqual(
    expect.arrayContaining(["Role.:type", "User.role:field", "UserFilter.role:field"]),
  );
  expect(searchSchema(schema, "admin")).toEqual([
    { type: "Role", field: "ADMIN", kind: "value", detail: "enum value" },
  ]);
  expect(searchSchema(schema, "token")[0]).toMatchObject({
    type: "User",
    field: "secret",
    kind: "argument",
  });
  expect(searchSchema(schema, "  ")).toEqual([]);
  expect(searchSchema(schema, "__")).toEqual([]);
});

it("prints the schema as SDL", () => {
  const sdl = printSchema(schema);
  expect(sdl).toContain("type User {\n  id: ID!");
  expect(sdl).toContain("users(first: Int, filter: UserFilter): [User!]!");
  expect(sdl).toContain("union SearchResult = User | Post");
  expect(sdl).toContain("enum Role {\n  ADMIN\n  MEMBER\n}");
  expect(sdl).toContain('legacy: String @deprecated(reason: "use users")');
  expect(sdl).not.toContain("scalar String");
  expect(sdl).not.toContain("__Schema");
});

it("builds an operation with required arguments as variables and no cycles", () => {
  expect(buildOperation(schema, "query", "user")).toEqual({
    operationName: "User",
    variables: { id: "" },
    query:
      "query User($id: ID!) {\n  user(id: $id) {\n    id\n    name\n    role\n    posts {\n      id\n      title\n    }\n  }\n}",
  });
  // Optional arguments are left out; fields that need arguments are not selected.
  const users = buildOperation(schema, "query", "users");
  expect(users.query).toBe(
    "query Users {\n  users {\n    id\n    name\n    role\n    posts {\n      id\n      title\n    }\n  }\n}",
  );
  expect(users.variables).toEqual({});
  expect(users.query).not.toContain("secret");
  expect(buildOperation(schema, "query", "user", { depth: 1 }).query).toBe(
    "query User($id: ID!) {\n  user(id: $id) {\n    id\n    name\n    role\n  }\n}",
  );
});

it("selects union members and builds mutations with sample input", () => {
  const search = buildOperation(schema, "query", "search");
  expect(search.query).toContain("search(text: $text) {\n    __typename\n    ... on User {");
  expect(search.query).toContain("... on Post {");
  expect(search.variables).toEqual({ text: "" });
  const mutation = buildOperation(schema, "mutation", "createUser");
  expect(
    mutation.query.startsWith(
      "mutation CreateUser($input: CreateUserInput!) {\n  createUser(input: $input) {",
    ),
  ).toBe(true);
  expect(mutation.variables).toEqual({ input: { name: "", role: "ADMIN", tags: [""] } });
  expect(() => buildOperation(schema, "query", "missing")).toThrow(/no query field/);
  expect(() => buildOperation(schema, "subscription", "x")).toThrow();
  expect(sampleValue(schema, { kind: "SCALAR", name: "Boolean", ofType: null })).toBe(false);
});

it("formats one-line documents and is stable when run twice", () => {
  const input =
    "query A($id:ID!,$n:Int=5){user(id:$id){id name ...F posts(limit:$n){id title}}}fragment F on User{role}";
  const expected = `query A($id: ID!, $n: Int = 5) {
  user(id: $id) {
    id
    name
    ...F
    posts(limit: $n) {
      id
      title
    }
  }
}

fragment F on User {
  role
}
`;
  expect(formatQuery(input)).toBe(expected);
  expect(formatQuery(expected)).toBe(expected);
  const complex = formatQuery(
    '{ a: user(id: "x{y}", filter: {role: ADMIN, tags: ["a","b"]}) @include(if: true) { id ... on Admin { level } } } # done',
  );
  expect(complex).toContain(
    'a: user(id: "x{y}", filter: { role: ADMIN, tags: ["a", "b"] }) @include(if: true) {',
  );
  expect(complex).toContain("    ... on Admin {\n      level\n    }");
  expect(complex.trimEnd().endsWith("# done")).toBe(true);
  expect(formatQuery(complex)).toBe(complex);
});

it("builds the HTTP request and reads operation names", () => {
  expect(operationNames("query A { a } mutation B { b } # query C {}")).toEqual(["A", "B"]);
  const request = buildGraphqlRequest({
    endpoint: "https://api.example.com/graphql",
    headers: { Authorization: "Bearer t", Host: "x", "content-type": "text/plain" },
    query: "query Me { me { id } }",
    variables: '{"a":1}',
    operationName: "",
  });
  expect(request.method).toBe("POST");
  expect(request.headers).toEqual({
    Authorization: "Bearer t",
    "Content-Type": "application/json",
    Accept: "application/json",
  });
  expect(JSON.parse(request.body)).toEqual({
    query: "query Me { me { id } }",
    variables: { a: 1 },
    operationName: "Me",
  });
  const several = buildGraphqlRequest({
    endpoint: "https://x/graphql",
    headers: {},
    query: "query A { a } query B { b }",
    variables: "",
    operationName: "",
  });
  expect(JSON.parse(several.body)).toEqual({ query: "query A { a } query B { b }" });
  expect(() =>
    buildGraphqlRequest({
      endpoint: "https://x/graphql",
      headers: {},
      query: "{ a }",
      variables: "[1]",
      operationName: "",
    }),
  ).toThrow(/object/);
  expect(() =>
    buildGraphqlRequest({
      endpoint: "https://x/graphql",
      headers: {},
      query: "{ a }",
      variables: "{oops",
      operationName: "",
    }),
  ).toThrow();
  expect(() =>
    buildGraphqlRequest({
      endpoint: "ftp://x",
      headers: {},
      query: "{ a }",
      variables: "",
      operationName: "",
    }),
  ).toThrow(/HTTP/);
  expect(() =>
    buildGraphqlRequest({
      endpoint: "https://x",
      headers: {},
      query: "  ",
      variables: "",
      operationName: "",
    }),
  ).toThrow(/query/);
});

it("parses and prints header lines", () => {
  const { headers, invalid } = parseHeaderLines(
    "Authorization: Bearer a:b\n# comment\n\nX-Test:1\nnot a header\n: empty",
  );
  expect(headers).toEqual({ Authorization: "Bearer a:b", "X-Test": "1" });
  expect(invalid).toEqual(["not a header", ": empty"]);
  expect(formatHeaderLines(headers)).toBe("Authorization: Bearer a:b\nX-Test: 1");
});

it("prefills the editor from captured requests", () => {
  const post = fromCapturedRequest({
    method: "POST",
    url: "https://api.example.com/graphql?x=1",
    headers: { "Content-Type": "application/json", Cookie: "a=b", "Content-Length": "9" },
    body: JSON.stringify([
      { query: "{ me { id } }", variables: { a: 1 }, operationName: "Me" },
      { query: "{ other }" },
    ]),
  });
  expect(post.isGraphql).toBe(true);
  expect(post.draft).toMatchObject({
    endpoint: "https://api.example.com/graphql?x=1",
    headers: { Cookie: "a=b" },
    query: "{ me { id } }",
    operationName: "Me",
  });
  expect(JSON.parse(post.draft.variables!)).toEqual({ a: 1 });
  const get = fromCapturedRequest({
    method: "GET",
    url: "https://api.example.com/gql?query=%7Bme%7D&variables=%7B%22a%22%3A1%7D&operationName=Me",
    headers: {},
    body: "",
  });
  expect(get.draft.endpoint).toBe("https://api.example.com/gql");
  expect(get.draft.query).toBe("{me}");
  expect(get.isGraphql).toBe(true);
  const raw = fromCapturedRequest({
    method: "POST",
    url: "https://api.example.com/q",
    headers: { "content-type": "application/graphql" },
    body: "{ me }",
  });
  expect(raw.draft.query).toBe("{ me }");
  const other = fromCapturedRequest({
    method: "POST",
    url: "https://api.example.com/api/items",
    headers: { "content-type": "application/json" },
    body: '{"a":1}',
  });
  expect(other.isGraphql).toBe(false);
  expect(other.draft.query).toBeUndefined();
});

it("hands a captured request to the GraphQL page exactly once", () => {
  setGraphqlSeed({ method: "POST", url: "https://x/graphql", headers: {}, body: "" });
  expect(takeGraphqlSeed()?.url).toBe("https://x/graphql");
  expect(takeGraphqlSeed()).toBeUndefined();
});
