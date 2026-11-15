/** GraphQL schema model built from an introspection result. No external GraphQL library is needed. */

export type Kind =
  "SCALAR" | "OBJECT" | "INTERFACE" | "UNION" | "ENUM" | "INPUT_OBJECT" | "LIST" | "NON_NULL";

export type TypeRef = { kind: Kind; name: string | null; ofType: TypeRef | null };

export type InputValue = {
  name: string;
  description: string;
  type: TypeRef;
  defaultValue: string | null;
};
export type Field = {
  name: string;
  description: string;
  args: InputValue[];
  type: TypeRef;
  deprecated: boolean;
  deprecationReason: string;
};
export type EnumValue = {
  name: string;
  description: string;
  deprecated: boolean;
  deprecationReason: string;
};
export type GqlType = {
  kind: Kind;
  name: string;
  description: string;
  fields: Field[];
  inputFields: InputValue[];
  interfaces: string[];
  enumValues: EnumValue[];
  possibleTypes: string[];
};
export type Directive = {
  name: string;
  description: string;
  locations: string[];
  args: InputValue[];
};
export type Schema = {
  queryType: string | null;
  mutationType: string | null;
  subscriptionType: string | null;
  types: Map<string, GqlType>;
  directives: Directive[];
};
export type Operation = "query" | "mutation" | "subscription";

export const BUILTIN_SCALARS = new Set(["Int", "Float", "String", "Boolean", "ID"]);

const MAX_TYPES = 20_000;

const str = (value: unknown) => (typeof value === "string" ? value : "");
const arr = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);
const obj = (value: unknown): Record<string, unknown> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};

function typeRef(value: unknown, depth = 0): TypeRef {
  const raw = obj(value);
  const kind = str(raw["kind"]) as Kind;
  if (!kind) throw new Error("Introspection type reference has no kind.");
  const inner = raw["ofType"];
  return {
    kind,
    name: typeof raw["name"] === "string" ? raw["name"] : null,
    ofType: inner && depth < 16 ? typeRef(inner, depth + 1) : null,
  };
}

function inputValue(value: unknown): InputValue {
  const raw = obj(value);
  return {
    name: str(raw["name"]),
    description: str(raw["description"]),
    type: typeRef(raw["type"]),
    defaultValue: typeof raw["defaultValue"] === "string" ? raw["defaultValue"] : null,
  };
}

/**
 * Accepts the JSON a server returns for an introspection query: `{ data: { __schema } }`, `{ __schema }`
 * or the `__schema` object itself.
 */
export function parseIntrospection(input: unknown): Schema {
  const root = obj(input);
  const candidate =
    root["__schema"] ?? obj(root["data"])["__schema"] ?? (root["types"] ? root : undefined);
  const raw = obj(candidate);
  const typeList = arr(raw["types"]);
  if (!typeList.length) {
    const errors = arr(root["errors"])
      .map((e) => str(obj(e)["message"]))
      .filter(Boolean);
    throw new Error(
      errors.length
        ? `The server did not return a schema: ${errors.slice(0, 2).join("; ")}`
        : "The response has no GraphQL schema (__schema).",
    );
  }
  if (typeList.length > MAX_TYPES) throw new Error("The schema has too many types to load.");
  const types = new Map<string, GqlType>();
  for (const item of typeList) {
    const t = obj(item);
    const name = str(t["name"]);
    if (!name) continue;
    types.set(name, {
      kind: str(t["kind"]) as Kind,
      name,
      description: str(t["description"]),
      fields: arr(t["fields"]).map((f) => {
        const field = obj(f);
        return {
          name: str(field["name"]),
          description: str(field["description"]),
          args: arr(field["args"]).map(inputValue),
          type: typeRef(field["type"]),
          deprecated: field["isDeprecated"] === true,
          deprecationReason: str(field["deprecationReason"]),
        };
      }),
      inputFields: arr(t["inputFields"]).map(inputValue),
      interfaces: arr(t["interfaces"])
        .map((i) => str(obj(i)["name"]))
        .filter(Boolean),
      enumValues: arr(t["enumValues"]).map((v) => {
        const value = obj(v);
        return {
          name: str(value["name"]),
          description: str(value["description"]),
          deprecated: value["isDeprecated"] === true,
          deprecationReason: str(value["deprecationReason"]),
        };
      }),
      possibleTypes: arr(t["possibleTypes"])
        .map((p) => str(obj(p)["name"]))
        .filter(Boolean),
    });
  }
  const rootName = (key: string) => {
    const name = str(obj(raw[key])["name"]);
    return name && types.has(name) ? name : null;
  };
  return {
    queryType: rootName("queryType"),
    mutationType: rootName("mutationType"),
    subscriptionType: rootName("subscriptionType"),
    types,
    directives: arr(raw["directives"]).map((d) => {
      const directive = obj(d);
      return {
        name: str(directive["name"]),
        description: str(directive["description"]),
        locations: arr(directive["locations"]).map(str),
        args: arr(directive["args"]).map(inputValue),
      };
    }),
  };
}

/** `[User!]!` */
export function typeToString(ref: TypeRef): string {
  if (ref.kind === "NON_NULL") return `${ref.ofType ? typeToString(ref.ofType) : "?"}!`;
  if (ref.kind === "LIST") return `[${ref.ofType ? typeToString(ref.ofType) : "?"}]`;
  return ref.name ?? "?";
}

/** The type name with list and non-null wrappers removed. */
export function namedType(ref: TypeRef): string {
  let current: TypeRef | null = ref;
  while (current && !current.name) current = current.ofType;
  return current?.name ?? "";
}

export const isRequired = (arg: InputValue) =>
  arg.type.kind === "NON_NULL" && arg.defaultValue === null;

export function isLeaf(schema: Schema, ref: TypeRef): boolean {
  const kind = schema.types.get(namedType(ref))?.kind;
  return kind === "SCALAR" || kind === "ENUM" || kind === undefined;
}

export function rootType(schema: Schema, operation: Operation): GqlType | undefined {
  const name =
    operation === "query"
      ? schema.queryType
      : operation === "mutation"
        ? schema.mutationType
        : schema.subscriptionType;
  return name ? schema.types.get(name) : undefined;
}

export const operationsOf = (schema: Schema): Operation[] =>
  (["query", "mutation", "subscription"] as const).filter((op) => rootType(schema, op));

const userTypes = (schema: Schema) =>
  [...schema.types.values()].filter((t) => !t.name.startsWith("__"));

/** Case-insensitive search over type, field, argument and enum-value names and descriptions. */
export type SearchHit = {
  type: string;
  field?: string;
  kind: "type" | "field" | "argument" | "value";
  detail: string;
};
export function searchSchema(schema: Schema, query: string, limit = 80): SearchHit[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const hits: SearchHit[] = [];
  const match = (...texts: string[]) => texts.some((t) => t.toLowerCase().includes(q));
  for (const type of userTypes(schema)) {
    if (match(type.name))
      hits.push({ type: type.name, kind: "type", detail: type.kind.toLowerCase() });
    for (const field of type.fields) {
      if (match(field.name))
        hits.push({
          type: type.name,
          field: field.name,
          kind: "field",
          detail: typeToString(field.type),
        });
      for (const arg of field.args)
        if (arg.name.toLowerCase().includes(q))
          hits.push({
            type: type.name,
            field: field.name,
            kind: "argument",
            detail: `${arg.name}: ${typeToString(arg.type)}`,
          });
    }
    for (const input of type.inputFields)
      if (match(input.name))
        hits.push({
          type: type.name,
          field: input.name,
          kind: "field",
          detail: typeToString(input.type),
        });
    for (const value of type.enumValues)
      if (match(value.name))
        hits.push({ type: type.name, field: value.name, kind: "value", detail: "enum value" });
    if (hits.length >= limit) break;
  }
  return hits.slice(0, limit);
}

export function schemaStats(schema: Schema) {
  const all = userTypes(schema);
  const count = (kind: Kind) => all.filter((t) => t.kind === kind).length;
  return {
    types: all.length,
    objects: count("OBJECT"),
    inputs: count("INPUT_OBJECT"),
    enums: count("ENUM"),
    queries: rootType(schema, "query")?.fields.length ?? 0,
    mutations: rootType(schema, "mutation")?.fields.length ?? 0,
    subscriptions: rootType(schema, "subscription")?.fields.length ?? 0,
  };
}

/** Schema Definition Language text for the loaded schema. */
export function printSchema(schema: Schema): string {
  const describe = (text: string, indent = "") =>
    text ? `${indent}"""${text.includes("\n") ? `\n${text}\n${indent}` : text}"""\n` : "";
  const args = (list: InputValue[]) =>
    list.length
      ? `(${list.map((a) => `${a.name}: ${typeToString(a.type)}${a.defaultValue !== null ? ` = ${a.defaultValue}` : ""}`).join(", ")})`
      : "";
  const deprecated = (flag: boolean, reason: string) =>
    flag ? ` @deprecated${reason ? `(reason: ${JSON.stringify(reason)})` : ""}` : "";
  const blocks: string[] = [];
  const defaults = { query: "Query", mutation: "Mutation", subscription: "Subscription" };
  const rootNames = {
    query: schema.queryType,
    mutation: schema.mutationType,
    subscription: schema.subscriptionType,
  };
  const custom = (Object.keys(defaults) as Operation[]).some(
    (op) => rootNames[op] && rootNames[op] !== defaults[op],
  );
  if (custom) {
    const lines = (Object.keys(defaults) as Operation[])
      .filter((op) => rootNames[op])
      .map((op) => `  ${op}: ${rootNames[op]}`);
    blocks.push(`schema {\n${lines.join("\n")}\n}`);
  }
  for (const type of [...userTypes(schema)].sort((a, b) => a.name.localeCompare(b.name))) {
    let body = "";
    if (type.kind === "SCALAR") {
      if (BUILTIN_SCALARS.has(type.name)) continue;
      body = `scalar ${type.name}`;
    } else if (type.kind === "OBJECT" || type.kind === "INTERFACE") {
      const implement = type.interfaces.length ? ` implements ${type.interfaces.join(" & ")}` : "";
      const fields = type.fields.map(
        (f) =>
          `${describe(f.description, "  ")}  ${f.name}${args(f.args)}: ${typeToString(f.type)}${deprecated(f.deprecated, f.deprecationReason)}`,
      );
      body = `${type.kind === "OBJECT" ? "type" : "interface"} ${type.name}${implement} {\n${fields.join("\n")}\n}`;
    } else if (type.kind === "UNION") {
      body = `union ${type.name} = ${type.possibleTypes.join(" | ")}`;
    } else if (type.kind === "ENUM") {
      body = `enum ${type.name} {\n${type.enumValues.map((v) => `  ${v.name}${deprecated(v.deprecated, v.deprecationReason)}`).join("\n")}\n}`;
    } else if (type.kind === "INPUT_OBJECT") {
      body = `input ${type.name} {\n${type.inputFields.map((f) => `  ${f.name}: ${typeToString(f.type)}${f.defaultValue !== null ? ` = ${f.defaultValue}` : ""}`).join("\n")}\n}`;
    }
    if (body) blocks.push(`${describe(type.description)}${body}`);
  }
  return `${blocks.join("\n\n")}\n`;
}
