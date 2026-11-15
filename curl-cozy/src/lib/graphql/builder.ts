import {
  isLeaf,
  isRequired,
  namedType,
  rootType,
  typeToString,
  type Field,
  type GqlType,
  type Operation,
  type Schema,
  type TypeRef,
} from "./schema";

export type BuiltOperation = {
  query: string;
  variables: Record<string, unknown>;
  operationName: string;
};

const MAX_FIELDS = 25;
const MAX_UNION_MEMBERS = 6;

/** A value that satisfies the type, used to prefill variables. */
export function sampleValue(schema: Schema, ref: TypeRef, depth = 0): unknown {
  if (ref.kind === "NON_NULL") return ref.ofType ? sampleValue(schema, ref.ofType, depth) : null;
  if (ref.kind === "LIST")
    return ref.ofType && depth < 4 ? [sampleValue(schema, ref.ofType, depth + 1)] : [];
  const type = schema.types.get(ref.name ?? "");
  switch (type?.kind ?? "SCALAR") {
    case "ENUM":
      return type?.enumValues.find((v) => !v.deprecated)?.name ?? type?.enumValues[0]?.name ?? "";
    case "INPUT_OBJECT": {
      if (depth > 4) return {};
      const value: Record<string, unknown> = {};
      for (const field of type?.inputFields ?? [])
        if (isRequired(field)) value[field.name] = sampleValue(schema, field.type, depth + 1);
      return value;
    }
    default:
      switch (ref.name) {
        case "Int":
        case "Float":
          return 0;
        case "Boolean":
          return false;
        default:
          return "";
      }
  }
}

const hasRequiredArgs = (field: Field) => field.args.some(isRequired);

function selection(
  schema: Schema,
  type: GqlType | undefined,
  depth: number,
  path: string[],
  indent: string,
): string {
  if (!type) return "";
  const inner = `${indent}  `;
  if (type.kind === "UNION") {
    const members = type.possibleTypes.slice(0, MAX_UNION_MEMBERS).map((name) => {
      const member = schema.types.get(name);
      const body = member ? selection(schema, member, depth, [...path, type.name], inner) : "";
      return `${inner}... on ${name} ${body || "{\n" + inner + "  __typename\n" + inner + "}"}`;
    });
    return `{\n${inner}__typename\n${members.join("\n")}\n${indent}}`;
  }
  const lines: string[] = [];
  const nested: string[] = [];
  for (const field of type.fields) {
    if (field.deprecated || hasRequiredArgs(field)) continue;
    if (isLeaf(schema, field.type)) {
      if (lines.length < MAX_FIELDS) lines.push(`${inner}${field.name}`);
    } else if (depth > 1) {
      const target = schema.types.get(namedType(field.type));
      // A type already on the path is not expanded again, which stops cycles such as User.friends.
      if (!target || path.includes(target.name) || target.name === type.name) continue;
      const body = selection(schema, target, depth - 1, [...path, type.name], inner);
      if (body) nested.push(`${inner}${field.name} ${body}`);
    }
  }
  const all = [...lines, ...nested.slice(0, 8)];
  if (!all.length) all.push(`${inner}__typename`);
  return `{\n${all.join("\n")}\n${indent}}`;
}

const pascal = (name: string) =>
  name.replace(/(^|[^A-Za-z0-9]+)([A-Za-z0-9])/g, (_m, _s, c: string) => c.toUpperCase());

/** A ready-to-send operation for one root field: required arguments become variables with sample values. */
export function buildOperation(
  schema: Schema,
  operation: Operation,
  fieldName: string,
  options: { depth?: number } = {},
): BuiltOperation {
  const root = rootType(schema, operation);
  const field = root?.fields.find((f) => f.name === fieldName);
  if (!root || !field) throw new Error(`The schema has no ${operation} field “${fieldName}”.`);
  const required = field.args.filter(isRequired);
  const variables: Record<string, unknown> = {};
  for (const arg of required) variables[arg.name] = sampleValue(schema, arg.type);
  const operationName = pascal(field.name) || "Operation";
  const definitions = required.length
    ? `(${required.map((a) => `$${a.name}: ${typeToString(a.type)}`).join(", ")})`
    : "";
  const call = required.length
    ? `(${required.map((a) => `${a.name}: $${a.name}`).join(", ")})`
    : "";
  const target = isLeaf(schema, field.type) ? undefined : schema.types.get(namedType(field.type));
  const body = target
    ? ` ${selection(schema, target, Math.max(1, options.depth ?? 2), [root.name], "  ")}`
    : "";
  return {
    query: `${operation} ${operationName}${definitions} {\n  ${field.name}${call}${body}\n}`,
    variables,
    operationName,
  };
}
