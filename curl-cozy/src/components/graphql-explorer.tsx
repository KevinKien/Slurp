import { useMemo, useState } from "react";
import { ArrowLeft, Play, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  namedType,
  operationsOf,
  rootType,
  schemaStats,
  searchSchema,
  typeToString,
  type Field,
  type GqlType,
  type InputValue,
  type Operation,
  type Schema,
  type TypeRef,
} from "@/lib/graphql/schema";

type Tab = Operation | "types";
type View = { type: string; focus?: string };

function TypeLink({
  schema,
  type,
  onOpen,
}: {
  schema: Schema;
  type: TypeRef;
  onOpen: (name: string) => void;
}) {
  const name = namedType(type);
  const text = typeToString(type);
  if (!name || !schema.types.has(name))
    return <span className="font-mono text-primary">{text}</span>;
  const [before, after] = text.split(name);
  return (
    <span className="font-mono">
      {before}
      <button
        type="button"
        className="text-primary underline-offset-2 hover:underline"
        onClick={() => onOpen(name)}
      >
        {name}
      </button>
      {after}
    </span>
  );
}

function Args({
  schema,
  args,
  onOpen,
}: {
  schema: Schema;
  args: InputValue[];
  onOpen: (name: string) => void;
}) {
  if (!args.length) return null;
  return (
    <ul className="mt-1 space-y-0.5 border-l border-border pl-3 text-[11px]">
      {args.map((arg) => (
        <li key={arg.name}>
          <span className="font-mono">{arg.name}</span>:{" "}
          <TypeLink schema={schema} type={arg.type} onOpen={onOpen} />
          {arg.defaultValue !== null && (
            <span className="text-muted-foreground"> = {arg.defaultValue}</span>
          )}
          {arg.description && (
            <span className="block text-muted-foreground">{arg.description}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function FieldRow({
  schema,
  field,
  onOpen,
  action,
}: {
  schema: Schema;
  field: Field;
  onOpen: (name: string) => void;
  action?: () => void;
}) {
  return (
    <li className="rounded px-2 py-1.5 text-xs hover:bg-secondary/40" data-field={field.name}>
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <span
            className={cn("font-mono font-medium", field.deprecated && "line-through opacity-60")}
          >
            {field.name}
          </span>
          {field.args.length > 0 && (
            <span className="text-muted-foreground">
              {" "}
              ({field.args.length} arg{field.args.length > 1 ? "s" : ""})
            </span>
          )}
          <span className="text-muted-foreground">: </span>
          <TypeLink schema={schema} type={field.type} onOpen={onOpen} />
          {field.deprecated && (
            <span className="ml-2 rounded bg-warning/10 px-1 text-[10px] text-warning">
              deprecated{field.deprecationReason ? `: ${field.deprecationReason}` : ""}
            </span>
          )}
          {field.description && <p className="mt-0.5 text-muted-foreground">{field.description}</p>}
          <Args schema={schema} args={field.args} onOpen={onOpen} />
        </div>
        {action && (
          <Button
            variant="outline"
            size="sm"
            className="h-6 shrink-0 gap-1 px-2 text-[10px]"
            title="Generate a ready-to-send operation"
            onClick={action}
          >
            <Play className="size-3" />
            Use
          </Button>
        )}
      </div>
    </li>
  );
}

function TypePage({
  schema,
  type,
  onOpen,
}: {
  schema: Schema;
  type: GqlType;
  onOpen: (name: string) => void;
}) {
  return (
    <div className="space-y-2 text-xs">
      <div>
        <span className="font-mono text-sm font-medium">{type.name}</span>
        <span className="ml-2 rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
          {type.kind.toLowerCase().replace("_", " ")}
        </span>
      </div>
      {type.description && <p className="text-muted-foreground">{type.description}</p>}
      {type.interfaces.length > 0 && (
        <p>
          Implements{" "}
          {type.interfaces.map((name) => (
            <button
              key={name}
              type="button"
              className="mr-2 font-mono text-primary hover:underline"
              onClick={() => onOpen(name)}
            >
              {name}
            </button>
          ))}
        </p>
      )}
      {type.possibleTypes.length > 0 && (
        <div>
          <div className="mb-1 text-[10px] tracking-wide text-muted-foreground">
            {type.kind === "UNION" ? "MEMBERS" : "IMPLEMENTATIONS"}
          </div>
          {type.possibleTypes.map((name) => (
            <button
              key={name}
              type="button"
              className="mr-2 font-mono text-primary hover:underline"
              onClick={() => onOpen(name)}
            >
              {name}
            </button>
          ))}
        </div>
      )}
      {type.fields.length > 0 && (
        <ul>
          {type.fields.map((field) => (
            <FieldRow key={field.name} schema={schema} field={field} onOpen={onOpen} />
          ))}
        </ul>
      )}
      {type.inputFields.length > 0 && (
        <ul>
          {type.inputFields.map((input) => (
            <li key={input.name} className="rounded px-2 py-1.5 hover:bg-secondary/40">
              <span className="font-mono font-medium">{input.name}</span>:{" "}
              <TypeLink schema={schema} type={input.type} onOpen={onOpen} />
              {input.defaultValue !== null && (
                <span className="text-muted-foreground"> = {input.defaultValue}</span>
              )}
              {input.description && <p className="text-muted-foreground">{input.description}</p>}
            </li>
          ))}
        </ul>
      )}
      {type.enumValues.length > 0 && (
        <ul>
          {type.enumValues.map((value) => (
            <li key={value.name} className="rounded px-2 py-1 hover:bg-secondary/40">
              <span className={cn("font-mono", value.deprecated && "line-through opacity-60")}>
                {value.name}
              </span>
              {value.description && (
                <span className="ml-2 text-muted-foreground">{value.description}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Browse a loaded schema: root operations, every type, search; "Use" turns a root field into an operation. */
export function GraphqlExplorer({
  schema,
  onUse,
  onCopySdl,
}: {
  schema: Schema;
  onUse: (operation: Operation, field: string) => void;
  onCopySdl: () => void;
}) {
  const operations = operationsOf(schema);
  const [tab, setTab] = useState<Tab>(operations[0] ?? "types");
  const [search, setSearch] = useState("");
  const [stack, setStack] = useState<View[]>([]);
  const stats = useMemo(() => schemaStats(schema), [schema]);
  const hits = useMemo(() => searchSchema(schema, search), [schema, search]);
  const view = stack[stack.length - 1];
  const open = (type: string, focus?: string) => {
    if (!schema.types.has(type)) return;
    setSearch("");
    setStack((previous) => [...previous, focus ? { type, focus } : { type }]);
  };
  const userTypes = useMemo(
    () =>
      [...schema.types.values()]
        .filter(
          (t) =>
            !t.name.startsWith("__") &&
            !["Int", "Float", "String", "Boolean", "ID"].includes(t.name),
        )
        .sort((a, b) => a.name.localeCompare(b.name)),
    [schema],
  );
  const root = tab === "types" ? undefined : rootType(schema, tab);
  const current = view ? schema.types.get(view.type) : undefined;

  return (
    <div className="flex min-h-0 flex-1 flex-col" aria-label="Schema explorer">
      <div className="flex items-center gap-2 border-b border-border px-3 py-2 text-[11px] text-muted-foreground">
        <span>
          {stats.types} types · {stats.queries} queries · {stats.mutations} mutations
          {stats.subscriptions ? ` · ${stats.subscriptions} subscriptions` : ""}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="ml-auto h-6 px-2 text-[10px]"
          onClick={onCopySdl}
        >
          Copy SDL
        </Button>
      </div>
      <div className="relative border-b border-border p-2">
        <Search className="absolute left-4 top-4 size-3.5 text-muted-foreground" />
        <input
          aria-label="Search schema"
          className="inspector-input h-8 w-full pl-8 text-xs"
          placeholder="Search types, fields, arguments…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {search.trim() ? (
          hits.length ? (
            <ul className="space-y-0.5 text-xs">
              {hits.map((hit, i) => (
                <li key={`${hit.type}.${hit.field ?? ""}.${hit.kind}.${i}`}>
                  <button
                    type="button"
                    className="w-full rounded px-2 py-1 text-left hover:bg-secondary/40"
                    onClick={() => open(hit.type, hit.field)}
                  >
                    <span className="font-mono">
                      {hit.field ? `${hit.type}.${hit.field}` : hit.type}
                    </span>
                    <span className="ml-2 text-muted-foreground">
                      {hit.kind} · {hit.detail}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="p-2 text-xs text-muted-foreground">Nothing matches “{search}”.</p>
          )
        ) : current ? (
          <div className="space-y-2">
            <Button
              variant="ghost"
              size="sm"
              className="h-6 gap-1 px-1 text-[11px]"
              onClick={() => setStack((previous) => previous.slice(0, -1))}
            >
              <ArrowLeft className="size-3" />
              Back
            </Button>
            <TypePage schema={schema} type={current} onOpen={(name) => open(name)} />
          </div>
        ) : (
          <>
            <div className="mb-2 flex gap-1 text-xs" role="tablist">
              {[...operations, "types" as const].map((id) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  className={cn(
                    "rounded px-2 py-1 capitalize",
                    tab === id
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-secondary/40",
                  )}
                  onClick={() => setTab(id)}
                >
                  {id === "types" ? "Types" : `${id}s`}
                </button>
              ))}
            </div>
            {root ? (
              <ul>
                {root.fields.map((field) => (
                  <FieldRow
                    key={field.name}
                    schema={schema}
                    field={field}
                    onOpen={(name) => open(name)}
                    action={() => onUse(tab as Operation, field.name)}
                  />
                ))}
              </ul>
            ) : (
              <ul className="space-y-0.5 text-xs">
                {userTypes.map((type) => (
                  <li key={type.name}>
                    <button
                      type="button"
                      className="flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-secondary/40"
                      onClick={() => open(type.name)}
                    >
                      <span className="font-mono">{type.name}</span>
                      <span className="text-[10px] text-muted-foreground">
                        {type.kind.toLowerCase().replace("_", " ")}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </div>
    </div>
  );
}
