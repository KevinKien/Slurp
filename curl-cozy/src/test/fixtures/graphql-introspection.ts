type Ref = { kind: string; name: string | null; ofType: Ref | null };
const named = (kind: string, name: string): Ref => ({ kind, name, ofType: null });
const nn = (of: Ref): Ref => ({ kind: "NON_NULL", name: null, ofType: of });
const list = (of: Ref): Ref => ({ kind: "LIST", name: null, ofType: of });
const S = (n: string) => named("SCALAR", n);
const O = (n: string) => named("OBJECT", n);
const arg = (name: string, type: Ref, defaultValue: string | null = null) => ({
  name,
  description: "",
  type,
  defaultValue,
});
const field = (
  name: string,
  type: Ref,
  args: ReturnType<typeof arg>[] = [],
  isDeprecated = false,
) => ({
  name,
  description: "",
  args,
  type,
  isDeprecated,
  deprecationReason: isDeprecated ? "use users" : null,
});
const type = (kind: string, name: string, extra: Record<string, unknown> = {}) => ({
  kind,
  name,
  description: null,
  fields: null,
  inputFields: null,
  interfaces: null,
  enumValues: null,
  possibleTypes: null,
  ...extra,
});

export const introspection = {
  data: {
    __schema: {
      queryType: { name: "Query" },
      mutationType: { name: "Mutation" },
      subscriptionType: null,
      directives: [
        {
          name: "include",
          description: "",
          locations: ["FIELD"],
          args: [arg("if", nn(S("Boolean")))],
        },
      ],
      types: [
        type("OBJECT", "Query", {
          fields: [
            field("user", O("User"), [arg("id", nn(S("ID")))]),
            field("users", nn(list(nn(O("User")))), [
              arg("first", S("Int")),
              arg("filter", named("INPUT_OBJECT", "UserFilter")),
            ]),
            field("search", nn(list(nn(named("UNION", "SearchResult")))), [
              arg("text", nn(S("String"))),
            ]),
            field("legacy", S("String"), [], true),
          ],
        }),
        type("OBJECT", "Mutation", {
          fields: [
            field("createUser", O("User"), [
              arg("input", nn(named("INPUT_OBJECT", "CreateUserInput"))),
            ]),
          ],
        }),
        type("OBJECT", "User", {
          fields: [
            field("id", nn(S("ID"))),
            field("name", nn(S("String"))),
            field("role", named("ENUM", "Role")),
            field("friends", nn(list(nn(O("User"))))),
            field("posts", nn(list(nn(O("Post")))), [arg("limit", S("Int"))]),
            field("secret", S("String"), [arg("token", nn(S("String")))]),
          ],
        }),
        type("OBJECT", "Post", {
          fields: [
            field("id", nn(S("ID"))),
            field("title", S("String")),
            field("author", O("User")),
          ],
        }),
        type("ENUM", "Role", {
          enumValues: [
            { name: "ADMIN", description: "", isDeprecated: false, deprecationReason: null },
            { name: "MEMBER", description: "", isDeprecated: false, deprecationReason: null },
          ],
        }),
        type("INPUT_OBJECT", "UserFilter", {
          inputFields: [arg("role", named("ENUM", "Role")), arg("name", S("String"))],
        }),
        type("INPUT_OBJECT", "CreateUserInput", {
          inputFields: [
            arg("name", nn(S("String"))),
            arg("role", nn(named("ENUM", "Role"))),
            arg("tags", nn(list(nn(S("String"))))),
            arg("note", S("String")),
          ],
        }),
        type("UNION", "SearchResult", { possibleTypes: [O("User"), O("Post")] }),
        type("SCALAR", "ID"),
        type("SCALAR", "String"),
        type("SCALAR", "Int"),
        type("SCALAR", "Boolean"),
        type("OBJECT", "__Schema", { fields: [] }),
      ],
    },
  },
};
