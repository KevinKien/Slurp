/** Streaming TXT/CSV parsing; at most one bounded record and one upload batch are retained. */
export async function* fileTextChunks(file: File): AsyncGenerator<string> {
  if (file.size > 256 * 1024 * 1024) throw Error("Import files up to 256 MB.");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let offset = 0; offset < file.size; offset += 65536) {
    yield decoder.decode(await file.slice(offset, offset + 65536).arrayBuffer(), { stream: true });
  }
  const tail = decoder.decode();
  if (tail) yield tail;
}
export async function* parsePayloadRows(
  chunks: AsyncIterable<string>,
  format: "txt" | "csv",
): AsyncGenerator<string[]> {
  let field = "",
    row: string[] = [],
    quoted = false,
    closed = false,
    skipLF = false,
    first = true,
    touched = false,
    recordLength = 0;
  const reset = () => {
    field = "";
    row = [];
    closed = false;
    touched = false;
    recordLength = 0;
  };
  for await (let chunk of chunks) {
    if (first && chunk.length) {
      chunk = chunk.replace(/^\uFEFF/, "");
      first = false;
    }
    for (const char of chunk) {
      if (skipLF) {
        skipLF = false;
        if (char === "\n") continue;
      }
      recordLength +=
        char.codePointAt(0)! > 0xffff
          ? 4
          : char.charCodeAt(0) > 0x7ff
            ? 3
            : char.charCodeAt(0) > 0x7f
              ? 2
              : 1;
      if (recordLength > 65536) throw Error("A payload record exceeds 64 KB.");
      if (format === "txt") {
        if (char === "\n" || char === "\r") {
          yield [field];
          reset();
          skipLF = char === "\r";
        } else {
          field += char;
          touched = true;
        }
        continue;
      }
      if (quoted) {
        if (char === '"') {
          quoted = false;
          closed = true;
        } else field += char;
        touched = true;
        continue;
      }
      if (closed && char === '"') {
        field += '"';
        quoted = true;
        closed = false;
        continue;
      }
      if (char === ",") {
        row.push(field);
        field = "";
        closed = false;
        touched = true;
        if (row.length >= 1000) throw Error("CSV supports at most 1,000 columns.");
        continue;
      }
      if (char === "\n" || char === "\r") {
        row.push(field);
        yield row;
        reset();
        skipLF = char === "\r";
        continue;
      }
      if (closed) {
        if (char === " " || char === "\t") continue;
        throw Error("Unexpected text after a quoted CSV field.");
      }
      if (char === '"') {
        if (field.length) throw Error("A quote must start a CSV field.");
        quoted = true;
        touched = true;
        continue;
      }
      field += char;
      touched = true;
    }
  }
  if (quoted) throw Error("Unclosed quote in CSV file.");
  if (touched || field.length || row.length) yield [...row, field];
}
export async function csvColumns(file: File): Promise<string[]> {
  for await (const row of parsePayloadRows(fileTextChunks(file), "csv")) return row;
  throw Error("CSV file is empty.");
}
export async function* selectedPayloads(
  file: File,
  format: "txt" | "csv",
  column: number,
  hasHeader: boolean,
  skipEmpty: boolean,
): AsyncGenerator<string> {
  let rowIndex = 0;
  for await (const row of parsePayloadRows(fileTextChunks(file), format)) {
    rowIndex++;
    if (format === "csv" && hasHeader && rowIndex === 1) continue;
    const value = row[column];
    if (value === undefined) throw Error(`CSV record ${rowIndex} has no column ${column + 1}.`);
    if (skipEmpty && !value.length) continue;
    if (new TextEncoder().encode(value).length > 16384) throw Error("A payload exceeds 16 KB.");
    yield value;
  }
}
