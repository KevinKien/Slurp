import { useEffect, useMemo, useRef, useState } from "react";
import { Copy, Check, WrapText, Search, ChevronUp, ChevronDown, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { pretty } from "@/lib/traffic";
import { cn } from "@/lib/utils";

function Highlight({ line }: { line: string }) {
  const parts = line.split(
    /("(?:[^"\\]|\\.)*"\s*:|"(?:[^"\\]|\\.)*"|\b(?:true|false|null|\d+)\b)/g,
  );
  return (
    <>
      {parts.map((part, index) => (
        <span
          key={index}
          className={
            part.startsWith('"')
              ? part.trim().endsWith(":")
                ? "text-code-key"
                : "text-code-string"
              : /^(true|false|null|\d+)$/.test(part)
                ? "text-code-number"
                : ""
          }
        >
          {part}
        </span>
      ))}
    </>
  );
}

const MAX_HIGHLIGHTS = 10_000;
export function CodePane({
  title,
  body,
  raw,
  headers,
  extra,
}: {
  title: string;
  body: string;
  raw: string;
  headers: Record<string, string>;
  extra?: React.ReactNode;
}) {
  const [tab, setTab] = useState("Pretty");
  const [copied, setCopied] = useState(false);
  const [wrap, setWrap] = useState(true);
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const searchToggle = useRef<HTMLButtonElement>(null);
  const [matchCase, setMatchCase] = useState(false);
  const [selection, setSelection] = useState({ text: "", query: "", matchCase: false, index: 0 });
  const viewport = useRef<HTMLDivElement>(null);
  const searchInput = useRef<HTMLInputElement>(null);
  const searchable = title === "Response" || title === "Request";
  const searchName = title.toLowerCase();
  const text = useMemo(
    () =>
      tab === "Headers"
        ? Object.entries(headers)
            .map(([key, value]) => `${key}: ${value}`)
            .join("\n")
        : tab === "Raw"
          ? raw
          : pretty(body),
    [tab, headers, raw, body],
  );
  const { matches, limited } = useMemo(() => {
    const found: { start: number; end: number }[] = [];
    if (!searchable || !query) return { matches: found, limited: false };
    const pattern = new RegExp(
      query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
      matchCase ? "g" : "gi",
    );
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(text))) {
      if (found.length === MAX_HIGHLIGHTS) return { matches: found, limited: true };
      found.push({ start: match.index, end: match.index + match[0].length });
    }
    return { matches: found, limited: false };
  }, [text, query, matchCase, searchable]);
  const active =
    selection.text === text && selection.query === query && selection.matchCase === matchCase
      ? Math.min(selection.index, Math.max(0, matches.length - 1))
      : 0;
  const lines = useMemo(() => {
    let offset = 0;
    let cursor = 0;
    return text.split("\n").map((line) => {
      const start = offset;
      const end = start + line.length;
      offset = end + 1;
      while (cursor < matches.length && matches[cursor]!.end <= start) cursor++;
      const segments: { start: number; end: number; index: number }[] = [];
      for (let index = cursor; index < matches.length && matches[index]!.start < end; index++) {
        const match = matches[index]!;
        segments.push({
          start: Math.max(0, match.start - start),
          end: Math.min(line.length, match.end - start),
          index,
        });
      }
      return { line, segments };
    });
  }, [text, matches]);
  useEffect(() => {
    if (matches.length)
      viewport.current
        ?.querySelector<HTMLElement>(`[data-search-match="${active}"]`)
        ?.scrollIntoView?.({ block: "center", inline: "nearest" });
  }, [active, matches]);
  useEffect(() => {
    if (searchOpen) {
      searchInput.current?.focus();
      searchInput.current?.select();
    }
  }, [searchOpen]);
  const closeSearch = () => {
    setSearchOpen(false);
    setQuery("");
    searchToggle.current?.focus();
  };
  const navigate = (direction: number) => {
    if (matches.length)
      setSelection({
        text,
        query,
        matchCase,
        index: (active + direction + matches.length) % matches.length,
      });
  };
  return (
    <section
      className="flex h-full min-w-0 flex-col bg-background"
      tabIndex={searchable ? 0 : undefined}
      onKeyDown={(event) => {
        if (searchable && (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "f") {
          event.preventDefault();
          setSearchOpen(true);
          searchInput.current?.focus();
          searchInput.current?.select();
        }
      }}
    >
      <div className="flex min-h-11 shrink-0 flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-2">
        <span className="font-medium">
          {title} {extra}
        </span>
        <div className="flex items-center gap-1">
          {searchable && (
            <Button
              ref={searchToggle}
              variant="ghost"
              size="icon"
              className={cn("h-7 w-7", searchOpen ? "text-primary" : "text-muted-foreground")}
              aria-label={`Toggle ${searchName} search`}
              aria-expanded={searchOpen}
              title={`Search ${searchName} (Ctrl/Cmd+F)`}
              onClick={() => (searchOpen ? closeSearch() : setSearchOpen(true))}
            >
              <Search />
            </Button>
          )}
          <div className="flex rounded bg-muted p-0.5">
            {["Pretty", "Raw", "Headers"].map((value) => (
              <Button
                key={value}
                variant="ghost"
                size="sm"
                onClick={() => setTab(value)}
                className={cn(
                  "h-6 px-2 text-[11px]",
                  tab === value ? "bg-secondary text-foreground" : "text-muted-foreground",
                )}
              >
                {value}
              </Button>
            ))}
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground"
            title="Toggle line wrapping"
            aria-label={`Wrap ${title}`}
            onClick={() => setWrap(!wrap)}
          >
            <WrapText />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground"
            title="Copy to clipboard"
            aria-label={`Copy ${title}`}
            onClick={async () => {
              await navigator.clipboard.writeText(text);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            }}
          >
            {copied ? <Check /> : <Copy />}
          </Button>
        </div>
      </div>
      {searchable && searchOpen && (
        <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-border px-3 py-2">
          <div className="relative min-w-28 flex-1">
            <Search className="pointer-events-none absolute left-2 top-2 size-3.5 text-muted-foreground" />
            <input
              ref={searchInput}
              aria-label={`Search ${searchName}`}
              placeholder={`Search ${searchName}…`}
              className="inspector-input h-8 w-full pl-7 text-xs"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  navigate(event.shiftKey ? -1 : 1);
                } else if (event.key === "Escape") {
                  event.preventDefault();
                  closeSearch();
                }
              }}
            />
          </div>
          <span
            role="status"
            aria-label={`${title} search results`}
            className="min-w-12 text-center font-mono text-[10px] text-muted-foreground"
          >
            {query
              ? `${matches.length ? active + 1 : 0}/${matches.length}${limited ? "+" : ""}`
              : "—"}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="size-7 text-xs"
            aria-label="Match case"
            aria-pressed={matchCase}
            onClick={() => setMatchCase(!matchCase)}
          >
            Aa
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label="Previous match"
            title="Previous match (Shift+Enter)"
            disabled={!matches.length}
            onClick={() => navigate(-1)}
          >
            <ChevronUp />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label="Next match"
            title="Next match (Enter)"
            disabled={!matches.length}
            onClick={() => navigate(1)}
          >
            <ChevronDown />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="size-7"
            aria-label={`Close ${searchName} search`}
            title="Close search (Escape)"
            onClick={closeSearch}
          >
            <X />
          </Button>
          {limited && (
            <span className="w-full text-[10px] text-muted-foreground">
              Showing the first 10,000 matches. Refine your search for more specific results.
            </span>
          )}
        </div>
      )}
      <div ref={viewport} className="min-h-0 flex-1 overflow-auto py-4">
        <div className="code-lines">
          {lines.map(({ line, segments }, index) => {
            let offset = 0;
            return (
              <div className="code-line" key={index}>
                <span className={cn("code-line-content pr-4", !wrap && "whitespace-pre")}>
                  {segments.map((segment) => {
                    const prefix = line.slice(offset, segment.start);
                    offset = segment.end;
                    return (
                      <span key={segment.index}>
                        <Highlight line={prefix} />
                        <mark
                          data-search-match={segment.index}
                          aria-current={segment.index === active ? "true" : undefined}
                          className={cn(
                            "rounded-sm text-foreground",
                            segment.index === active
                              ? "bg-warning/60 outline outline-1 outline-warning"
                              : "bg-primary/25",
                          )}
                        >
                          <Highlight line={line.slice(segment.start, segment.end)} />
                        </mark>
                      </span>
                    );
                  })}
                  <Highlight line={line.slice(offset)} />
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
