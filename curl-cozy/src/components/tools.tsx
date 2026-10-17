import { useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { CODECS, encode, decode, type CodecId } from "@/lib/codec";
import { generateUuids, type UuidVersion } from "@/lib/uuid";
import {
  JWT_ALGS,
  decodeJwt,
  describeClaimTimes,
  signJwt,
  verifyJwt,
  type JwtAlg,
  type SecretEncoding,
} from "@/lib/jwt";

const editor = "inspector-input min-h-44 w-full font-mono text-xs";
function TextField({
  label,
  value,
  onChange,
  readOnly = false,
}: {
  label: string;
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
}) {
  return (
    <label className="block space-y-2 text-xs text-muted-foreground">
      <span>{label}</span>
      <textarea
        aria-label={label}
        className={editor}
        value={value}
        readOnly={readOnly}
        spellCheck={false}
        onChange={(e) => onChange?.(e.target.value)}
      />
    </label>
  );
}
function Copy({ value }: { value: string }) {
  return (
    <Button
      variant="outline"
      size="sm"
      disabled={!value}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast.success("Copied");
        } catch {
          toast.error("Could not copy. Select the output and copy manually.");
        }
      }}
    >
      Copy output
    </Button>
  );
}
function CodecTool() {
  const [codec, setCodec] = useState<CodecId>("base64");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [message, setMessage] = useState("");
  const [plus, setPlus] = useState(false);
  function run(direction: "encode" | "decode") {
    setMessage("");
    setOutput("");
    try {
      if (direction === "encode") setOutput(encode(codec, input));
      else {
        const result = decode(codec, input, { plusAsSpace: plus });
        if (result.ok) {
          setOutput(result.value);
          setMessage(result.note ?? "");
        } else setMessage(result.error);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Conversion failed");
    }
  }
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        <select
          aria-label="Encoding format"
          className="inspector-input text-sm"
          value={codec}
          onChange={(e) => {
            setCodec(e.target.value as CodecId);
            setOutput("");
            setMessage("");
          }}
        >
          {CODECS.map((c) => (
            <option key={c.id} value={c.id}>
              {c.label}
            </option>
          ))}
        </select>
        {codec === "url" && (
          <label className="text-xs">
            <input type="checkbox" checked={plus} onChange={(e) => setPlus(e.target.checked)} />{" "}
            Decode + as space
          </label>
        )}
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <TextField label="Input" value={input} onChange={setInput} />
        <TextField label="Output" value={output} readOnly />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button onClick={() => run("encode")}>Encode</Button>
        <Button variant="secondary" onClick={() => run("decode")}>
          Decode
        </Button>
        <Button
          variant="outline"
          onClick={() => {
            setInput(output);
            setOutput(input);
            setMessage("");
          }}
        >
          Swap
        </Button>
        <Copy value={output} />
      </div>
      {message && (
        <p role="status" className="text-sm text-warning">
          {message}
        </p>
      )}
    </div>
  );
}
function UuidTool() {
  const [version, setVersion] = useState<UuidVersion>("v4");
  const [count, setCount] = useState(1);
  const [uppercase, setUppercase] = useState(false);
  const [hyphens, setHyphens] = useState(true);
  const [output, setOutput] = useState("");
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <label>
          Version{" "}
          <select
            aria-label="UUID version"
            className="inspector-input"
            value={version}
            onChange={(e) => setVersion(e.target.value as UuidVersion)}
          >
            <option value="v4">UUID v4 (random)</option>
            <option value="v7">UUID v7 (time ordered)</option>
          </select>
        </label>
        <label>
          Count{" "}
          <input
            aria-label="UUID count"
            className="inspector-input w-24"
            type="number"
            min={1}
            max={1000}
            value={count}
            onChange={(e) => setCount(Number(e.target.value))}
          />
        </label>
        <label>
          <input
            type="checkbox"
            checked={uppercase}
            onChange={(e) => setUppercase(e.target.checked)}
          />{" "}
          Uppercase
        </label>
        <label>
          <input type="checkbox" checked={hyphens} onChange={(e) => setHyphens(e.target.checked)} />{" "}
          Hyphens
        </label>
      </div>
      <Button
        onClick={() => setOutput(generateUuids(count, { version, uppercase, hyphens }).join("\n"))}
      >
        Generate UUIDs
      </Button>
      <TextField label="Generated UUIDs" value={output} readOnly />
      <Copy value={output} />
    </div>
  );
}
function JwtTool() {
  const [alg, setAlg] = useState<JwtAlg>("HS256");
  const [header, setHeader] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payload, setPayload] = useState('{\n  "sub": "1234567890",\n  "name": "John Doe"\n}');
  const [key, setKey] = useState("");
  const [secretEncoding, setSecretEncoding] = useState<SecretEncoding>("text");
  const [token, setToken] = useState("");
  const [output, setOutput] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  async function run(action: "sign" | "decode" | "verify") {
    setBusy(true);
    setMessage("");
    setOutput("");
    try {
      if (action === "sign") {
        const result = await signJwt({
          alg,
          headerText: header,
          payloadText: payload,
          key,
          secretEncoding,
        });
        setToken(result);
        setOutput(result);
        setMessage("Token generated.");
      } else if (action === "decode") {
        const decoded = decodeJwt(token);
        setOutput(
          JSON.stringify(
            {
              header: decoded.header,
              payload: decoded.payload,
              claimTimes: describeClaimTimes(decoded.payload),
            },
            null,
            2,
          ),
        );
        setMessage("Decoded only. The signature has not been verified.");
      } else {
        const result = await verifyJwt(token, { key, secretEncoding });
        setMessage(result.message);
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "JWT operation failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-5">
      <p className="text-xs text-muted-foreground">
        Decode signed JWTs (3 parts), generate tokens, or verify signatures. Decoding does not
        require a key. Encrypted JWE tokens are not supported.
      </p>
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <label>
          Signing algorithm{" "}
          <select
            aria-label="JWT algorithm"
            className="inspector-input"
            value={alg}
            onChange={(e) => {
              const next = e.target.value as JwtAlg;
              setAlg(next);
              try {
                setHeader(JSON.stringify({ ...JSON.parse(header), alg: next }, null, 2));
              } catch {
                /* Keep invalid JSON editable. */
              }
            }}
          >
            {JWT_ALGS.map((a) => (
              <option key={a}>{a}</option>
            ))}
          </select>
        </label>
        <label>
          Secret encoding{" "}
          <select
            aria-label="Secret encoding"
            className="inspector-input"
            value={secretEncoding}
            onChange={(e) => setSecretEncoding(e.target.value as SecretEncoding)}
          >
            <option value="text">UTF-8 text</option>
            <option value="base64">Base64</option>
          </select>
        </label>
      </div>
      <div className="grid gap-5 lg:grid-cols-2">
        <TextField label="JWT header (JSON)" value={header} onChange={setHeader} />
        <TextField label="JWT payload (JSON)" value={payload} onChange={setPayload} />
      </div>
      <TextField
        label="Secret / PEM private key (sign) / public key (verify)"
        value={key}
        onChange={setKey}
      />
      <p className="text-xs text-muted-foreground">
        HS*: shared secret. RS*/PS*/ES*: PEM private key for signing, public or private key for
        verification. Verification uses the algorithm in the token header.
      </p>
      <Button disabled={busy} onClick={() => run("sign")}>
        Generate JWT
      </Button>
      <TextField label="JWT token" value={token} onChange={setToken} />
      <div className="flex gap-2">
        <Button disabled={busy || !token.trim()} onClick={() => run("decode")}>
          Decode JWT
        </Button>
        <Button variant="secondary" disabled={busy || !token.trim()} onClick={() => run("verify")}>
          Verify signature
        </Button>
      </div>
      {message && (
        <p role="status" className="text-sm text-warning">
          {message}
        </p>
      )}
      <TextField label="JWT output" value={output} readOnly />
      <Copy value={output} />
    </div>
  );
}
export function ToolsView() {
  const [tab, setTab] = useState("codec");
  return (
    <div className="min-h-0 flex-1 overflow-auto p-6">
      <div className="max-w-6xl space-y-6">
        <div>
          <h1 className="text-xl font-semibold">Tools</h1>
          <p className="mt-2 text-xs text-muted-foreground">
            All conversions and cryptographic operations run locally in your browser. Keys and input
            are kept in page memory.
          </p>
        </div>
        <div role="tablist" aria-label="Tools" className="flex gap-2 border-b border-border pb-3">
          {[
            ["codec", "Encode / Decode"],
            ["uuid", "UUID generator"],
            ["jwt", "JWT"],
          ].map(([id, label]) => (
            <Button
              key={id}
              role="tab"
              aria-selected={tab === id}
              variant={tab === id ? "secondary" : "ghost"}
              onClick={() => setTab(id!)}
            >
              {label}
            </Button>
          ))}
        </div>
        <div role="tabpanel">
          {tab === "codec" ? <CodecTool /> : tab === "uuid" ? <UuidTool /> : <JwtTool />}
        </div>
      </div>
    </div>
  );
}
