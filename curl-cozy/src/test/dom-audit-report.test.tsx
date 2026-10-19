import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { DomAuditReport } from "../components/dom-audit-report";
it("shows script audit and payload decisions even when a scan has no findings", () => {
  render(
    <DomAuditReport
      audits={[
        {
          id: "a1",
          url: "https://app.test",
          notes: ["A dynamic import was not resolved"],
          runtimeScripts: ["https://app.test/runtime.js"],
          scripts: [
            {
              url: "https://app.test/app.js",
              evidenceId: "e1",
              sources: ["location.hash"],
              sinks: ["innerHTML"],
              parsed: true,
            },
          ],
          candidates: [
            {
              id: "c1",
              source: { kind: "fragment", label: "location.hash", decoded: true, base64: false },
              sink: "innerHTML",
              context: "html",
              script: "https://app.test/app.js",
              line: 12,
              column: 8,
              excerpt: "target.innerHTML=decodeURIComponent(location.hash.slice(1))",
              families: ["html-element"],
            },
          ],
        },
      ]}
    />,
  );
  fireEvent.click(screen.getByText("DOM script audit (1 scripts)"));
  expect(screen.getByRole("table", { name: "Audited scripts" })).toBeInTheDocument();
  expect(screen.getByText(/app.js:12:8/)).toBeInTheDocument();
  expect(screen.getByText(/Payload families: html-element/)).toBeInTheDocument();
  expect(screen.getByText("A dynamic import was not resolved")).toBeInTheDocument();
  expect(screen.getByText("Runtime script dependencies (1)")).toBeInTheDocument();
  expect(screen.getByText("https://app.test/runtime.js")).toBeInTheDocument();
});
