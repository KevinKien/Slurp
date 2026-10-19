import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { ScanCoverage } from "../components/scan-coverage";
it("shows coverage without presenting planned browser checks as executable", () => {
  render(<ScanCoverage />);
  expect(screen.getByText(/Scan coverage ·/)).toHaveTextContent("experimental");
  const browser = screen.getByText("Full browser taint and interaction analysis").closest("tr");
  expect(browser).toHaveTextContent("planned");
  expect(browser).toHaveTextContent("Full taint propagation");
});
