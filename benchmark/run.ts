/**
 * Benchmark: is the auditor *right*?
 *
 * A security tool that produces plausible-sounding findings is worse than
 * nothing, so accuracy is measured against fixtures with known ground truth.
 * Two failure modes are tracked separately because they are not equally bad:
 *
 *   false negative — a real capability missed. The tool says "safe" when the
 *                    server can shell out. This is the dangerous one.
 *   false positive — a capability invented. This is what makes users turn the
 *                    tool off, and what fabricates combination findings.
 *
 * The harness fails if any false negative occurs, or if false positives
 * exceed the budget.
 *
 * Run: node --experimental-strip-types benchmark/run.ts
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { auditServer } from "../src/audit.ts";
import { parseFixture } from "../src/loader.ts";
import { EXPECTATIONS, type Expectation } from "./expectations.ts";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

interface Result {
  file: string;
  detected: string[];
  falseNegatives: string[];
  falsePositives: string[];
  missingFindings: string[];
  spuriousFindings: string[];
  risk: number;
  riskOk: boolean;
}

function runOne(exp: Expectation): Result {
  const raw = JSON.parse(readFileSync(join(root, "fixtures", exp.file), "utf8"));
  const input = parseFixture(raw, exp.file);
  const audit = auditServer(input);

  const detected = audit.capabilities;
  const falseNegatives = exp.mustDetect.filter((c) => !detected.includes(c));
  const falsePositives = exp.mustNotDetect.filter((c) => detected.includes(c));

  const findingIds = audit.findings.map((f) => f.id);
  const missingFindings = exp.mustFind.filter((f) => !findingIds.includes(f));
  const spuriousFindings = exp.mustNotFind.filter((f) => findingIds.includes(f));

  const [lo, hi] = exp.riskRange;
  const riskOk = audit.risk >= lo && audit.risk <= hi;

  return {
    file: exp.file,
    detected,
    falseNegatives,
    falsePositives,
    missingFindings,
    spuriousFindings,
    risk: audit.risk,
    riskOk,
  };
}

const results = EXPECTATIONS.map(runOne);

// ── reporting ───────────────────────────────────────────────────────────
const pad = (s: string | number, n: number) => String(s).padEnd(n);

console.log("");
console.log("  Ground-truth accuracy");
console.log("  " + "─".repeat(72));
console.log("  " + pad("fixture", 26) + pad("caps", 6) + pad("risk", 6) + pad("FN", 5) + pad("FP", 5) + pad("miss", 6) + "spurious");
console.log("  " + "─".repeat(72));

for (const r of results) {
  console.log(
    "  " +
      pad(r.file, 26) +
      pad(r.detected.length, 6) +
      pad(r.risk + (r.riskOk ? "" : "!"), 6) +
      pad(r.falseNegatives.length, 5) +
      pad(r.falsePositives.length, 5) +
      pad(r.missingFindings.length, 6) +
      r.spuriousFindings.length,
  );
}

const totalFN = results.reduce((n, r) => n + r.falseNegatives.length, 0);
const totalFP = results.reduce((n, r) => n + r.falsePositives.length, 0);
const totalMissing = results.reduce((n, r) => n + r.missingFindings.length, 0);
const totalSpurious = results.reduce((n, r) => n + r.spuriousFindings.length, 0);
const totalExpected = EXPECTATIONS.reduce(
  (n, e) => n + e.mustDetect.length + e.mustNotDetect.length,
  0,
);

console.log("  " + "─".repeat(72));
console.log(
  `  capability checks: ${totalExpected}   false negatives: ${totalFN}   false positives: ${totalFP}`,
);
console.log(`  finding checks:    miss: ${totalMissing}   spurious: ${totalSpurious}`);
console.log("");

// ── detail on failures ──────────────────────────────────────────────────
for (const r of results) {
  if (
    r.falseNegatives.length === 0 &&
    r.falsePositives.length === 0 &&
    r.missingFindings.length === 0 &&
    r.spuriousFindings.length === 0 &&
    r.riskOk
  ) {
    continue;
  }
  console.log(`  ${r.file}`);
  if (r.falseNegatives.length) console.log(`    MISSED capabilities: ${r.falseNegatives.join(", ")}`);
  if (r.falsePositives.length) console.log(`    INVENTED capabilities: ${r.falsePositives.join(", ")}`);
  if (r.missingFindings.length) console.log(`    MISSED findings: ${r.missingFindings.join(", ")}`);
  if (r.spuriousFindings.length) console.log(`    SPURIOUS findings: ${r.spuriousFindings.join(", ")}`);
  if (!r.riskOk) console.log(`    risk ${r.risk} outside expected range`);
  console.log("");
}

// ── invariants ──────────────────────────────────────────────────────────
const failures: string[] = [];
if (totalFN > 0) failures.push(`${totalFN} false negative(s) — the auditor missed a real capability`);
if (totalMissing > 0) failures.push(`${totalMissing} expected finding(s) did not fire`);
if (totalFP > 2) failures.push(`${totalFP} false positive(s) exceeds the budget of 2`);
if (totalSpurious > 0) failures.push(`${totalSpurious} spurious finding(s)`);

const sidecar = {
  generatedAt: new Date().toISOString(),
  totals: { checks: totalExpected, falseNegatives: totalFN, falsePositives: totalFP, missing: totalMissing, spurious: totalSpurious },
  results: results.map((r) => ({
    file: r.file,
    detected: r.detected,
    risk: r.risk,
    falseNegatives: r.falseNegatives,
    falsePositives: r.falsePositives,
  })),
  failures,
};

(await import("node:fs")).writeFileSync(join(here, "summary.json"), JSON.stringify(sidecar, null, 2) + "\n");
console.log(`  wrote ${join(here, "summary.json")}`);
console.log("");

if (failures.length > 0) {
  console.error("  BENCHMARK FAILED");
  for (const f of failures) console.error("   - " + f);
  process.exit(1);
}
console.log("  All invariants hold.");
console.log("");
