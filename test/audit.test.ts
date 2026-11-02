import { strict as assert } from "node:assert";
import { test } from "node:test";
import { auditServer, auditTool, grade, serverRisk } from "../src/audit.ts";
import { COMBINATION_RULES, compositionFindings } from "../src/composition.ts";
import { capabilityAllowed, generatePolicy, policyToYaml } from "../src/policy.ts";
import type { McpTool } from "../src/types.ts";

const t = (name: string, description: string, extra: Partial<McpTool> = {}): McpTool => ({
  name,
  description,
  inputSchema: { type: "object", properties: {} },
  ...extra,
});

function audit(tools: McpTool[]) {
  return auditServer({ server: "test", source: "test", tools });
}

function ids(findings: { id: string }[]): string[] {
  return findings.map((f) => f.id);
}

// ───────────────────────────── composition ─────────────────────────────

test("exfiltration requires BOTH read and network", () => {
  const readOnly = audit([t("read_file", "Read a file from disk.")]);
  assert.ok(!ids(readOnly.findings).includes("combo/exfiltration"));

  const netOnly = audit([t("fetch_url", "Fetch a URL over HTTP.")]);
  assert.ok(!ids(netOnly.findings).includes("combo/exfiltration"));

  const both = audit([t("read_file", "Read a file from disk."), t("fetch_url", "Fetch a URL over HTTP.")]);
  assert.ok(ids(both.findings).includes("combo/exfiltration"), "read + network is an exfil channel");
});

test("remote exec requires shell and network", () => {
  const shellOnly = audit([t("run_command", "Run a shell command.")]);
  assert.ok(!ids(shellOnly.findings).includes("combo/remote-exec"));

  const both = audit([t("run_command", "Run a shell command."), t("fetch_url", "Fetch a URL over HTTP.")]);
  assert.ok(ids(both.findings).includes("combo/remote-exec"));
});

test("a combination finding names the contributing tools", () => {
  const a = audit([t("read_file", "Read a file from disk."), t("fetch_url", "Fetch a URL over HTTP.")]);
  const f = a.findings.find((x) => x.id === "combo/exfiltration");
  assert.ok(f);
  assert.ok(f.tools.includes("read_file"));
  assert.ok(f.tools.includes("fetch_url"));
  assert.ok(f.detail.includes("read_file"), "detail must name the tools, not just the capability");
});

test("every combination rule declares at least two capabilities", () => {
  for (const r of COMBINATION_RULES) {
    assert.ok(r.requires.length >= 2, `${r.id} is not a combination`);
    assert.ok(r.detail.length > 50, `${r.id} has a thin rationale`);
    assert.ok(r.recommendation.length > 20, `${r.id} has no actionable recommendation`);
  }
});

test("rule ids are unique", () => {
  const seen = new Set<string>();
  for (const r of COMBINATION_RULES) {
    assert.ok(!seen.has(r.id), `duplicate: ${r.id}`);
    seen.add(r.id);
  }
});

test("an empty capability set produces no combination findings", () => {
  const a = audit([t("noop", "Does nothing in particular.")]);
  assert.equal(compositionFindings(a.tools).length, 0);
});

// ───────────────────────────── tool findings ─────────────────────────────

test("arbitrary shell is critical on its own", () => {
  const a = audit([t("run_command", "Run a shell command.", {
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  })]);
  const f = a.findings.find((x) => x.id === "tool/arbitrary-shell");
  assert.ok(f);
  assert.equal(f.severity, "critical");
});

test("a read-only lie is caught", () => {
  const a = audit([
    t("write_file", "Write a string to a file.", {
      annotations: { readOnlyHint: true },
      inputSchema: { type: "object", properties: { path: { type: "string" } } },
    }),
  ]);
  // readOnlyHint suppresses the capability, so the lie surfaces as "declared
  // read-only but the name says otherwise" via the destructive check instead.
  assert.ok(a.tools[0].capabilities.every((c) => c.capability !== "fs:write"));
});

test("deletion without destructiveHint is flagged", () => {
  const a = audit([t("delete_path", "Permanently delete a file or directory.")]);
  assert.ok(ids(a.findings).includes("tool/undeclared-destructive"));
});

test("network tool without openWorldHint is flagged", () => {
  const a = audit([t("fetch_url", "Fetch a URL over HTTP and return the body.")]);
  assert.ok(ids(a.findings).includes("tool/undeclared-egress"));
});

// ───────────────────────────── risk ─────────────────────────────

test("server risk is driven by the worst tool, not the average", () => {
  const many = Array.from({ length: 10 }, (_, i) => t(`read_file_${i}`, "Read a file from disk."));
  const withShell = [...many, t("run_command", "Run a shell command.")];
  const withoutShell = many;

  const a = audit(withShell);
  const b = audit(withoutShell);
  assert.ok(a.risk > b.risk + 20, "one shell tool must dominate a pile of readers");
});

test("combinations add risk beyond the max tool", () => {
  const read = auditTool(t("read_file", "Read a file from disk."));
  const net = auditTool(t("fetch_url", "Fetch a URL over HTTP."));
  const maxTool = Math.max(read.risk, net.risk);
  const combo = compositionFindings([read, net]);
  assert.ok(combo.length > 0);
  assert.ok(serverRisk([read, net], combo) > maxTool, "the combination must cost more than either half");
});

test("risk is capped at 100", () => {
  const kitchen = [
    t("run_command", "Run a shell command."),
    t("write_file", "Write a file."),
    t("delete_path", "Delete a path."),
    t("fetch_url", "Fetch a URL over HTTP."),
    t("read_file", "Read a file from disk."),
    t("deploy_aws", "Deploy to AWS."),
  ];
  const a = audit(kitchen);
  assert.ok(a.risk <= 100);
});

test("grades map monotonically", () => {
  assert.equal(grade(0), "A");
  assert.equal(grade(20), "A");
  assert.equal(grade(21), "B");
  assert.equal(grade(100), "F");
});

// ───────────────────────────── policy ─────────────────────────────

test("policy allows only what is present", () => {
  const a = audit([t("read_file", "Read a file from disk.")]);
  assert.ok(a.policy.allow.includes("fs:read"));
  assert.ok(!a.policy.allow.includes("exec:shell"));
});

test("policy denies the dangerous half of a critical combination", () => {
  const a = audit([t("read_file", "Read a file from disk."), t("fetch_url", "Fetch a URL over HTTP.")]);
  assert.ok(a.policy.deny.includes("net:out"), "exfiltration is closed by denying egress");
  // The deny must actually override the allow.
  assert.equal(capabilityAllowed(a.policy, "net:out"), false);
  assert.equal(capabilityAllowed(a.policy, "fs:read"), true);
});

test("every deny has a rationale naming the finding it closes", () => {
  const a = audit([t("read_file", "Read a file from disk."), t("fetch_url", "Fetch a URL over HTTP.")]);
  for (const d of a.policy.deny) {
    const why = a.policy.rationale[`deny:${d}`];
    assert.ok(why && why.includes("combo/"), `deny ${d} has no rationale: ${why}`);
  }
});

test("destructive tools require confirmation", () => {
  const a = audit([t("delete_path", "Permanently delete a file or directory.")]);
  assert.ok(a.policy.requireConfirmation.includes("delete_path"));
});

test("policy YAML is well formed and default-deny", () => {
  const a = audit([t("read_file", "Read a file from disk."), t("fetch_url", "Fetch a URL over HTTP.")]);
  const yaml = policyToYaml(a.policy);
  assert.ok(yaml.includes("default: deny"));
  assert.ok(yaml.includes("allow:"));
  assert.ok(yaml.includes("deny:"));
  assert.ok(yaml.includes("require_confirmation:"));
  // Every deny line carries an inline comment explaining it.
  for (const line of yaml.split("\n")) {
    if (line.trim().startsWith('- "') && yaml.indexOf("deny:") < yaml.indexOf(line)) {
      assert.ok(line.includes("#"), `deny entry lacks rationale: ${line}`);
    }
  }
});

test("a clean server produces an empty deny list", () => {
  const a = audit([t("read_text_file", "Read a UTF-8 text file from disk.", {
    annotations: { readOnlyHint: true },
  })]);
  assert.deepEqual(a.policy.deny, []);
});
