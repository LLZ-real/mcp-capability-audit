#!/usr/bin/env node
/**
 * CLI.
 *
 * Exit codes:
 *   0  no critical findings (and no --fail-on threshold breached)
 *   1  findings at or above --fail-on
 *   2  usage / IO error
 */

import { existsSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { auditAll, VERSION } from "./audit.ts";
import { loadAll, FixtureError } from "./loader.ts";
import { renderJson, renderMarkdown, renderTerminal } from "./report.ts";
import { policyToYaml } from "./policy.ts";
import { CAPABILITY_ORDER } from "./types.ts";
import type { Severity } from "./types.ts";

const HELP = `
  mcp-capability-audit — what can this MCP server actually do?

  Usage
    mcp-capability-audit <paths...>       audit fixture files or directories
    mcp-capability-audit rules            list the combination rules
    mcp-capability-audit capabilities     list every capability and its signals

  Options
    --format <terminal|json|md>   output format            (default: terminal)
    --out <file>                  write report to a file
    --policy-out <file>           write the least-privilege policy as YAML
    --policy                      show the policy inline
    --verbose                     show evidence for every capability claim
    --fail-on <severity>          exit 1 on this severity or worse
    --no-color                    disable ANSI colors
    --version                     print version
    --help                        print this message

  Exit codes: 0 clean · 1 findings at/above --fail-on · 2 usage error

  Severity: critical | high | medium | low
`;

class UsageError extends Error {}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

function parse(argv: string[]) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      format: { type: "string", default: "terminal" },
      out: { type: "string" },
      "policy-out": { type: "string" },
      policy: { type: "boolean", default: false },
      verbose: { type: "boolean", default: false },
      "fail-on": { type: "string" },
      "no-color": { type: "boolean", default: false },
      version: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  const format = String(values.format);
  if (!["terminal", "json", "md"].includes(format)) {
    throw new UsageError(`--format must be terminal, json, or md (got "${format}")`);
  }
  const failOn = values["fail-on"] as string | undefined;
  if (failOn && !SEVERITIES.includes(failOn as Severity)) {
    throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(", ")}`);
  }

  return {
    paths: positionals,
    command: positionals[0],
    format: format as "terminal" | "json" | "md",
    out: values.out as string | undefined,
    policyOut: values["policy-out"] as string | undefined,
    showPolicy: Boolean(values.policy),
    verbose: Boolean(values.verbose),
    failOn: failOn as Severity | undefined,
    color: !values["no-color"] && process.stdout.isTTY !== false,
    version: Boolean(values.version),
    help: Boolean(values.help),
  };
}

async function main(): Promise<number> {
  let args: ReturnType<typeof parse>;
  try {
    args = parse(process.argv.slice(2));
  } catch (e) {
    process.stderr.write(`error: ${(e as Error).message}\n${HELP}`);
    return 2;
  }

  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }

  if (args.command === "capabilities") {
    const { CAPABILITY_SIGNALS } = await import("./capabilities.ts");
    const L: string[] = [""];
    for (const cap of CAPABILITY_ORDER) {
      const sig = CAPABILITY_SIGNALS[cap];
      if (!sig) continue;
      L.push(`  ${cap}`);
      L.push(`    name:   ${sig.name.join(", ") || "—"}`);
      L.push(`    prose:  ${sig.prose.slice(0, 8).join(", ") || "—"}`);
      L.push(`    params: ${sig.schema.join(", ") || "—"}`);
      L.push("");
    }
    process.stdout.write(L.join("\n"));
    return 0;
  }

  if (args.command === "rules") {
    const { COMBINATION_RULES } = await import("./composition.ts");
    const L: string[] = ["", `  ${COMBINATION_RULES.length} combination rules`, ""];
    for (const r of COMBINATION_RULES) {
      L.push(`  ${r.id.padEnd(30)} ${r.severity.toUpperCase().padEnd(9)} ${r.title}`);
      L.push(`    requires: ${r.requires.join(" + ")}`);
      for (const line of wrapText(r.detail, 84)) L.push(`    ${line}`);
      L.push("");
    }
    process.stdout.write(L.join("\n"));
    return 0;
  }

  if (args.paths.length === 0) {
    process.stderr.write(`error: no input. Pass a fixture path.\n${HELP}`);
    return 2;
  }
  for (const p of args.paths) {
    if (!existsSync(p)) {
      process.stderr.write(`error: path does not exist: ${p}\n`);
      return 2;
    }
  }

  let inputs;
  try {
    inputs = loadAll(args.paths);
  } catch (e) {
    const fe = e as FixtureError;
    process.stderr.write(`error: ${fe.message}${fe.file ? ` (${fe.file})` : ""}\n`);
    return 2;
  }
  if (inputs.length === 0) {
    process.stderr.write("error: no fixtures found\n");
    return 2;
  }

  const report = auditAll(inputs);

  let text: string;
  switch (args.format) {
    case "json":
      text = renderJson(report);
      break;
    case "md":
      text = renderMarkdown(report);
      break;
    default:
      text = renderTerminal(report, {
        color: args.color,
        verbose: args.verbose,
        showPolicy: args.showPolicy,
      });
  }

  if (args.out) {
    writeFileSync(args.out, text.endsWith("\n") ? text : text + "\n", "utf8");
    process.stderr.write(`report written to ${args.out}\n`);
  } else {
    process.stdout.write(text.endsWith("\n") ? text : text + "\n");
  }

  if (args.policyOut) {
    const yaml = report.servers
      .map((s) => `# ${s.server} (risk ${s.risk}/100, grade ${s.grade})\n${policyToYaml(s.policy)}`)
      .join("\n");
    writeFileSync(args.policyOut, yaml, "utf8");
    process.stderr.write(`policy written to ${args.policyOut}\n`);
  }

  if (args.failOn) {
    const threshold = SEVERITIES.indexOf(args.failOn);
    const breaching = SEVERITIES.slice(0, threshold + 1);
    const count = report.servers.reduce(
      (n, s) => n + s.findings.filter((f) => breaching.includes(f.severity)).length,
      0,
    );
    if (count > 0) {
      process.stderr.write(`error: ${count} finding(s) at or above "${args.failOn}"\n`);
      return 1;
    }
  }

  return 0;
}

function wrapText(text: string, width: number): string[] {
  const out: string[] = [];
  let cur = "";
  for (const w of text.split(/\s+/)) {
    if (cur.length + w.length + 1 > width) {
      out.push(cur);
      cur = w;
    } else {
      cur = cur ? `${cur} ${w}` : w;
    }
  }
  if (cur) out.push(cur);
  return out;
}

main().then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`fatal: ${(e as Error).stack ?? String(e)}\n`);
    process.exit(2);
  },
);
