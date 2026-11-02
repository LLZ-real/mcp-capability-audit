/**
 * Report renderers.
 *
 * The terminal view leads with *combinations*, because that is the finding a
 * per-tool linter cannot produce. Per-tool capability detail comes second.
 */

import { CAPABILITY_ORDER } from "./types.ts";
import type { AuditReport, Capability, ServerAudit } from "./types.ts";
import { policyToYaml } from "./policy.ts";

const C = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  red: "\u001b[31m",
  brightRed: "\u001b[91m",
  yellow: "\u001b[33m",
  blue: "\u001b[34m",
  green: "\u001b[32m",
  gray: "\u001b[90m",
  magenta: "\u001b[35m",
  cyan: "\u001b[36m",
};

export interface RenderOptions {
  color: boolean;
  verbose: boolean;
  showPolicy: boolean;
}

const paint = (on: boolean, code: string, s: string) => (on ? `${code}${s}${C.reset}` : s);

function riskColor(risk: number): string {
  if (risk <= 20) return C.green;
  if (risk <= 40) return C.cyan;
  if (risk <= 60) return C.yellow;
  if (risk <= 80) return C.brightRed;
  return C.red;
}

function bar(value: number, width = 20): string {
  const filled = Math.round((value / 100) * width);
  return "█".repeat(filled) + "░".repeat(width - filled);
}

function severityTag(s: string, color: boolean): string {
  switch (s) {
    case "critical":
      return paint(color, C.brightRed, "CRIT");
    case "high":
      return paint(color, C.red, "HIGH");
    case "medium":
      return paint(color, C.yellow, "MED ");
    default:
      return paint(color, C.blue, "LOW ");
  }
}

function capabilityTag(cap: Capability, color: boolean): string {
  if (cap.startsWith("exec") || cap.startsWith("secrets") || cap.startsWith("cloud")) {
    return paint(color, C.brightRed, cap);
  }
  if (cap.startsWith("fs:delete") || cap.startsWith("db:write") || cap === "net:out") {
    return paint(color, C.red, cap);
  }
  return paint(color, C.cyan, cap);
}

export function renderTerminal(report: AuditReport, opts: RenderOptions): string {
  const { color } = opts;
  const L: string[] = [];

  L.push("");
  L.push(paint(color, C.bold, "  mcp-capability-audit") + paint(color, C.gray, `  v${report.version}`));
  L.push(
    paint(
      color,
      C.gray,
      `  ${report.summary.servers} server(s) · ${report.summary.tools} tools · ${report.summary.capabilities} distinct capabilities`,
    ),
  );
  L.push("");

  for (const s of report.servers) {
    L.push(renderServerHeader(s, opts));
    L.push("");

    if (s.findings.length === 0) {
      L.push("    " + paint(color, C.green, "no findings"));
      L.push("");
    } else {
      for (const f of s.findings) {
        const combo = f.id.startsWith("combo/");
        L.push(
          "    " +
            severityTag(f.severity, color) +
            "  " +
            paint(color, combo ? C.magenta : C.gray, (combo ? "▣ " : "· ") + f.id.padEnd(28)) +
            " " +
            paint(color, C.bold, f.title),
        );
        if (opts.verbose) {
          for (const line of wrap(f.detail, 88)) L.push("            " + paint(color, C.gray, line));
          for (const line of wrap("→ " + f.recommendation, 88)) L.push("            " + paint(color, C.green, line));
          L.push("");
        }
      }
      if (!opts.verbose) {
        L.push("            " + paint(color, C.gray, `(${s.findings.length} findings — use --verbose for detail)`));
        L.push("");
      }
    }

    L.push(renderCapabilityTable(s, opts));
    L.push("");

    if (opts.showPolicy) {
      L.push("    " + paint(color, C.bold, "Least-privilege policy"));
      L.push("");
      for (const line of policyToYaml(s.policy).split("\n")) {
        L.push("      " + paint(color, C.gray, line));
      }
      L.push("");
    }
  }

  L.push(renderSummary(report, opts));
  return L.join("\n");
}

function renderServerHeader(s: ServerAudit, opts: RenderOptions): string {
  const { color } = opts;
  return (
    "  " +
    paint(color, C.bold, s.server) +
    paint(color, C.gray, `  (${s.source})`) +
    "  " +
    paint(color, riskColor(s.risk), `risk ${String(s.risk).padStart(3)}/100`) +
    "  " +
    paint(color, C.gray, bar(s.risk, 10)) +
    "  " +
    paint(color, riskColor(s.risk), s.grade)
  );
}

function renderCapabilityTable(s: ServerAudit, opts: RenderOptions): string {
  const { color } = opts;
  const L: string[] = [];
  const present = CAPABILITY_ORDER.filter((c) => s.capabilities.includes(c));
  if (present.length === 0) return "    " + paint(color, C.gray, "no capabilities detected");

  L.push("    " + paint(color, C.gray, "capabilities"));
  for (const cap of present) {
    const owners = s.tools.filter((t) => t.capabilities.some((h) => h.capability === cap));
    const names = owners.map((o) => o.name).join(", ");
    L.push(
      "      " +
        capabilityTag(cap, color).padEnd(color ? 28 : 16) +
        "  " +
        paint(color, C.gray, truncate(names, 46)),
    );
    if (opts.verbose) {
      for (const o of owners) {
        const hit = o.capabilities.find((h) => h.capability === cap);
        if (hit) L.push("        " + paint(color, C.dim, `${o.name}: ${hit.evidence} (${hit.confidence})`));
      }
    }
  }
  return L.join("\n");
}

function renderSummary(report: AuditReport, opts: RenderOptions): string {
  const { color } = opts;
  const s = report.summary;
  const L: string[] = [];
  const rule = paint(color, C.gray, "  " + "─".repeat(74));

  L.push(rule);
  L.push("");
  L.push(
    "  " +
      paint(color, C.bold, "Overall") +
      "  worst " +
      paint(color, riskColor(s.worstRisk), `${s.worstRisk}/100`) +
      "   mean " +
      paint(color, riskColor(s.meanRisk), `${s.meanRisk}/100`) +
      "   " +
      paint(color, C.brightRed, `${s.bySeverity.critical} critical`) +
      paint(color, C.gray, " · ") +
      paint(color, C.red, `${s.bySeverity.high} high`) +
      paint(color, C.gray, " · ") +
      paint(color, C.yellow, `${s.bySeverity.medium} medium`),
  );
  L.push("");
  return L.join("\n");
}

function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (const para of text.split("\n")) {
    if (para.trim() === "") {
      out.push("");
      continue;
    }
    let cur = "";
    for (const w of para.split(/\s+/)) {
      if (cur.length + w.length + 1 > width) {
        out.push(cur);
        cur = "  " + w;
      } else {
        cur = cur ? `${cur} ${w}` : w;
      }
    }
    if (cur) out.push(cur);
  }
  return out;
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

// ───────────────────────────── markdown ─────────────────────────────

export function renderMarkdown(report: AuditReport): string {
  const L: string[] = [];
  const s = report.summary;

  L.push("# MCP capability audit");
  L.push("");
  L.push(`Generated ${report.generatedAt} · mcp-capability-audit v${report.version}`);
  L.push("");
  L.push(
    `**${s.servers} server(s) · ${s.tools} tools · ${s.bySeverity.critical} critical · ${s.bySeverity.high} high**`,
  );
  L.push("");

  L.push("## Overview");
  L.push("");
  L.push("| Server | Tools | Risk | Grade | Critical | High |");
  L.push("|---|---:|---:|:---:|---:|---:|");
  for (const srv of report.servers) {
    const crit = srv.findings.filter((f) => f.severity === "critical").length;
    const high = srv.findings.filter((f) => f.severity === "high").length;
    L.push(`| \`${srv.server}\` | ${srv.tools.length} | ${srv.risk} | ${srv.grade} | ${crit} | ${high} |`);
  }
  L.push("");

  for (const srv of report.servers) {
    L.push(`## \`${srv.server}\` — risk ${srv.risk}/100 (${srv.grade})`);
    L.push("");
    L.push(`Capabilities: ${srv.capabilities.map((c) => `\`${c}\``).join(", ") || "_none_"}`);
    L.push("");

    if (srv.findings.length > 0) {
      L.push("### Findings");
      L.push("");
      for (const f of srv.findings) {
        L.push(`#### ${severityBadge(f.severity)} ${f.title}`);
        L.push("");
        L.push(`\`${f.id}\` · capabilities: ${f.capabilities.map((c) => `\`${c}\``).join(", ")}`);
        L.push("");
        for (const line of f.detail.split("\n")) L.push(line);
        L.push("");
        L.push(`**Recommendation.** ${f.recommendation}`);
        L.push("");
      }
    } else {
      L.push("_No findings._");
      L.push("");
    }

    L.push("### Least-privilege policy");
    L.push("");
    L.push("```yaml");
    L.push(policyToYaml(srv.policy).trimEnd());
    L.push("```");
    L.push("");
  }

  return L.join("\n");
}

function severityBadge(s: string): string {
  switch (s) {
    case "critical":
      return "🔴 **CRITICAL**";
    case "high":
      return "🟠 **HIGH**";
    case "medium":
      return "🟡 **MEDIUM**";
    default:
      return "🔵 **LOW**";
  }
}

export function renderJson(report: AuditReport): string {
  return JSON.stringify(report, null, 2);
}
