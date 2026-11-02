/**
 * Audit assembly + risk scoring.
 */

import { extractCapabilities, toolRisk, isMutating, isNetworked } from "./capabilities.ts";
import { compositionFindings, serverCapabilities, toolFindings } from "./composition.ts";
import { generatePolicy } from "./policy.ts";
import type {
  AuditReport,
  Finding,
  McpTool,
  Policy,
  ServerAudit,
  ServerTools,
  Severity,
  ToolCapabilities,
} from "./types.ts";

export const VERSION = "0.1.0";

export function auditTool(tool: McpTool): ToolCapabilities {
  const hits = extractCapabilities(tool);
  const caps = hits.map((h) => h.capability);
  return {
    name: tool.name,
    capabilities: hits,
    mutating: caps.some(isMutating),
    networked: caps.some(isNetworked),
    risk: toolRisk(hits),
  };
}

/**
 * Server risk.
 *
 * Deliberately *not* the mean of tool risks. A server with twenty harmless
 * readers and one shell tool is not "low risk" — the shell tool is the whole
 * story. So we take the max tool risk and add a bounded premium for
 * dangerous combinations, which are strictly worse than any single tool.
 */
export function serverRisk(tools: ToolCapabilities[], findings: Finding[]): number {
  const maxTool = tools.reduce((m, t) => Math.max(m, t.risk), 0);
  const comboPremium = findings
    .filter((f) => f.id.startsWith("combo/"))
    .reduce((sum, f) => sum + severityPremium(f.severity), 0);
  // Cap the premium so a server is not pushed to 100 by rule count alone.
  return Math.min(100, Math.round(maxTool + Math.min(30, comboPremium)));
}

function severityPremium(s: Severity): number {
  switch (s) {
    case "critical":
      return 12;
    case "high":
      return 7;
    case "medium":
      return 3;
    case "low":
      return 1;
  }
}

export function grade(risk: number): ServerAudit["grade"] {
  if (risk <= 20) return "A";
  if (risk <= 40) return "B";
  if (risk <= 60) return "C";
  if (risk <= 80) return "D";
  return "F";
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function auditServer(input: ServerTools): ServerAudit {
  const tools = input.tools.map(auditTool);

  const findings: Finding[] = [];
  for (const t of tools) {
    const raw = input.tools.find((r) => r.name === t.name);
    if (raw) findings.push(...toolFindings(t, raw));
  }
  findings.push(...compositionFindings(tools));
  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const risk = serverRisk(tools, findings);
  const policy: Policy = generatePolicy(tools, findings);

  return {
    server: input.server,
    source: input.source,
    tools,
    capabilities: serverCapabilities(tools),
    findings,
    risk,
    grade: grade(risk),
    policy,
  };
}

export function auditAll(inputs: ServerTools[]): AuditReport {
  const servers = inputs.map(auditServer);
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let tools = 0;
  for (const s of servers) {
    tools += s.tools.length;
    for (const f of s.findings) bySeverity[f.severity]++;
  }

  const risks = servers.map((s) => s.risk);
  return {
    version: VERSION,
    generatedAt: new Date().toISOString(),
    servers,
    summary: {
      servers: servers.length,
      tools,
      capabilities: new Set(servers.flatMap((s) => s.capabilities)).size,
      findings: servers.reduce((a, s) => a + s.findings.length, 0),
      bySeverity,
      worstRisk: risks.length === 0 ? 0 : Math.max(...risks),
      meanRisk: risks.length === 0 ? 0 : Math.round(risks.reduce((a, b) => a + b, 0) / risks.length),
    },
  };
}
