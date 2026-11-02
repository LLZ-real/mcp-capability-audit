/**
 * Capability model.
 *
 * A *capability* is a primitive effect a tool can have on the world. The
 * audit does not care what a tool is called; it cares which of these it can
 * exercise. Combinations are what make a server dangerous, so capabilities
 * are modelled as a set with an explicit composition analysis on top.
 */

export interface JSONSchema {
  type?: string | string[];
  description?: string;
  properties?: Record<string, JSONSchema>;
  required?: string[];
  enum?: unknown[];
  items?: JSONSchema;
  default?: unknown;
  format?: string;
  [key: string]: unknown;
}

export interface McpTool {
  name: string;
  description?: string;
  inputSchema?: JSONSchema;
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
}

export interface ServerTools {
  server: string;
  source: string;
  tools: McpTool[];
}

/**
 * Primitive capabilities, ordered from least to most dangerous for display.
 *
 * `fs:read` and `net:out` look mild alone. Together they are an exfiltration
 * channel -- that is the whole point of tracking them as a set.
 */
export type Capability =
  | "fs:read"
  | "fs:write"
  | "fs:delete"
  | "net:out"
  | "net:listen"
  | "exec:shell"
  | "exec:code"
  | "db:read"
  | "db:write"
  | "secrets:read"
  | "proc:spawn"
  | "env:read"
  | "env:write"
  | "cloud:control"
  | "browser:control"
  | "clipboard"
  | "notification"
  | "unknown";

export const CAPABILITY_ORDER: readonly Capability[] = [
  "fs:read",
  "env:read",
  "db:read",
  "fs:write",
  "env:write",
  "db:write",
  "fs:delete",
  "net:out",
  "net:listen",
  "secrets:read",
  "proc:spawn",
  "exec:code",
  "exec:shell",
  "cloud:control",
  "browser:control",
  "clipboard",
  "notification",
  "unknown",
] as const;

export interface CapabilityHit {
  capability: Capability;
  /** Which tool exposed it. */
  tool: string;
  /** What in the tool made us believe this — the evidence trail. */
  evidence: string;
  /** How sure we are, 0..1. */
  confidence: number;
}

/** A tool after analysis. */
export interface ToolCapabilities {
  name: string;
  capabilities: CapabilityHit[];
  /** True when the tool mutates anything at all. */
  mutating: boolean;
  /** True when the tool's effects leave the machine. */
  networked: boolean;
  /** Tool-level risk, 0..100 (higher = worse). */
  risk: number;
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  /** Capabilities that combined to produce this finding. */
  capabilities: Capability[];
  /** Tools involved. */
  tools: string[];
  recommendation: string;
}

export interface ServerAudit {
  server: string;
  source: string;
  tools: ToolCapabilities[];
  capabilities: Capability[];
  findings: Finding[];
  risk: number;
  grade: "A" | "B" | "C" | "D" | "F";
  /** Generated least-privilege policy. */
  policy: Policy;
}

export interface Policy {
  /** Deny-by-default allow list of capability globs. */
  allow: string[];
  /** Explicit denies that override allows. */
  deny: string[];
  /** Tools that must be confirmed by a human before running. */
  requireConfirmation: string[];
  /** Human-readable justification for each entry. */
  rationale: Record<string, string>;
}

export interface AuditReport {
  version: string;
  generatedAt: string;
  servers: ServerAudit[];
  summary: {
    servers: number;
    tools: number;
    capabilities: number;
    findings: number;
    bySeverity: Record<Severity, number>;
    worstRisk: number;
    meanRisk: number;
  };
}
