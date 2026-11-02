/**
 * Least-privilege policy generation.
 *
 * The audit's output is only useful if it changes something. A list of scary
 * findings is a report; a policy you can paste into a config file is a
 * mitigation.
 *
 * The policy is deny-by-default: the `allow` list names the capability globs
 * the server genuinely needs, `deny` overrides them for the specific shapes
 * that caused a critical finding, and `requireConfirmation` names the tools a
 * human must approve.
 */

import type { Capability, Finding, Policy, ToolCapabilities } from "./types.ts";

/**
 * Capability globs are `group:action` with `*` support, e.g. `fs:*`, `*:read`.
 * The policy deliberately speaks in the same vocabulary as the audit so the
 * two can be diffed.
 */
function globMatches(glob: string, cap: Capability): boolean {
  if (glob === "*") return true;
  const [gGroup, gAction] = glob.split(":");
  const [cGroup, cAction] = cap.split(":");
  const groupOk = gGroup === "*" || gGroup === cGroup;
  const actionOk = gAction === "*" || gAction === cAction;
  return Boolean(groupOk && actionOk);
}

export function capabilityAllowed(policy: Policy, cap: Capability): boolean {
  const denied = policy.deny.some((d) => globMatches(d, cap));
  if (denied) return false;
  return policy.allow.some((a) => globMatches(a, cap));
}

/**
 * Generate a policy.
 *
 * Design choice: we allow what the server *demonstrably* needs (capabilities
 * that appear on at least one tool), and deny the specific capability halves
 * of any critical combination. Denying the whole group would break the
 * server; denying the dangerous half makes the combination impossible while
 * leaving ordinary reads and writes working.
 */
export function generatePolicy(tools: ToolCapabilities[], findings: Finding[]): Policy {
  const present = new Set<Capability>();
  for (const t of tools) for (const h of t.capabilities) present.add(h.capability);

  const rationale: Record<string, string> = {};
  const allow: string[] = [];
  const deny: string[] = [];

  // Allow exactly the capabilities observed, nothing more.
  for (const cap of [...present].sort()) {
    allow.push(cap);
    const owners = tools.filter((t) => t.capabilities.some((h) => h.capability === cap)).map((t) => t.name);
    rationale[cap] = `needed by ${owners.map((o) => `\`${o}\``).join(", ")}`;
  }

  // For each critical combination, deny the capability with the larger
  // blast radius. Denying `net:out` breaks every remote tool; denying the
  // local half is usually the narrower fix -- except for exfiltration, where
  // egress is the actual exfiltration path.
  const critical = findings.filter((f) => f.severity === "critical");
  const alreadyDenied = new Set<string>();

  for (const f of critical) {
    const target = pickDenyTarget(f.capabilities, present);
    if (!target) continue;
    if (alreadyDenied.has(target)) continue;
    alreadyDenied.add(target);
    if (!deny.includes(target)) {
      deny.push(target);
      rationale[`deny:${target}`] =
        `closes \`${f.id}\` — ${f.title.toLowerCase()}. Deny overrides allow, so this capability becomes unreachable even though a tool advertises it.`;
    }
  }

  // Tools that must be human-confirmed: anything destructive (deletion or
  // destructive DDL like `drop_table`), anything with the sharpest single-tool
  // edges (shell, cloud control), and anything implicated in a critical/high
  // finding.
  const requireConfirmation = new Set<string>();
  for (const t of tools) {
    const caps = t.capabilities.map((c) => c.capability);
    if (caps.includes("fs:delete") || caps.includes("exec:shell") || caps.includes("cloud:control") || t.destructive) {
      requireConfirmation.add(t.name);
    }
  }
  for (const f of findings) {
    if (f.severity === "critical" || f.severity === "high") {
      for (const t of f.tools) requireConfirmation.add(t);
    }
  }

  for (const name of requireConfirmation) {
    rationale[`confirm:${name}`] = "mutating or implicated in a high-severity finding";
  }

  return {
    allow: allow.sort(),
    deny: deny.sort(),
    requireConfirmation: [...requireConfirmation].sort(),
    rationale,
  };
}

/**
 * Which capability to deny to break a dangerous combination.
 *
 * Heuristic: prefer to deny the *effect* rather than the *input*. A server
 * that reads files is usually doing its job; a server that reaches the
 * internet is usually the thing you can turn off. Exceptions are noted.
 */
function pickDenyTarget(caps: Capability[], present: Set<Capability>): string | null {
  if (!caps.every((c) => present.has(c))) return null;

  // Egress is the exfiltration path in both of these: deny it.
  if (caps.includes("net:out") && (caps.includes("fs:read") || caps.includes("secrets:read"))) {
    return "net:out";
  }
  // For remote code execution, the shell is the sharper edge: deny it.
  if (caps.includes("exec:shell")) return "exec:shell";
  if (caps.includes("cloud:control")) return "cloud:control";
  // Destructive remote: deny deletion rather than the fetcher.
  if (caps.includes("fs:delete")) return "fs:delete";
  // Database read-write: deny writes.
  if (caps.includes("db:write")) return "db:write";
  if (caps.includes("exec:code")) return "exec:code";

  // Fall back to the rule's *last required* capability. That is rule order,
  // not a danger ranking — the deliberate choices above cover the rules whose
  // dangerous half is known.
  return caps[caps.length - 1] ?? null;
}

/** Render the policy as YAML-ish text (no dependency, easy to read). */
export function policyToYaml(policy: Policy): string {
  const lines: string[] = [];
  lines.push("version: 1");
  lines.push("default: deny");
  lines.push("");
  lines.push("allow:");
  if (policy.allow.length === 0) lines.push("  []");
  for (const a of policy.allow) {
    lines.push(`  - "${a}"   # ${policy.rationale[a] ?? ""}`);
  }
  lines.push("");
  lines.push("deny:");
  if (policy.deny.length === 0) lines.push("  []");
  for (const d of policy.deny) {
    lines.push(`  - "${d}"   # ${policy.rationale[`deny:${d}`] ?? ""}`);
  }
  lines.push("");
  lines.push("require_confirmation:");
  if (policy.requireConfirmation.length === 0) lines.push("  []");
  for (const c of policy.requireConfirmation) {
    lines.push(`  - "${c}"   # ${policy.rationale[`confirm:${c}`] ?? ""}`);
  }
  lines.push("");
  return lines.join("\n");
}
