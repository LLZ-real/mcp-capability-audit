/**
 * Composition analysis.
 *
 * Single capabilities are usually fine. `fs:read` is a file reader.
 * `net:out` is an HTTP client. Both are reasonable.
 *
 * Together they are an exfiltration channel, and that is a completely
 * different risk statement than "this server can read files" plus "this
 * server can make requests". No per-tool linter catches it, because no
 * single tool is the problem — the *server* is.
 *
 * Each rule below encodes one such combination, with the reasoning spelled
 * out so a human can disagree with it.
 */

import type { Capability, Finding, McpTool, ToolCapabilities } from "./types.ts";
import { isMutating, isNetworked } from "./capabilities.ts";

interface CombinationRule {
  id: string;
  severity: Finding["severity"];
  /** All of these must be present. */
  requires: Capability[];
  title: string;
  detail: string;
  recommendation: string;
}

const RULES: CombinationRule[] = [
  {
    id: "combo/exfiltration",
    severity: "critical",
    requires: ["fs:read", "net:out"],
    title: "Exfiltration channel: local reads + outbound network",
    detail:
      "This server can read local files AND make outbound requests. An agent steered by a prompt injection — for example one that reads a poisoned file or a hostile web page — can read ~/.ssh/id_rsa or .env and POST it anywhere. No single tool does anything wrong; the combination is the vulnerability.",
    recommendation:
      "Split reads and network egress into separate servers, or pin egress to an allow-listed host set. If both are genuinely needed, require human confirmation on every network call that follows a read.",
  },
  {
    id: "combo/remote-exec",
    severity: "critical",
    requires: ["net:out", "exec:shell"],
    title: "Remote code execution: network input + shell",
    detail:
      "The server can fetch remote content and run shell commands. A compromised or merely mistyped endpoint turns into arbitrary code execution on the host. This is the classic `curl | sh` shape, except an agent decides when to pull the trigger.",
    recommendation:
      "Never allow fetched content to reach a shell in the same process. Sandbox the shell in a container with no network, or drop the shell capability entirely.",
  },
  {
    id: "combo/secrets-exfil",
    severity: "critical",
    requires: ["secrets:read", "net:out"],
    title: "Credential exposure: secret access + outbound network",
    detail:
      "The server can read credentials and make outbound calls. A single injected instruction is enough to ship an API key to an attacker. Credential access should essentially never coexist with arbitrary egress.",
    recommendation:
      "Move secret access to a separate server that has no network capability. Prefer short-lived tokens injected per-call over long-lived secrets in reach of the agent.",
  },
  {
    id: "combo/destructive-remote",
    severity: "high",
    requires: ["fs:delete", "net:out"],
    title: "Destructive actions driven by remote content",
    detail:
      "The server can delete files and fetch remote content. An agent that reads a page saying \"clean up /home\" can act on it. Deletion plus untrusted input is how an injection becomes data loss.",
    recommendation:
      "Require human confirmation for deletion, and make deletion scope-limited (a single known directory) rather than path-arbitrary.",
  },
  {
    id: "combo/shell-plus-write",
    severity: "high",
    requires: ["exec:shell", "fs:write"],
    title: "Shell access with arbitrary file writes",
    detail:
      "Writing files plus executing commands means the agent can persist code and then run it. Either capability alone is containable; together they are a foothold.",
    recommendation: "Run the shell in an ephemeral sandbox whose filesystem is discarded after the call.",
  },
  {
    id: "combo/db-destructive",
    severity: "high",
    requires: ["db:write", "db:read"],
    title: "Read-write database access in one server",
    detail:
      "The same server can read and mutate the database. A SELECT-shaped injection (or a confused agent) can escalate to UPDATE/DELETE. Read and write should be separate credentials at minimum.",
    recommendation:
      "Use a read-only database role for query tools, and a separate write path behind confirmation. Never share one connection string across both.",
  },
  {
    id: "combo/cloud-blast-radius",
    severity: "critical",
    requires: ["cloud:control", "net:out"],
    title: "Cloud control plane exposed to an agent",
    detail:
      "The server can drive cloud infrastructure. The blast radius is not this machine — it is every resource the credential can reach, including billing. Agent mistakes here are expensive and sometimes irreversible.",
    recommendation:
      "Scope the credential to a single resource and a single action set. Require explicit confirmation for anything tagged delete/terminate/scale.",
  },
  {
    id: "combo/browser-plus-secrets",
    severity: "high",
    requires: ["browser:control", "secrets:read"],
    title: "Browser automation with credential access",
    detail:
      "Browser control plus secret access lets an agent log in as a user and act with their authority, including on sites that trust the session cookie.",
    recommendation: "Give the browser a throwaway profile with no stored sessions, and no access to the secret store.",
  },
];

/** Which capabilities are present anywhere on the server. */
export function serverCapabilities(tools: ToolCapabilities[]): Capability[] {
  const set = new Set<Capability>();
  for (const t of tools) for (const h of t.capabilities) set.add(h.capability);
  return [...set];
}

/** Exposed for `mcp-capability-audit rules`. */
export const COMBINATION_RULES: readonly CombinationRule[] = RULES;

function toolsWith(tools: ToolCapabilities[], cap: Capability): string[] {
  return tools.filter((t) => t.capabilities.some((h) => h.capability === cap)).map((t) => t.name);
}

/**
 * Run combination rules.
 *
 * A rule only fires when *every* required capability is present. We report
 * the specific tools that contributed each half, because "this server is
 * dangerous" is not actionable and "read_file + fetch_url are dangerous
 * together" is.
 */
export function compositionFindings(tools: ToolCapabilities[]): Finding[] {
  const present = new Set(serverCapabilities(tools));
  const out: Finding[] = [];

  for (const rule of RULES) {
    if (!rule.requires.every((c) => present.has(c))) continue;

    const contributors = rule.requires.map((c) => ({ cap: c, tools: toolsWith(tools, c) }));
    const detailWithTools =
      rule.detail +
      "\n\n" +
      contributors.map((c) => `  • ${c.cap} via ${c.tools.map((t) => `\`${t}\``).join(", ")}`).join("\n");

    out.push({
      id: rule.id,
      severity: rule.severity,
      title: rule.title,
      detail: detailWithTools,
      capabilities: rule.requires,
      tools: [...new Set(contributors.flatMap((c) => c.tools))],
      recommendation: rule.recommendation,
    });
  }

  return out;
}

/**
 * Single-tool findings. These are the cases where one tool is bad on its own,
 * independent of what else the server exposes.
 */
export function toolFindings(tool: ToolCapabilities, raw: McpTool): Finding[] {
  const out: Finding[] = [];
  const caps = new Set(tool.capabilities.map((c) => c.capability));

  // Shell execution reachable from a tool that does not look like a shell tool.
  if (caps.has("exec:shell")) {
    out.push({
      id: "tool/arbitrary-shell",
      severity: "critical",
      title: `\`${raw.name}\` can execute arbitrary shell commands`,
      detail:
        "The tool accepts a command string and runs it. Whatever the description promises, the actual authority granted is 'run anything the process user can run'.",
      capabilities: ["exec:shell"],
      tools: [raw.name],
      recommendation:
        "Replace the free-form command with a closed set of named operations (`enum`), or run it in a container with a read-only filesystem and no network.",
    });
  }

  // Writes that claim to be read-only.
  if (raw.annotations?.readOnlyHint === true && [...caps].some(isMutating)) {
    out.push({
      id: "tool/readonly-lie",
      severity: "critical",
      title: `\`${raw.name}\` declares \`readOnlyHint\` but can mutate`,
      detail: `Capabilities detected: ${[...caps].filter(isMutating).join(", ")}. A false read-only hint lets clients skip confirmation and run the tool in parallel.`,
      capabilities: [...caps].filter(isMutating),
      tools: [raw.name],
      recommendation: "Remove `readOnlyHint`, or fix the tool so it genuinely cannot mutate.",
    });
  }

  // Destructive without confirmation hint. Only true deletion counts --
  // overwriting a file is a write, and conflating the two makes the finding
  // fire on every write tool, which trains users to ignore it.
  if (caps.has("fs:delete") && raw.annotations?.destructiveHint !== true) {
    out.push({
      id: "tool/undeclared-destructive",
      severity: "high",
      title: `\`${raw.name}\` deletes data without \`destructiveHint\``,
      detail:
        "Clients rely on `destructiveHint` to gate a tool behind a confirmation prompt. Without it the deletion can be auto-approved.",
      capabilities: ["fs:delete"],
      tools: [raw.name],
      recommendation: "Set `annotations.destructiveHint: true`.",
    });
  }

  // A network tool that does not declare it leaves the machine.
  if ([...caps].some(isNetworked) && raw.annotations?.openWorldHint !== true) {
    out.push({
      id: "tool/undeclared-egress",
      severity: "medium",
      title: `\`${raw.name}\` reaches the network without \`openWorldHint\``,
      detail: "Undisclosed egress is what makes data-exfiltration review impossible for the client.",
      capabilities: [...caps].filter(isNetworked),
      tools: [raw.name],
      recommendation: "Set `annotations.openWorldHint: true`.",
    });
  }

  return out;
}
