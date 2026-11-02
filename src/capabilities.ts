/**
 * Capability extraction.
 *
 * The hard problem: a tool's declared schema says almost nothing about what
 * it actually does. `run_query` could be a SELECT or a DROP TABLE. So we
 * combine three weak signals and let their agreement raise confidence:
 *
 *   1. NAME      — verb/noun in the identifier        (weight 0.5)
 *   2. PROSE     — the description text               (weight 0.35)
 *   3. SCHEMA    — param names and enums              (weight 0.15)
 *
 * Every hit records the signal that produced it, so a human can audit the
 * auditor. An unexplained capability claim is worthless in a security tool.
 */

import type { Capability, CapabilityHit, JSONSchema, McpTool } from "./types.ts";

/** Split readFile / read_file / read-file / ReadFile into lowercase words. */
export function words(s: string): string[] {
  return s
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[\s_\-.]+/)
    .map((w) => w.toLowerCase())
    .filter(Boolean);
}

/**
 * Signal lexicons.
 *
 * Each entry maps capability -> words that suggest it. Words are matched
 * against the *word list* of name and description, never as substrings:
 * "metadata" must not match "data", "display" must not match "play".
 */
const NAME_SIGNALS: Record<Capability, string[]> = {
  "fs:read": ["read", "load", "cat", "open", "view", "show", "get", "fetch", "list", "ls", "dir", "glob", "stat", "inspect"],
  "fs:write": ["write", "save", "create", "append", "put", "mkdir", "touch", "upload", "copy", "move", "rename", "edit", "patch", "insert"],
  // Deletion needs an explicit destructive verb. `write` must NOT imply it:
  // overwriting a file and deleting a tree are different risks.
  "fs:delete": ["delete", "remove", "rm", "unlink", "drop", "purge", "truncate", "wipe", "erase", "clear", "prune", "rmdir", "destroy"],
  "net:out": ["fetch", "http", "request", "curl", "download", "post", "send", "upload", "webhook", "notify", "browse", "crawl", "scrape", "api", "web"],
  "net:listen": ["listen", "serve", "bind", "accept", "socket"],
  "exec:shell": ["exec", "shell", "bash", "sh", "zsh", "cmd", "powershell", "spawn", "system", "run", "command", "terminal", "subprocess"],
  "exec:code": ["eval", "evaluate", "interpret", "script", "compile", "execute"],
  // `search` alone is not a database signal: search_files searches the disk.
  // `table`/`tables` are: `list_tables` and `describe_table` are database
  // introspection in their own right (the db:read action gate keeps DDL
  // names like `drop_table` from leaking in).
  "db:read": ["query", "select", "lookup", "sql", "db", "database", "table", "tables"],
  "db:write": ["insert", "update", "upsert", "delete", "drop", "alter", "create", "truncate", "migrate", "commit"],
  // Reading one named env var is env:read. `secrets:read` is reserved for
  // tools that specifically target a secret store; conflating the two made
  // every config-reading tool look like a credential leak.
  "secrets:read": ["secret", "token", "credential", "password", "apikey", "auth", "vault"],
  // "service" is far too common in ops tools ("deploy a service") to imply
  // process spawning; spawning needs a verb about starting a process.
  "proc:spawn": ["spawn", "fork", "daemon", "worker", "pid"],
  "env:read": ["env", "environment", "getenv", "config", "setting"],
  "env:write": ["setenv", "export", "configure", "set"],
  "cloud:control": ["aws", "gcp", "azure", "s3", "ec2", "lambda", "bucket", "instance", "deploy", "provision", "terraform", "k8s", "kubernetes", "pod", "cluster"],
  "browser:control": ["browser", "navigate", "click", "type", "scroll", "page", "screenshot", "puppeteer", "playwright", "selenium"],
  clipboard: ["clipboard", "copy", "paste", "yank"],
  notification: ["notify", "notification", "alert", "email", "sms", "slack", "message", "push"],
  unknown: [],
};

/** Prose signals are broader: descriptions talk about effects in plain English. */
const PROSE_SIGNALS: Record<Capability, string[]> = {
  "fs:read": ["read", "reads", "load", "loads", "contents", "file", "files", "directory", "disk", "path", "lines", "parse"],
  "fs:write": ["write", "writes", "save", "saves", "create", "creates", "append", "appends", "overwrite", "modify", "modifies", "persist", "store", "stores"],
  // "overwrite" is a write, not a delete. Deletion needs explicit language.
  "fs:delete": ["delete", "deletes", "remove", "removes", "erase", "purge", "destroy", "permanently", "unrecoverable", "drop", "drops"],
  "net:out": ["http", "https", "url", "request", "requests", "network", "internet", "remote", "endpoint", "download", "upload", "webhook", "api", "web"],
  // "server" is deliberately NOT a signal: "ping the remote server" and
  // "check the deployment server" are not listeners. Listening needs a verb
  // or socket-shaped word.
  "net:listen": ["listen", "listens", "listening", "serve", "serves", "port", "socket", "bind", "daemon"],
  "exec:shell": ["shell", "command", "commands", "bash", "powershell", "terminal", "subprocess", "execute", "executes", "runs"],
  "exec:code": ["evaluate", "expression", "script", "interpreter", "compiles", "eval"],
  // A database is only a database if the prose says so.
  "db:read": ["query", "queries", "select", "rows", "records", "database", "table", "tables", "sql"],
  "db:write": ["insert", "inserts", "update", "updates", "upsert", "upserts", "delete", "deletes", "rows affected", "commit", "transaction", "migrate", "alter", "drop", "drops", "create", "creates", "truncate", "truncates"],
  "secrets:read": ["secret", "secrets", "token", "tokens", "credential", "credentials", "password", "api key", "private key", "vault"],
  "proc:spawn": ["process", "daemon", "background", "worker", "service"],
  "env:read": ["environment variable", "env var", "configuration", "config"],
  "env:write": ["sets the environment", "export", "configure"],
  "cloud:control": ["aws", "gcp", "azure", "s3", "ec2", "bucket", "instance", "deploy", "provision", "kubernetes", "cluster"],
  "browser:control": ["browser", "navigate", "clicks", "screenshot", "renders the page", "dom"],
  clipboard: ["clipboard"],
  notification: ["notification", "alert", "email", "sms", "slack", "message", "notify"],
  unknown: [],
};

/** Param-level signals: a param named `sql` implies a database capability. */
const SCHEMA_SIGNALS: Record<Capability, string[]> = {
  "fs:read": ["path", "file", "filename", "dir", "directory", "glob", "pattern"],
  "fs:write": ["content", "contents", "body", "data", "text", "bytes"],
  "fs:delete": ["path", "file", "recursive", "force"],
  "net:out": ["url", "uri", "endpoint", "host", "headers", "method", "webhook", "token"],
  "net:listen": ["port", "bind", "host"],
  "exec:shell": ["command", "cmd", "script", "args", "shell"],
  "exec:code": ["code", "expression", "source", "script"],
  "db:read": ["sql", "query", "table", "where", "columns"],
  "db:write": ["sql", "statement", "values", "rows", "params"],
  "secrets:read": ["key", "token", "secret", "credential", "password"],
  "proc:spawn": ["command", "args", "executable", "binary", "pid"],
  "env:read": ["name", "key", "var"],
  "env:write": ["name", "value", "var"],
  "cloud:control": ["region", "bucket", "instance", "cluster", "namespace", "resource"],
  "browser:control": ["selector", "url", "xpath", "text"],
  clipboard: [],
  notification: ["message", "body", "to", "subject"],
  unknown: [],
};

const WEIGHTS = { name: 0.5, prose: 0.35, schema: 0.15 } as const;

/**
 * The signal table, exposed so `mcp-capability-audit capabilities` can show
 * exactly what words trigger each claim. A capability detector whose trigger
 * words are hidden cannot be audited.
 */
export const CAPABILITY_SIGNALS: Record<Capability, { name: string[]; prose: string[]; schema: string[] }> =
  Object.fromEntries(
    (Object.keys(NAME_SIGNALS) as Capability[]).map((cap) => [
      cap,
      { name: NAME_SIGNALS[cap], prose: PROSE_SIGNALS[cap], schema: SCHEMA_SIGNALS[cap] },
    ]),
  ) as Record<Capability, { name: string[]; prose: string[]; schema: string[] }>;

/**
 * A local-only capability should not be inferred from a tool whose target is
 * clearly remote. `fetch_url` returns a "body" over HTTP; that body is not a
 * file on disk.
 */
const REMOTE_CONTEXT = new Set([
  "url", "uri", "http", "https", "endpoint", "web", "api", "remote",
  "request", "response", "host", "webhook", "server",
]);

const LOCAL_CAPS: ReadonlySet<Capability> = new Set<Capability>(["fs:read", "fs:write", "fs:delete", "env:read", "env:write"]);

/**
 * Exception to the remote-context guard: a local-file *transfer* reads a
 * local file in order to send it. `upload_file` is exactly the read half of
 * an exfiltration channel, and suppressing its `fs:read` because the
 * destination is remote would blind the audit to the one thing it exists to
 * catch. Detected by a transfer verb plus a local object word.
 */
const TRANSFER_VERBS = new Set(["upload", "uploads", "send", "sends", "publish", "publishes"]);
const LOCAL_OBJECTS = new Set(["file", "files", "path", "paths", "directory", "dir", "folder", "folders", "disk"]);

function isLocalFileTransfer(tool: McpTool): boolean {
  const w = [...words(tool.name), ...words(tool.description ?? "")];
  return w.some((x) => TRANSFER_VERBS.has(x)) && w.some((x) => LOCAL_OBJECTS.has(x));
}

/**
 * A tool that targets environment variables is not touching the filesystem,
 * even though it "reads" something. Without this guard every `read_env` /
 * `get_config` tool looks like a file reader, which then fabricates an
 * exfiltration combination with any network tool on the server.
 */
function isEnvContext(tool: McpTool): boolean {
  const w = [...words(tool.name), ...words(tool.description ?? "")];
  return w.some((x) => x === "env" || x === "environment" || x === "getenv" || x === "variable");
}

const FS_CAPS: ReadonlySet<Capability> = new Set<Capability>(["fs:read", "fs:write", "fs:delete"]);

/**
 * A tool whose object is a secret is not a filesystem tool, even though the
 * verb is "read". `read_secret` and `read_file` share a verb and nothing else.
 */
const SECRET_OBJECTS = new Set([
  "secret", "secrets", "token", "tokens", "credential", "credentials",
  "password", "passwords", "apikey", "vault",
]);

function isSecretTargeted(tool: McpTool): boolean {
  const w = [...words(tool.name), ...words(tool.description ?? "")];
  return w.some((x) => SECRET_OBJECTS.has(x));
}

/**
 * A tool whose object is a database is not a filesystem tool, and vice versa:
 * `drop_table` deletes a table, `delete_file` deletes a file. The verb can be
 * identical — the object decides which domain the capability belongs to.
 */
const DB_OBJECTS = new Set([
  "table", "tables", "query", "queries", "sql", "statement", "statements",
  "database", "databases", "row", "rows", "record", "records", "db",
]);

function isDbContext(tool: McpTool): boolean {
  const w = [
    ...words(tool.name),
    ...words(tool.description ?? ""),
    ...Object.keys(tool.inputSchema?.properties ?? {}).flatMap(words),
  ];
  return w.some((x) => DB_OBJECTS.has(x));
}

/**
 * Mutation verbs that turn an env-targeted tool into an `env:write` and away
 * from `env:read`: `set_env` reads nothing, `unset_env` writes state.
 * Name-only, so a description like "does not update anything" cannot trip it.
 */
const ENV_MUTATION_VERBS = new Set([
  "set", "setenv", "unset", "unsetenv", "put", "write", "overwrite",
  "delete", "remove", "clear", "update", "export",
]);

function nameHasEnvMutationVerb(tool: McpTool): boolean {
  return words(tool.name).some((x) => ENV_MUTATION_VERBS.has(x));
}

/**
 * Deletion-style destruction: real deletion (`fs:delete`), or a database
 * write whose verb drops data (`drop_table`, `truncate_logs`). Raw-SQL tools
 * are `db:write` by the assume-worst rule but are not *called* destructive —
 * over-reporting destruction trains users to ignore it.
 */
const DESTRUCTIVE_DB_VERBS = new Set([
  "delete", "deletes", "drop", "drops", "truncate", "truncates",
  "purge", "purges", "destroy", "destroys", "wipe", "wipes",
]);

export function looksDestructive(raw: McpTool, caps: Capability[]): boolean {
  if (caps.includes("fs:delete")) return true;
  if (!caps.includes("db:write")) return false;
  const w = [...words(raw.name), ...words(raw.description ?? "")];
  return w.some((x) => DESTRUCTIVE_DB_VERBS.has(x));
}

function isRemoteContext(tool: McpTool): boolean {
  const w = [...words(tool.name), ...words(tool.description ?? "")];
  return w.some((x) => REMOTE_CONTEXT.has(x));
}

/**
 * Does the prose explicitly deny a capability?
 * "does not write to disk" must not be read as a write capability.
 */
function proseDenies(tool: McpTool, capability: Capability): boolean {
  const d = (tool.description ?? "").toLowerCase();
  const verb: Partial<Record<Capability, string>> = {
    "fs:write": "writ",
    "fs:delete": "delet",
    "net:out": "network",
    "exec:shell": "execut",
  };
  const v = verb[capability];
  if (!v) return false;
  return new RegExp(`\\b(does not|never|no|without)\\s+\\w*\\s*${v}`).test(d);
}

/**
 * Capabilities that require an explicit *action* word, not just an object.
 *
 * "Write a string to a file" contains `file`, but nothing is being read.
 * Without this split, every filesystem tool looks like a reader.
 */
const ACTION_WORDS: Partial<Record<Capability, string[]>> = {
  "fs:read": ["read", "reads", "load", "loads", "cat", "open", "parse", "inspect", "list", "stat", "upload", "uploads", "send", "sends", "publish", "publishes"],
  "fs:write": ["write", "writes", "save", "saves", "create", "creates", "append", "appends", "overwrite", "modify", "modifies", "store", "stores", "persist"],
  "fs:delete": ["delete", "deletes", "remove", "removes", "erase", "purge", "destroy", "drop", "drops", "truncate", "wipe"],
  "net:out": ["fetch", "request", "requests", "download", "upload", "post", "send", "crawl", "scrape", "browse", "connect"],
  // Shell execution needs a shell-shaped word. `run` alone is not one:
  // `run_query`, `run_report` and `run_search` run things that are not
  // commands, and calling them "arbitrary shell" is a fabricated critical.
  "exec:shell": ["shell", "command", "commands", "bash", "zsh", "powershell", "terminal", "subprocess", "exec", "cmd", "sh"],
  "db:read": ["query", "queries", "select", "lookup", "search", "list", "lists", "describe", "describes", "show", "shows", "inspect", "inspects", "count", "counts"],
  "db:write": ["insert", "inserts", "update", "updates", "upsert", "upserts", "delete", "deletes", "commit", "migrate", "migrates", "alter", "alters", "truncate", "truncates", "create", "creates", "drop", "drops"],
};

/**
 * Does the tool have an action word for this capability in its name or prose?
 * Object words (`file`, `path`, `table`) corroborate but never establish.
 */
function hasActionWord(tool: McpTool, capability: Capability): boolean {
  const action = ACTION_WORDS[capability];
  if (!action) return true; // no action gate for this capability
  const w = [...words(tool.name), ...words(tool.description ?? "")];
  return w.some((x) => action.includes(x));
}

function hitsFor(tool: McpTool, capability: Capability): CapabilityHit[] {
  const out: CapabilityHit[] = [];
  const nameWords = words(tool.name);
  const proseWords = words(tool.description ?? "");
  const desc = (tool.description ?? "").toLowerCase();
  const paramWords = Object.keys(tool.inputSchema?.properties ?? {}).flatMap(words);

  const nameMatches = NAME_SIGNALS[capability].filter((w) => nameWords.includes(w));
  const proseMatches = PROSE_SIGNALS[capability].filter(
    (w) => (w.includes(" ") ? desc.includes(w) : proseWords.includes(w)),
  );
  const schemaMatches = SCHEMA_SIGNALS[capability].filter((w) => paramWords.includes(w));

  let confidence = 0;
  const evidenceParts: string[] = [];
  if (nameMatches.length > 0) {
    confidence += WEIGHTS.name;
    evidenceParts.push(`name has ${nameMatches.map((m) => `\`${m}\``).join(", ")}`);
  }
  if (proseMatches.length > 0) {
    confidence += WEIGHTS.prose;
    evidenceParts.push(`description mentions ${proseMatches.slice(0, 3).map((m) => `"${m}"`).join(", ")}`);
  }
  // Schema signals only corroborate an effect that the name or prose already
  // established. A param called `path` proves the tool takes a path; it does
  // NOT prove the tool reads that path -- `write_file` and `delete_path` take
  // the same param and do something else entirely.
  if (schemaMatches.length > 0 && confidence > 0) {
    confidence += WEIGHTS.schema;
    evidenceParts.push(`params include ${schemaMatches.slice(0, 3).map((m) => `\`${m}\``).join(", ")}`);
  }

  if (confidence === 0) return out;

  // Object words alone are not an effect: "write a string to a file" mentions
  // `file` without reading anything. Require the action word too.
  if (!hasActionWord(tool, capability)) return out;

  out.push({
    capability,
    tool: tool.name,
    evidence: evidenceParts.join("; "),
    confidence: Math.round(confidence * 100) / 100,
  });
  return out;
}

/**
 * Extraction is deliberately blind to `annotations`. Per the MCP 2025-06 spec
 * all ToolAnnotations are hints that "are not guaranteed to provide a faithful
 * description of tool behavior" — "Clients should never make tool use
 * decisions based on ToolAnnotations received from untrusted servers" — so a
 * self-declared `readOnlyHint` must never erase a capability the text evidence
 * supports: that would let a lying annotation delete the evidence of its own
 * lie. Contradicting hints are surfaced as findings in `composition.ts`
 * instead of muting extraction.
 *
 * Does the description explicitly say it only reads?
 */
function proseReadOnly(tool: McpTool): boolean {
  const d = (tool.description ?? "").toLowerCase();
  return /\bread[- ]only\b|\bdoes not (modify|write|change)\b|\bnever (writes|modifies)\b|\bonly reads\b/.test(d);
}

/**
 * Extract capabilities for one tool.
 *
 * @param assumeWorst When true (default), a tool that could plausibly write
 *   is treated as writing. Security review should not depend on optimistic
 *   reading of ambiguous prose.
 */
export function extractCapabilities(tool: McpTool, assumeWorst = true): CapabilityHit[] {
  const hits: CapabilityHit[] = [];

  for (const cap of Object.keys(NAME_SIGNALS) as Capability[]) {
    if (cap === "unknown") continue;
    hits.push(...hitsFor(tool, cap));
  }

  const proseReadOnlyDeclared = proseReadOnly(tool);
  const remote = isRemoteContext(tool);
  const envTargeted = isEnvContext(tool);
  const secretTargeted = isSecretTargeted(tool);
  const dbTargeted = isDbContext(tool);
  const localTransfer = isLocalFileTransfer(tool);

  const keep = hits.filter((h) => {
    // Prose that explicitly claims read-only suppresses mutating capabilities.
    if (proseReadOnlyDeclared && isMutating(h.capability)) return false;
    // A remote-targeted tool's content comes over the wire, so it is not a
    // local read — except a local-file transfer (`upload_file`), which reads a
    // local file precisely in order to send it. Losing that `fs:read` would
    // hide the read half of an exfiltration channel.
    if (remote && LOCAL_CAPS.has(h.capability) && !(h.capability === "fs:read" && localTransfer)) return false;
    // An env-targeted tool is not touching the filesystem.
    if (envTargeted && FS_CAPS.has(h.capability)) return false;
    // A secret-targeted tool is not a file tool either.
    if (secretTargeted && FS_CAPS.has(h.capability)) return false;
    // A database-targeted tool is not a filesystem tool: `drop_table` drops
    // a table, and `create_table` writes DDL, not files.
    if (dbTargeted && FS_CAPS.has(h.capability)) return false;
    // Database capabilities need database context (a raw `sql`/`statement`
    // param counts and is handled by detectGenericEffectParam below):
    // `delete_file` is not a database write no matter how the verb overlaps.
    if ((h.capability === "db:read" || h.capability === "db:write") && !dbTargeted) return false;
    // `set_env` / `unset_env` mutate environment state; their name says
    // "env", which must not be read as a *read* of it.
    if (h.capability === "env:read" && envTargeted && nameHasEnvMutationVerb(tool)) return false;
    // Explicit denial in the prose wins over weak lexical evidence.
    if (proseDenies(tool, h.capability)) return false;
    return true;
  });

  // A tool whose name/description is a pure read verb but which takes a
  // generic `sql`/`command` param is still dangerous: the param is the effect.
  if (assumeWorst) {
    const genericEffect = detectGenericEffectParam(tool);
    if (genericEffect && !keep.some((k) => k.capability === genericEffect.capability)) {
      keep.push(genericEffect);
    }
    // An env-targeted tool whose name carries a mutation verb writes the
    // environment even when the verb is outside the env:write lexicon
    // (`unset_env`, `clear_env`, `delete_env`).
    if (envTargeted && nameHasEnvMutationVerb(tool) && !keep.some((k) => k.capability === "env:write")) {
      keep.push({
        capability: "env:write",
        tool: tool.name,
        evidence: "env-targeted tool with a mutating verb in its name",
        confidence: 0.5,
      });
    }
  }

  // Deduplicate by capability, keeping the highest-confidence evidence.
  const best = new Map<Capability, CapabilityHit>();
  for (const h of keep) {
    const cur = best.get(h.capability);
    if (!cur || h.confidence > cur.confidence) best.set(h.capability, h);
  }

  return [...best.values()].sort((a, b) => b.confidence - a.confidence);
}

/**
 * A param named `sql`, `command`, `script`, or `code` hands arbitrary power to
 * the caller. The tool's own name may be innocuous (`run`), but the param is
 * the actual attack surface.
 */
function detectGenericEffectParam(tool: McpTool): CapabilityHit | null {
  const params = Object.keys(tool.inputSchema?.properties ?? {}).map((p) => p.toLowerCase());

  if (params.some((p) => p === "sql" || p === "statement")) {
    const d = (tool.description ?? "").toLowerCase();
    const readOnly = /\bselect\b|\bread[- ]only\b/.test(d) || words(tool.name).includes("select");
    return {
      capability: readOnly ? "db:read" : "db:write",
      tool: tool.name,
      evidence: "accepts raw `sql`/`statement`, so the caller controls the effect",
      confidence: 0.9,
    };
  }

  if (params.some((p) => p === "command" || p === "cmd" || p === "script")) {
    return {
      capability: "exec:shell",
      tool: tool.name,
      evidence: "accepts a raw `command`/`script` param, so the caller controls execution",
      confidence: 0.9,
    };
  }

  if (params.some((p) => p === "code" || p === "expression" || p === "eval")) {
    return {
      capability: "exec:code",
      tool: tool.name,
      evidence: "accepts a `code`/`expression` param",
      confidence: 0.85,
    };
  }

  return null;
}

const MUTATING: ReadonlySet<Capability> = new Set<Capability>([
  "fs:write",
  "fs:delete",
  "db:write",
  "env:write",
  "exec:shell",
  "exec:code",
  "proc:spawn",
  "cloud:control",
  "browser:control",
]);

export function isMutating(cap: Capability): boolean {
  return MUTATING.has(cap);
}

const NETWORKED: ReadonlySet<Capability> = new Set<Capability>(["net:out", "net:listen", "browser:control"]);

export function isNetworked(cap: Capability): boolean {
  return NETWORKED.has(cap);
}

/** Tool-level risk from its capabilities. */
export function toolRisk(hits: CapabilityHit[]): number {
  const RISK: Partial<Record<Capability, number>> = {
    "exec:shell": 45,
    "exec:code": 40,
    "secrets:read": 35,
    "cloud:control": 35,
    "fs:delete": 30,
    "db:write": 25,
    "fs:write": 20,
    "env:write": 20,
    "proc:spawn": 25,
    "browser:control": 15,
    "net:out": 15,
    "net:listen": 10,
    "db:read": 8,
    "fs:read": 8,
    "env:read": 10,
    "clipboard": 5,
    notification: 5,
    unknown: 10,
  };
  let total = 0;
  for (const h of hits) total += (RISK[h.capability] ?? 10) * h.confidence;
  return Math.min(100, Math.round(total));
}
