import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  extractCapabilities,
  isMutating,
  isNetworked,
  toolRisk,
  words,
} from "../src/capabilities.ts";
import type { McpTool } from "../src/types.ts";

const tool = (over: Partial<McpTool> & { name: string }): McpTool => ({
  inputSchema: { type: "object", properties: {} },
  ...over,
});

const caps = (t: McpTool): string[] => extractCapabilities(t).map((h) => h.capability);

// ───────────────────────────── word splitting ─────────────────────────────

test("words splits every naming convention", () => {
  assert.deepEqual(words("read_file"), ["read", "file"]);
  assert.deepEqual(words("readFile"), ["read", "file"]);
  assert.deepEqual(words("ReadFile"), ["read", "file"]);
  assert.deepEqual(words("read-file"), ["read", "file"]);
  assert.deepEqual(words("HTTPGet"), ["http", "get"]);
});

// ───────────────────────────── extraction ─────────────────────────────

test("a plain file reader gets fs:read and nothing scary", () => {
  const t = tool({
    name: "read_text_file",
    description: "Read a UTF-8 text file from disk and return its contents as a string.",
    inputSchema: { type: "object", properties: { path: { type: "string", description: "Path." } } },
  });
  const c = caps(t);
  assert.ok(c.includes("fs:read"));
  assert.ok(!c.includes("fs:write"));
  assert.ok(!c.includes("fs:delete"));
  assert.ok(!c.includes("net:out"));
  assert.ok(!c.includes("exec:shell"));
});

test("write and delete are not conflated", () => {
  const w = tool({
    name: "write_file",
    description: "Write a string to a file, creating it if needed.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
    },
  });
  assert.ok(caps(w).includes("fs:write"));
  assert.ok(!caps(w).includes("fs:delete"), "overwriting is not deleting");

  const d = tool({
    name: "delete_path",
    description: "Permanently delete a file or directory.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(caps(d).includes("fs:delete"));
});

test("a schema param alone cannot prove a capability", () => {
  // `write_file` and `delete_path` both take `path`. If schema signals were
  // sufficient, every write tool would look like a reader.
  const w = tool({
    name: "write_file",
    description: "Write a string to a file.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
    },
  });
  assert.ok(!caps(w).includes("fs:read"));
});

test("a remote tool is not a filesystem reader", () => {
  const t = tool({
    name: "fetch_url",
    description: "Fetch a URL over HTTP and return the response body.",
    inputSchema: { type: "object", properties: { url: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("net:out"));
  assert.ok(!c.includes("fs:read"), "an HTTP body is not a file");
});

test("an env tool is not a filesystem reader", () => {
  const t = tool({
    name: "read_env",
    description: "Read an environment variable by name.",
    inputSchema: { type: "object", properties: { name: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("env:read"));
  assert.ok(!c.includes("fs:read"));
});

test("searching files is not a database read", () => {
  const t = tool({
    name: "search_files",
    description: "Search file names and contents under a directory.",
    inputSchema: { type: "object", properties: { root: { type: "string" } } },
  });
  assert.ok(!caps(t).includes("db:read"));
});

test("a generic command param grants shell even from an innocuous name", () => {
  const t = tool({
    name: "run",
    description: "Run something.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  });
  assert.ok(caps(t).includes("exec:shell"));
});

test("a raw sql param is db:write unless the tool is explicitly read-only", () => {
  const ambiguous = tool({
    name: "run_query",
    description: "Run a query.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  assert.ok(caps(ambiguous).includes("db:write"), "ambiguous SQL must assume the worse reading");

  const selectOnly = tool({
    name: "run_select_query",
    description: "Execute a read-only SELECT statement and return rows.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  assert.ok(caps(selectOnly).includes("db:read"));
  assert.ok(!caps(selectOnly).includes("db:write"));
});

test("a secret tool is not a filesystem reader", () => {
  const t = tool({
    name: "read_secret",
    description: "Read a secret from the vault by name and return its plaintext value.",
    inputSchema: { type: "object", properties: { name: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("secrets:read"));
  assert.ok(!c.includes("fs:read"), "a vault is not a filesystem");
});

test("`run` in a name is not shell without a shell-shaped word", () => {
  const query = tool({
    name: "run_query",
    description: "Run a query.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  assert.ok(!caps(query).includes("exec:shell"), "run_query runs a query, not commands");

  const report = tool({ name: "run_report", description: "Run the weekly report." });
  assert.ok(!caps(report).includes("exec:shell"));

  // ...but a genuine shell tool is still caught.
  const shell = tool({
    name: "run_command",
    description: "Run a shell command.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  });
  assert.ok(caps(shell).includes("exec:shell"));
});

test("DDL verbs are database writes, not filesystem effects", () => {
  const drop = tool({
    name: "drop_table",
    description: "Drop a table from the database.",
    inputSchema: { type: "object", properties: { table: { type: "string" } } },
  });
  assert.ok(caps(drop).includes("db:write"), "DROP TABLE is a database write");
  assert.ok(!caps(drop).includes("fs:delete"), "a table is not a file");

  const create = tool({
    name: "create_table",
    description: "Create a new table in the database.",
    inputSchema: { type: "object", properties: { table: { type: "string" } } },
  });
  assert.ok(caps(create).includes("db:write"));
  assert.ok(!caps(create).includes("fs:write"), "DDL does not write files");

  const del = tool({
    name: "delete_file",
    description: "Delete a file from disk.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(caps(del).includes("fs:delete"));
  assert.ok(!caps(del).includes("db:write"), "a file is not a database row");
});

test("a read-only SQL tool is db:read only, not a file reader", () => {
  const t = tool({
    name: "run_select_query",
    description: "Execute a read-only SELECT statement and return rows.",
    inputSchema: { type: "object", properties: { sql: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("db:read"));
  assert.ok(!c.includes("fs:read"), "'read-only' about rows is not a file read");
  assert.ok(!c.includes("db:write"));
  assert.ok(!c.includes("exec:shell"));
});

test("a remote server in prose is not a listener", () => {
  const ping = tool({
    name: "ping_server",
    description: "Ping the remote server and return latency.",
    inputSchema: { type: "object", properties: { host: { type: "string" } } },
  });
  assert.ok(!caps(ping).includes("net:listen"), "pinging a server is not listening on one");

  const status = tool({ name: "check_deployment", description: "Check the status of the deployment server." });
  assert.ok(!caps(status).includes("net:listen"));

  // ...but a genuine listener is still caught.
  const listener = tool({
    name: "start_server",
    description: "Start an HTTP server listening on a port.",
    inputSchema: { type: "object", properties: { port: { type: "number" } } },
  });
  assert.ok(caps(listener).includes("net:listen"));
});

test("database introspection verbs are db:read", () => {
  const list = tool({
    name: "list_tables",
    description: "List the tables in the database.",
    inputSchema: { type: "object", properties: { schema: { type: "string" } } },
  });
  assert.ok(caps(list).includes("db:read"));
  assert.ok(!caps(list).includes("fs:read"), "listing tables is not reading files");

  const describe = tool({ name: "describe_table", description: "Describe a table." });
  assert.ok(caps(describe).includes("db:read"));

  const show = tool({ name: "show_tables", description: "Show tables." });
  assert.ok(caps(show).includes("db:read"));
});

test("a local-file transfer keeps fs:read; a fetch does not", () => {
  const upload = tool({
    name: "upload_file",
    description: "Upload a file to the remote server over HTTP.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  const c = caps(upload);
  assert.ok(c.includes("fs:read"), "uploading a file reads it first — that is the exfiltration half");
  assert.ok(c.includes("net:out"));

  const fetch = tool({
    name: "fetch_url",
    description: "Fetch a URL over HTTP and return the response body.",
    inputSchema: { type: "object", properties: { url: { type: "string" } } },
  });
  assert.ok(!caps(fetch).includes("fs:read"), "an HTTP body is not a file");
});

test("set_env writes the environment; it does not read it", () => {
  const t = tool({
    name: "set_env",
    description: "Set an environment variable.",
    inputSchema: { type: "object", properties: { name: { type: "string" }, value: { type: "string" } } },
  });
  const c = caps(t);
  assert.ok(c.includes("env:write"));
  assert.ok(!c.includes("env:read"), "`set` mutates env state; the `env` in the name is the object, not a read");
});

test("readOnlyHint is an untrusted hint and never suppresses capabilities", () => {
  const t = tool({
    name: "delete_file",
    description: "Delete a file from disk.",
    annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(
    caps(t).includes("fs:delete"),
    "a lying annotation must not erase the evidence of its own lie (MCP spec: annotations are untrusted hints)",
  );
});

test("explicit prose denial suppresses the capability", () => {
  const t = tool({
    name: "inspect_file",
    description: "Inspect a file and return its size. Does not write to disk.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  assert.ok(!caps(t).includes("fs:write"));
});

test("every capability claim carries evidence and a confidence", () => {
  const t = tool({
    name: "delete_path",
    description: "Permanently delete a file or directory.",
    inputSchema: { type: "object", properties: { path: { type: "string" } } },
  });
  for (const h of extractCapabilities(t)) {
    assert.ok(h.evidence.length > 0, `${h.capability} has no evidence`);
    assert.ok(h.confidence > 0 && h.confidence <= 1, `${h.capability} confidence out of range`);
  }
});

test("extraction is deterministic", () => {
  const t = tool({ name: "read_file", description: "Read a file from disk." });
  assert.deepEqual(caps(t), caps(t));
});

// ───────────────────────────── risk ─────────────────────────────

test("shell scores higher than reading", () => {
  const reader = tool({ name: "read_file", description: "Read a file from disk." });
  const shell = tool({ name: "run_command", description: "Run a shell command." });
  assert.ok(toolRisk(extractCapabilities(shell)) > toolRisk(extractCapabilities(reader)));
});

test("risk is bounded to 0..100", () => {
  const kitchenSink = tool({
    name: "do_everything",
    description: "Run shell commands, write files, delete files, fetch URLs, read secrets, control aws.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        sql: { type: "string" },
        url: { type: "string" },
      },
    },
  });
  const r = toolRisk(extractCapabilities(kitchenSink));
  assert.ok(r >= 0 && r <= 100, `risk out of range: ${r}`);
});

test("mutating and networked classifiers agree with the capability names", () => {
  assert.equal(isMutating("fs:write"), true);
  assert.equal(isMutating("fs:read"), false);
  assert.equal(isNetworked("net:out"), true);
  assert.equal(isNetworked("fs:read"), false);
});
