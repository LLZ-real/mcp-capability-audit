# mcp-capability-audit

**What can this MCP server actually do — and what could an agent do with it?**

Linters check whether tools are well-described. This asks a different question: once you grant an agent this server, what is the blast radius?

The answer is usually not any single tool. It is a **combination**.

```
$ mcp-capability-audit fixtures/ops-automation.json

  ops-automation  (fixture:worst-case)  risk  75/100  ████████░░  D

    CRIT  · tool/arbitrary-shell       `run_command` can execute arbitrary shell commands
    CRIT  ▣ combo/remote-exec          Remote code execution: network input + shell
    CRIT  ▣ combo/secrets-exfil        Credential exposure: secret access + outbound network
    CRIT  ▣ combo/cloud-blast-radius   Cloud control plane exposed to an agent
    MED   · tool/undeclared-egress     `fetch_url` reaches the network without `openWorldHint`

    capabilities
      net:out        fetch_url
      secrets:read   read_secret
      exec:shell     run_command
      cloud:control  deploy_service
```

## The core idea

`read_file` is a file reader. `fetch_url` is an HTTP client. Both are reasonable. **Together they are an exfiltration channel**, and that is a different statement than either tool's description.

No per-tool review catches this, because no single tool is wrong — the server is. So the audit works in three layers:

1. **Extract** primitive capabilities per tool (`fs:read`, `net:out`, `exec:shell`, …).
2. **Compose** them. Eight combination rules encode known-dangerous pairs, each with a written rationale.
3. **Emit a least-privilege policy** that closes the dangerous half while leaving ordinary work intact.

## Why combinations, specifically

| Combination | What it means |
|---|---|
| `fs:read` + `net:out` | Read `~/.ssh/id_rsa`, POST it anywhere |
| `net:out` + `exec:shell` | `curl \| sh`, with an agent deciding when |
| `secrets:read` + `net:out` | Ship an API key to an attacker |
| `exec:shell` + `fs:write` | Persist code, then run it |
| `db:read` + `db:write` | A SELECT-shaped injection escalates to DELETE |
| `cloud:control` + `net:out` | Blast radius is the billing account, not the machine |

Each rule states *why* it is dangerous and *what to do*, so you can disagree with a specific rule instead of the whole tool.

## Least-privilege policy

The audit's real output is a policy you can act on:

```yaml
version: 1
default: deny

allow:
  - "cloud:control"   # needed by `deploy_service`
  - "exec:shell"      # needed by `run_command`
  - "net:out"         # needed by `fetch_url`
  - "secrets:read"    # needed by `read_secret`

deny:
  - "net:out"         # closes `combo/secrets-exfil` — deny overrides allow
  - "exec:shell"      # closes `tool/arbitrary-shell`
  - "cloud:control"   # closes `combo/cloud-blast-radius`

require_confirmation:
  - "read_secret"     # implicated in a critical finding
  - "run_command"     # mutating or implicated in a high-severity finding
```

Design choice worth stating: the policy **allows what the server demonstrably needs** and then denies the specific capability half of each critical combination. Denying the whole group would break the server; denying the dangerous half makes the combination impossible while leaving ordinary reads working.

## Accuracy, measured

A security tool that produces plausible-sounding findings is worse than nothing. So the fixtures carry **ground truth** and the benchmark fails on any false negative:

```
  Ground-truth accuracy
  ────────────────────────────────────────────────────────────────
  fixture                   caps  risk  FN   FP   miss  spurious
  ────────────────────────────────────────────────────────────────
  dev-assistant.json        5     75    0    0    0     0
  filesystem-readonly.json  1     8     0    0    0     0
  ops-automation.json       4     75    0    0    0     0
  ────────────────────────────────────────────────────────────────
  capability checks: 23   false negatives: 0   false positives: 0
```

```bash
node --experimental-strip-types benchmark/run.ts
```

The two failure modes are scored separately because they are not equally bad:

- **False negative** — a real capability missed. The tool says "safe" about a server that can shell out. Hard-fails CI.
- **False positive** — a capability invented. This is what makes people turn the tool off, and what fabricates combination findings. Budget: 2.

## Usage

```bash
npx mcp-capability-audit fixtures/
npx mcp-capability-audit fixtures/ --policy            # show the policy
npx mcp-capability-audit fixtures/ --policy-out p.yaml # write it
npx mcp-capability-audit fixtures/ --verbose           # evidence for every claim
npx mcp-capability-audit fixtures/ --fail-on critical  # CI gate
npx mcp-capability-audit rules                         # the 8 combination rules
npx mcp-capability-audit capabilities                  # every capability's trigger words
```

Exit codes: `0` clean · `1` findings at/above `--fail-on` · `2` usage error.

### Library

```ts
import { auditServer, extractCapabilities } from "mcp-capability-audit";

const audit = auditServer({ server: "mine", source: "live", tools });
console.log(audit.risk, audit.grade, audit.findings);
console.log(audit.policy.deny);   // what to block
```

## How extraction works (and where it fails)

Every claim is a weighted vote of three weak signals:

| Signal | Weight | Example |
|---|---:|---|
| tool name | 0.50 | `run_command` → `exec:shell` |
| description prose | 0.35 | "execute a shell command" |
| param names | 0.15 | `{ command: string }` |

Confidence is the sum. A hit at 0.5 (name only) is weak; 0.85 (name + prose) is strong. **Every finding prints the evidence**, so you can audit the auditor:

```bash
$ mcp-capability-audit fixtures/ --verbose
  exec:shell  run_command
    run_command: name has `run`, `command`; description mentions "shell", "command"; params include `command` (0.9)
```

### Guards that prevent fabricated findings

These exist because the first version produced exactly these false positives:

| Guard | Prevents |
|---|---|
| schema signals need a name/prose signal first | `write_file` looking like a reader because it takes `path` |
| action-word gate | "write a string to a file" → `fs:read` (the word `file` is an object, not an action) |
| remote context | `fetch_url` → `fs:read` (an HTTP body is not a file) |
| env context | `read_env` → `fs:read` |
| secret context | `read_secret` → `fs:read` |
| prose denial | "does not write to disk" → `fs:write` |

### Where it falls short

- **Heuristic, not semantic.** A tool named `sync` that calls `subprocess` internally is invisible to it. It reads declarations, not implementations.
- **English-only.** The lexicons are English.
- **Assumes the worse reading for ambiguous SQL.** `run_query` taking raw `sql` is scored as `db:write`, because a SELECT-only tool and a DDL tool have very different risk and the description rarely says which. This is deliberate: an auditor that assumes the best case is not an auditor. It will be wrong for genuinely read-only query tools — that is the trade.
- **The risk number is a hand-tuned heuristic**, not a measured exploitability score. It ranks servers against each other; it does not predict what an attacker achieves.
- **No dynamic analysis.** Nothing is executed. The optional next step is a sandboxed probe that watches actual syscalls and network calls, which would catch the `sync` case above.

## Relation to mcp-tool-lint

Two tools, two questions:

| | [mcp-tool-lint](https://github.com/LLZ-real/mcp-tool-lint) | this repo |
|---|---|---|
| Question | Will the model call this tool *correctly*? | What can this server *do*? |
| Unit | one tool | the whole server |
| Catches | ambiguous names, missing types | capability combinations |
| Output | score + fixes | risk + policy |

They share the fixture format, so a server can be checked by both.

## Development

```bash
npm install
npm test          # 36 tests
npm run bench     # ground-truth accuracy
npm run build
```

## License

MIT
