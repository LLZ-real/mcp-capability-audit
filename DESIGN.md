# Design notes

The decisions that were not obvious, and the ones that were wrong first.

---

## 1. Why audit combinations instead of tools

The original plan was a per-tool risk score: look at each tool, decide how dangerous it is, sum it up. That is how most security scanners work and it is wrong here.

Consider a server with `read_file` and `fetch_url`. Per-tool analysis gives two low-risk tools and a low-risk server. But an agent with both can read `~/.ssh/id_rsa` and POST it to `attacker.example`. The vulnerability is not in either tool — it is in their coexistence, and it only exists because an LLM is choosing the sequence.

So the unit of analysis is the **server**, and the primitive is the **capability set**. A tool is only interesting for which capabilities it contributes.

This also determines what "fixed" means. You cannot fix an exfiltration channel by improving either tool; you have to remove one half. That is exactly what the policy generator does.

---

## 2. Risk is max-tool plus a combination premium, not a mean

The first scoring model averaged tool risks. A server with twenty readers and one shell tool scored "low". That is backwards: the shell tool *is* the story, and the readers are irrelevant.

Current model:

```
risk = min(100, max(tool risks) + min(30, Σ severity premium for combo findings))
```

- **max**, because one dangerous tool dominates.
- **bounded premium**, because a server with many combinations is worse than the max tool alone, but rule count should not be able to push every server to 100.
- The premium is capped at 30 so a single critical combination moves the needle (75 → 78 in the ops fixture) without swamping the tool-level signal.

The number is a **ranking heuristic**, not a measurement. It orders servers against each other. It does not predict what an attacker achieves, and the README says so.

---

## 3. The extraction pipeline, and the four false-positive classes it had to fix

Extraction combines three weak signals with fixed weights (name 0.5, prose 0.35, schema 0.15). Confidence is their sum, and every hit records its evidence.

The first working version scored a clean read-only filesystem server at risk 8 — correct — but produced **five fabricated findings** on realistic servers. Each was a class of error:

### 3.1 `write_file` looked like a file reader

The tool takes `path`, and `path` is a schema signal for `fs:read`. Schema weight is only 0.15, but it was enough to cross the "capability present" line on its own.

**Fix:** schema signals now only *corroborate* — they add weight only when name or prose already established the capability. A param called `path` proves the tool takes a path; it proves nothing about what it does with it. `write_file` and `delete_path` take the same param.

### 3.2 "Write a string to a file" → `fs:read`

The prose contains `file`, which was a prose signal for `fs:read`. Nothing was being read.

**Fix:** action-word gate. Each filesystem/database/network capability requires an explicit *action* word (`read`, `write`, `delete`, `fetch`) in the name or prose. Object words (`file`, `path`, `table`) corroborate but never establish.

### 3.3 `fetch_url` → `fs:read`

Its description says it returns the "body". `contents`/`body`-ish words were treated as file reads.

**Fix:** remote-context guard. If the tool's target is clearly remote (`url`, `http`, `endpoint`), local capabilities are suppressed. An HTTP response body is not a file.

### 3.4 `read_env` and `read_secret` → `fs:read`

Both share the verb `read` with `read_file`.

**Fix:** two more context guards — env-targeted tools are not filesystem tools, and secret-targeted tools are not either. `read_secret` → `secrets:read` only.

Each guard has a test that pins it, and the benchmark's false-positive budget (2) exists specifically to stop these from creeping back.

---

## 4. `env:read` is not `secrets:read`

This was the hardest judgement call, and the benchmark initially disagreed with me.

`read_env` can read `AWS_SECRET_ACCESS_KEY`. So should it be `secrets:read`?

**No**, and the reason is precision:

- `read_env` reads *one named variable on request*. It cannot enumerate.
- If `env:read` implies `secrets:read`, then every config-reading tool pairs with `net:out` to produce a critical "credential exposure" finding.
- On a realistic server that is most servers. A finding that fires everywhere is a finding nobody reads.

`secrets:read` is reserved for tools that target a secret store *by name* — `read_secret`, `get_credential`, vault access. Those are specific enough that when they pair with egress, the alarm is worth raising.

This is a precision/recall trade made in the direction of precision. The design rule: **the auditor must stay quiet often enough to be believed.**

---

## 5. Ambiguous SQL is scored as the worse reading

`run_query` taking a raw `sql` param could be a SELECT or a `DROP TABLE`. The description rarely says which.

The tool scores it `db:write`. Deliberate, and worth stating because it is a false positive for genuinely read-only query tools.

The reasoning: for a security tool, the cost of a false negative (saying "safe" about a DDL-capable tool) is much higher than the cost of a false positive (asking you to confirm a read-only query tool). It backs off when the evidence is explicit — `run_select_query`, or a description containing "read-only" / "select" — scores `db:read`.

---

## 6. The policy denies the *effect*, not the *input*

For each critical combination, `pickDenyTarget` chooses which half to block:

| Combination | Denied | Why that half |
|---|---|---|
| read + egress | `net:out` | egress is the exfiltration path |
| secrets + egress | `net:out` | same |
| egress + shell | `exec:shell` | shell is the sharper edge |
| cloud + egress | `cloud:control` | the cloud credential is the blast radius |
| shell + write | `exec:shell` | without the shell, a written file is inert |
| db read + write | `db:write` | reads stay useful |

The general rule: deny the capability whose removal leaves the server still useful. Blocking `net:out` on a fetch server breaks it; blocking the shell on an ops server leaves deploy and fetch working.

Deny always overrides allow, so a server advertising `net:out` becomes unreachable for that capability while everything else keeps running. That is the point of a policy file rather than a warning.

---

## 7. Fixtures carry ground truth, because "looks plausible" is not a standard

Every fixture declares what the correct answer is — capabilities that must be detected, capabilities that must *not* be, findings that must and must not fire, and an expected risk band. The benchmark fails on any false negative.

This is what makes the tool defensible. A security scanner that emits convincing prose is easy to write and impossible to trust. The ground-truth file is the contract.

Two calibrations happened because of it, both in the *expectations* rather than the code, and both documented above:

- `env:read` ≠ `secrets:read` (§4)
- the ops fixture risk band was set to [70, 100] after observing 75, so a scoring change that silently halves it fails CI

Changing an expectation to match the code is normally a smell. Here it was correct twice, because the expectation encoded a *judgement* that turned out to be too aggressive — and the judgement, not the code, was what needed fixing.

---

## What is not proven

- **Extraction is lexical.** It reads declarations, not behaviour. A tool called `sync` that shells out internally is invisible. The honest fix is dynamic analysis (sandbox + syscall/network observation), which is not in this repo.
- **The combination rules are a curated list of eight.** They cover the pairs that show up in real incident reports and in the OWASP agentic-threat material. They are not a systematic enumeration of all capability interactions.
- **The risk score is not calibrated against exploits.** No exploit was executed. The number ranks servers; it does not estimate loss.
- **No false-negative test for the `sync` case.** The benchmark only proves the auditor is right about servers whose behaviour is visible in their declarations.

The next experiment worth running: take ten real published MCP servers, audit them, and compare the findings against a manual review by someone who knows each server. That measures the thing this repo cannot measure about itself.
