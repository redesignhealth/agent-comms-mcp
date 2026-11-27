import { test } from "node:test";
import assert from "node:assert/strict";
import {
  evaluateFactoryPr,
  holdPaths,
  hasGateApprovalAtHead,
  isFactoryOwned,
  REQUIRED_CHECKS,
} from "./factory-merge-eligibility.mjs";

const REPO = "redesignhealth/agent-comms-mcp";
const SHA = "a".repeat(40);
const OLD = "b".repeat(40);
const gate = (over = {}) => ({ user: { login: "github-actions[bot]", type: "Bot" }, state: "APPROVED", commit_id: SHA, ...over });
const green = () => REQUIRED_CHECKS.map((name) => ({ name, status: "completed", conclusion: "success" }));

function base(over = {}) {
  return {
    repo: REPO,
    pr: {
      state: "open",
      draft: false,
      merged: false,
      mergeable: true,
      mergeable_state: "clean",
      labels: [{ name: "auto-approved" }],
      user: { login: "rh-code-factory[bot]", type: "Bot" },
      head: { ref: "factory/TECH-1-thing", sha: SHA, repo: { full_name: REPO } },
      base: { ref: "main" },
      ...(over.pr ?? {}),
    },
    files: over.files ?? ["service.py", "tests/test_service.py"],
    reviews: over.reviews ?? [gate()],
    checkRuns: over.checkRuns ?? green(),
    disabled: over.disabled ?? false,
  };
}

test("merges a fully passing factory PR", () => {
  assert.equal(evaluateFactoryPr(base()).action, "merge");
});

test("off switch stops the merge", () => {
  assert.equal(evaluateFactoryPr(base({ disabled: true })).action, "skip");
});

test("person PR that passes the gate is left alone", () => {
  const r = evaluateFactoryPr(base({ pr: { user: { login: "alice", type: "User" }, head: { ref: "alice/fix", sha: SHA, repo: { full_name: REPO } } } }));
  assert.equal(r.action, "skip");
});

test("factory/ branch from a person is left alone", () => {
  assert.equal(evaluateFactoryPr(base({ pr: { user: { login: "alice", type: "User" } } })).action, "skip");
});

test("factory bot on a non-factory branch is left alone", () => {
  const r = evaluateFactoryPr(base({ pr: { head: { ref: "feat/x", sha: SHA, repo: { full_name: REPO } } } }));
  assert.equal(r.action, "skip");
});

test("lookalike bot is left alone", () => {
  assert.equal(isFactoryOwned({ ...base().pr, user: { login: "rh-code-factory-evil[bot]", type: "Bot" } }, REPO), false);
  assert.equal(isFactoryOwned({ ...base().pr, user: { login: "rh-code-factory[bot]", type: "User" } }, REPO), false);
});

test("fork PR with a factory/ branch is left alone", () => {
  const r = evaluateFactoryPr(base({ pr: { head: { ref: "factory/x", sha: SHA, repo: { full_name: "evil/fork" } } } }));
  assert.equal(r.action, "skip");
});

test("PR targeting a non-main base is left alone", () => {
  assert.equal(evaluateFactoryPr(base({ pr: { base: { ref: "dev" } } })).action, "skip");
});

test("infrastructure builder PR is left for a person", () => {
  const r = evaluateFactoryPr(base({ pr: { head: { ref: "factory/infrastructure/x", sha: SHA, repo: { full_name: REPO } } } }));
  assert.equal(r.action, "skip");
});

test("hold-list paths hold the PR with the paths listed", () => {
  const files = [
    "migrations/versions/001_x.py",
    "alembic.ini",
    "auth.py",
    "identity.py",
    "wake_secrets.py",
    "Dockerfile",
    "entrypoint.sh",
    "docker-compose.yml",
    "pyproject.toml",
    "uv.lock",
    ".github/workflows/ci.yml",
    "service.py",
  ];
  const r = evaluateFactoryPr(base({ files }));
  assert.equal(r.action, "hold");
  assert.deepEqual(r.paths, files.slice(0, -1));
  assert.deepEqual(holdPaths(["service.py", "tests/test_wake.py", "docs/x.md"]), []);
});

test("failing, missing or pending required check blocks the merge", () => {
  for (const name of REQUIRED_CHECKS) {
    const failed = green().map((c) => (c.name === name ? { ...c, conclusion: "failure" } : c));
    assert.equal(evaluateFactoryPr(base({ checkRuns: failed })).action, "skip", name);
    assert.equal(evaluateFactoryPr(base({ checkRuns: green().filter((c) => c.name !== name) })).action, "skip", name);
    const pending = green().map((c) => (c.name === name ? { ...c, status: "in_progress", conclusion: null } : c));
    assert.equal(evaluateFactoryPr(base({ checkRuns: pending })).action, "skip", name);
  }
});

test("a rerun of a check that failed after an earlier success blocks the merge", () => {
  const runs = [...green(), { name: "Tests", status: "completed", conclusion: "failure" }];
  assert.equal(evaluateFactoryPr(base({ checkRuns: runs })).action, "skip");
});

test("no approval blocks", () => {
  assert.equal(evaluateFactoryPr(base({ reviews: [] })).action, "skip");
});

test("approval on an older commit does not count", () => {
  assert.equal(evaluateFactoryPr(base({ reviews: [gate({ commit_id: OLD })] })).action, "skip");
});

test("approval from a person, another bot, or the author does not count", () => {
  assert.equal(hasGateApprovalAtHead([gate({ user: { login: "alice", type: "User" } })], SHA, "rh-code-factory[bot]"), false);
  assert.equal(hasGateApprovalAtHead([gate({ user: { login: "other-app[bot]", type: "Bot" } })], SHA, "rh-code-factory[bot]"), false);
  assert.equal(hasGateApprovalAtHead([gate({ user: { login: "rh-code-factory[bot]", type: "Bot" } })], SHA, "rh-code-factory[bot]"), false);
});

test("an outstanding changes-requested review blocks", () => {
  const reviews = [gate(), { user: { login: "alice", type: "User" }, state: "CHANGES_REQUESTED", commit_id: SHA }];
  assert.equal(evaluateFactoryPr(base({ reviews })).action, "skip");
});

test("missing auto-approved label blocks", () => {
  assert.equal(evaluateFactoryPr(base({ pr: { labels: [] } })).action, "skip");
});

test("unknown merge state is retried, not skipped", () => {
  assert.equal(evaluateFactoryPr(base({ pr: { mergeable: null, mergeable_state: "unknown" } })).action, "retry");
});

test("conflicts, draft, closed, behind and blocked are skipped", () => {
  assert.equal(evaluateFactoryPr(base({ pr: { mergeable: false, mergeable_state: "dirty" } })).action, "skip");
  assert.equal(evaluateFactoryPr(base({ pr: { draft: true } })).action, "skip");
  assert.equal(evaluateFactoryPr(base({ pr: { state: "closed" } })).action, "skip");
  assert.equal(evaluateFactoryPr(base({ pr: { mergeable_state: "behind" } })).action, "skip");
  assert.equal(evaluateFactoryPr(base({ pr: { mergeable_state: "blocked" } })).action, "skip");
});
