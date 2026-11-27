/**
 * Eligibility check for factory auto-merge (.github/workflows/factory-auto-merge.yml,
 * TECH-11016, ported from rh-data-platform TECH-9802). Pure function: the workflow
 * gathers PR facts and this decides.
 *
 * A PR is merged automatically ONLY if every condition holds. Anything else is
 * left alone (`action: "skip"`), left for a person with a comment
 * (`action: "hold"`), or retried on the next run (`action: "retry"`).
 *
 * Ownership needs BOTH: a `factory/` head branch AND an author that is the
 * rh-code-factory GitHub App. Everything else is never touched.
 *
 * Argus evidence: auto-approve.yml (the gate) posts an APPROVED review as
 * github-actions[bot] only after the Argus store holds an APPROVE verdict at the
 * exact head SHA and CI is green. The IAM role that reads the Argus store trusts
 * only auto-approve.yml, so this workflow cannot read the store itself and relies
 * on that approval, bound to the head SHA, instead.
 */

export const FACTORY_BOT_LOGIN = "rh-code-factory[bot]";
export const FACTORY_BRANCH_PREFIX = "factory/";
export const GATE_APPROVER_LOGIN = "github-actions[bot]";
export const BASE_BRANCH = "main";
// The four contexts of the `main branch protection` ruleset.
export const REQUIRED_CHECKS = ["Lint & type-check", "Tests", "Docker build", "All checks passed"];

// Paths a person must merge: migrations, auth and secrets, packaging, image and
// release files, anything under .github/.
export const HOLD_PATH_PATTERNS = [
  /(^|\/)(migrations?|alembic)\//i,
  /^alembic\.ini$/i,
  /(^|\/)auth([-_][^/]*|n|z|entication|orization)?\//i,
  /(^|\/)(auth|authn|authz|oauth|okta|identity|scopes?|mint_token|secrets?|tokens?|wake_secrets)[^/]*\.(py|ts|tsx|js|mjs|tf|ya?ml)$/i,
  /(^|\/)(secrets?|tokens?)\//i,
  // All of .github/: workflows and the gate scripts themselves. A factory PR must
  // never change the rules that decide whether it merges.
  /^\.github\//,
  // Image, packaging and release inputs (releases are cut by hand from main).
  /(^|\/)Dockerfile[^/]*$/i,
  /(^|\/)entrypoint\.sh$/,
  /(^|\/)docker-compose[^/]*\.ya?ml$/i,
  /(^|\/)pyproject\.toml$/,
  /(^|\/)uv\.lock$/,
];

// PRs from the infrastructure builder are always a person's to merge.
const INFRA_BRANCH = /^factory\/infrastructure([/-]|$)/i;
const INFRA_LABEL = "builder:infrastructure";

export function holdPaths(files) {
  return (files ?? []).filter((f) => HOLD_PATH_PATTERNS.some((re) => re.test(f)));
}

export function isFactoryOwned(pr, repoFullName) {
  if (!repoFullName) return false;
  const headRef = pr?.head?.ref ?? "";
  return (
    headRef.startsWith(FACTORY_BRANCH_PREFIX) &&
    pr?.user?.login === FACTORY_BOT_LOGIN &&
    pr?.user?.type === "Bot" &&
    pr?.head?.repo?.full_name === repoFullName &&
    pr?.base?.ref === BASE_BRANCH
  );
}

/**
 * Latest-per-reviewer APPROVED review at the head SHA from the gate (github-actions[bot]),
 * carrying the gate's marker for that full SHA. The marker is a tripwire, not proof: the
 * repo lets any workflow approve as github-actions[bot], so a writer could forge it. That
 * writer could already approve and merge their own PR, so this adds no new privilege.
 */
export function hasGateApprovalAtHead(reviews, headSha, authorLogin) {
  const latest = new Map();
  for (const r of reviews ?? []) {
    if (!r.user || r.state === "COMMENTED" || r.state === "PENDING") continue;
    latest.set(r.user.login, r);
  }
  const states = [...latest.values()];
  if (states.some((r) => r.state === "CHANGES_REQUESTED")) return false;
  return states.some(
    (r) =>
      r.state === "APPROVED" &&
      r.commit_id === headSha &&
      r.user.type === "Bot" &&
      r.user.login === GATE_APPROVER_LOGIN &&
      r.user.login !== authorLogin &&
      (r.body ?? "").includes(`<!-- argus-gate-approval:${headSha} -->`),
  );
}

export function checksGreen(checkRuns, required = REQUIRED_CHECKS) {
  return required.every((name) => {
    const runs = (checkRuns ?? []).filter((c) => c.name === name);
    return runs.length > 0 && runs.every((c) => c.status === "completed" && c.conclusion === "success");
  });
}

/**
 * @param {object} input
 * @param {object} input.pr          GitHub PR object (pulls.get)
 * @param {string} input.repo        "owner/name"
 * @param {string[]} input.files     changed file paths
 * @param {object[]} input.reviews   PR reviews
 * @param {object[]} input.checkRuns check runs for the head SHA
 * @param {boolean} input.disabled   global off switch (FACTORY_AUTO_MERGE_DISABLED=true)
 * @returns {{action: "merge"|"skip"|"hold"|"retry", reason: string, paths?: string[]}}
 */
export function evaluateFactoryPr({ pr, repo, files, reviews, checkRuns, disabled }) {
  if (disabled) return { action: "skip", reason: "off switch is on" };
  if (!isFactoryOwned(pr, repo)) return { action: "skip", reason: "not a factory-owned PR" };
  if (pr.state !== "open" || pr.merged) return { action: "skip", reason: "not open" };
  if (pr.draft) return { action: "skip", reason: "draft" };

  const headRef = pr.head.ref;
  const labels = (pr.labels ?? []).map((l) => l.name);
  if (INFRA_BRANCH.test(headRef) || labels.includes(INFRA_LABEL)) {
    return { action: "skip", reason: "infrastructure builder PR: a person merges" };
  }

  const held = holdPaths(files);
  if (held.length > 0) {
    return { action: "hold", reason: "touches hold-list paths", paths: held };
  }

  const sha = pr.head.sha;
  if (!checksGreen(checkRuns)) return { action: "skip", reason: "required checks not green yet" };
  if (!labels.includes("auto-approved") || !hasGateApprovalAtHead(reviews, sha, pr.user.login)) {
    return { action: "skip", reason: "no gate approval (Argus APPROVE + CI) at head SHA" };
  }

  // Merge state is computed lazily by GitHub. Unknown means retry, not skip.
  if (pr.mergeable === null || pr.mergeable === undefined || pr.mergeable_state === "unknown") {
    return { action: "retry", reason: "merge state unknown" };
  }
  if (pr.mergeable === false || pr.mergeable_state === "dirty") {
    return { action: "skip", reason: "merge conflicts" };
  }
  // Allow-list: anything but a clean state (behind, blocked, unstable, ...) is left alone.
  if (pr.mergeable_state !== "clean" && pr.mergeable_state !== "has_hooks") {
    return { action: "skip", reason: `merge state ${pr.mergeable_state}` };
  }
  return { action: "merge", reason: "all conditions hold", paths: [] };
}
