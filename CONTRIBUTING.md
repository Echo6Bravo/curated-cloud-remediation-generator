# Contributing

Thanks for considering a contribution. The bar here is deliberately specific, because this tool
emits commands that people run against production cloud accounts.

## Where code goes

The package is split so that adding a cloud cannot change what an existing cloud emits:

| Path | Holds | Rule |
| --- | --- | --- |
| `src/remgen/core/` | The shared pipeline — findings loading, dedupe, safety gating, layout, HCL rendering, the CLI. | **Must not import from `providers`.** Anything cloud-specific it needs arrives through `core/provider.py`. |
| `src/remgen/providers/aws/` | AWS recipes, the shell-script generator, the service-model verifier, and the `Provider` descriptor wiring them together. | Must not import another provider. Shared code goes in `core`, where both clouds' tests cover it. |

`tests/test_structure.py` enforces both rules by parsing imports from the AST, so a lazy import
inside a function body cannot satisfy them while breaking them. If a change needs `core` to know
something about a cloud, add a field to `Provider` rather than an import — a failure there names the
import to invert.

Each cloud gets its own console command (`awsremgen`) rather than a `--cloud` flag. See
[One command per cloud](./README.md#one-command-per-cloud) for why; the short version is that the
cloud selects the recipe set, the API verifier and the identity preflight together, so it should not
be a value a typo can change.

## The one rule that matters most

**A recipe is not a mapping exercise.** Adding coverage is the most requested change and the
easiest one to do badly. A recipe that "looks right" and emits a command that fails — or worse,
succeeds in a way the user did not intend — is worse than no recipe at all, because the user
trusted it.

## Adding a recipe

Every field must be verified against a primary source, not inferred from a similar recipe:

1. **Policy UUID** from the live Tenable Cloud Security catalog. Not invented, not guessed.
2. **API call and parameters** confirmed against the AWS service model (`service-2.json`) —
   the same source `awsremgen verify` reads. Confirm the operation name and every parameter's shape.
3. **HCL resource type and attribute** confirmed against the current provider documentation.
4. **Reversal command**, actually run, or an explicit `reversible=False` with the reason.
5. **Safety classification** — and be honest about it. Ask specifically: is it reversible? does it
   touch the data path? does it require a restart or replacement? does it add usage-scaled cost?
   does it interfere with `terraform destroy` / `tofu destroy`? Each of those has a field.
6. **Safety notes and caveats** written for someone who will read them at 2am during an incident.

Then prove it end to end:

- `awsremgen verify` passes for the new recipe.
- Generated HCL passes **real** `tofu init` / `validate` / `fmt -check` — in its own workspace, per
  file. A substring assertion is not proof; real parsers reject artifacts that substring checks
  accept.
- The generated shell script's identity preflight is exercised: it must exit non-zero and run
  **zero** commands when pointed at the wrong account.
- Tests cover the new recipe at the smallest input size where a bug could appear (two items, two
  accounts, two regions), not just a single happy-path finding.

A new recipe changes the shipped output, so it also changes the committed sample. Regenerate it in
the same commit — CI diffs `examples/sample-output/` against a fresh run and fails on drift:

```bash
awsremgen generate --findings examples/findings.sample.json --out ./artifacts \
  --safety-level caution -v > examples/sample-run.txt 2>&1
rm -rf examples/sample-output && mkdir examples/sample-output
cp -R ./artifacts/. examples/sample-output/    # -R: artifacts are under a per-cloud directory
```

Run it from the repo root with `./artifacts` as the output, because the console transcript quotes the
output path verbatim and CI normalizes only the timestamp.

If your recipe covers a policy worth demonstrating, add a finding for it to
`examples/findings.sample.json` rather than leaving the sample silent about it. Keep the four
deliberately-bad records — they are what makes the sample show rejection and reconciliation instead
of only the happy path.

**Do not weaken an existing safety assertion to make a new recipe pass.** If a new recipe trips a
safety check, the check is usually right. Replace a blanket ban with an exact allowlist that stays
accounted for, rather than loosening the pattern.

## Fixture hygiene

Generate test axes independently. Deriving them from one loop counter (`account = i % 40`,
`region = i % 4`) silently couples them, so combination-dependent behavior is never exercised and
any measurement taken on those fixtures flatters the code. This has already caused one bad
measurement in this project's history.

## Gates

All of these must pass, and all of them run in CI as blocking checks:

```bash
pip install -e '.[dev]'
pytest                  # full suite, no -k narrowing
ruff check .
ruff format --check .   # or `ruff format .` to fix
bandit -q -r src/
```

`ruff format` is the autoformatter and `ruff check` is the linter — same binary, different tools, and
CI runs both. Formatting is therefore mechanical: do not spend review comments on it, and do not
hand-format against it. It provably does not change generated output, so reformatting a generator is
safe.

The OpenTofu-backed tests run a real binary, so the suite takes ~30s rather than a few seconds. That
is already the fast path: one warmed workspace is shared for the session, because a fully warm `tofu
init` still costs 16.7s per workspace while `validate` costs 2.0s. Do not skip these tests locally
and do not narrow the suite to the ones you expect to be affected — the ones you did not expect to be
affected are the point.

The first run downloads the AWS provider (~663 MB) into `~/.cache/remgen-test-tofu-plugins`, and
later runs reuse it. `REMGEN_TEST_TOFU_CACHE` moves it. If you are offline and `init` cannot reach
the registry, the tests **fail** rather than skip — a skip would report green having validated
nothing. `REMGEN_ALLOW_TOFU_INIT_FAILURE=1` opts into skipping, deliberately, for that case only.

### Adding a recipe

`tests/test_recipe_set.py` holds the invariants a new entry has to satisfy, and each one states what
breaks if it does not. Read the failure message before working around it: two recipes on one HCL
resource type, for example, is currently a real defect that `tofu validate` reports as **valid**.

When adding an invariant there, check that it constrains an *authored* field. `safety_tier` and
`safety_notes` are computed properties, so an assertion about them re-implements the derivation and
passes unconditionally — three of the original invariants did exactly that and had to be rewritten.
Prove a new one fails by mutating the recipe set to violate it.

## Scope

Some omissions are deliberate design decisions, not gaps. Before proposing one, read
[ROADMAP.md](./ROADMAP.md): no boto3 generator, no live API adapter, no shared shell-script skeleton,
no provider plugin discovery, and the unresolved question of how to gate non-reversible remediations.
If you want to change one of those, argue the tradeoff rather than just supplying the code.

**A second cloud is in scope, but it is the AWS work again, not a parameterization of it.** The
structure exists (`core` is cloud-neutral, output splits by cloud), and that is the easy part. A new
cloud needs its own verified recipe set, its own safety classification per remediation, its own IaC
mapping, and its own source of API definitions to verify against. A provider descriptor with no
verified recipes is a directory, not support — do not add one to claim coverage.

## Commits

Explain **why**, not just what. A commit that says "add S3 recipe" is less useful in six months
than one that records which source confirmed the parameter shape and why the safety tier is what
it is.

Do not add model or AI attribution trailers to commits.

## Reporting security issues

See [SECURITY.md](./SECURITY.md) — do not open a public issue for a security problem.
