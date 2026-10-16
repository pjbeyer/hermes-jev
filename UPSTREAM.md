# Upstream tracking

This fork exists to evaluate and augment `DoGMaTiiC/hermes-jev`, the upstream of the
`jev-judge` plugin installed at `~/.hermes/plugins/jev-judge`. It is one of three Jev gate
implementations under evaluation on this machine; the comparison is at the bottom of this file.

## Baseline

| | |
|---|---|
| fork | https://github.com/pjbeyer/hermes-jev |
| parent | `DoGMaTiiC/hermes-jev` |
| remotes | `origin` = fork, `upstream` = parent |
| baseline commit | `5dddbeaa` (2026-09-25), `main` |
| catalog-pinned commit | `dfa109f2` (2026-09-25), 36 commits behind `main` |
| license | none declared. See "Licensing" below. |
| layout | monorepo: `plugins/jev-judge/`, `plugins/jev-skill-router/`, `contracts/`, `tools/calibration/` |
| language | Python, standard library only, no `pyproject.toml` |
| release gate | `python3 scripts/verify_release.py` against `RELEASE_MANIFEST.sha256` |

`main` is the baseline. Augmentations are separate branches rebased onto `upstream/main`,
never squashed into the baseline commit.

## The installed plugin is a third state, and it was untracked

The plugin actually running at `~/.hermes/plugins/jev-judge` matches **neither** the
catalog-pinned commit nor `main`. It is a local working state built on the pinned commit, 36
upstream commits behind, and it was not in any repository. Its content would have been lost by
reinstalling or updating the plugin.

It is preserved on `local/installed-plugin-dfa109f2`, as a single commit on the pinned base.
That branch is a recovery artifact, not a curated change series: it exists so the work survives,
not so it ships. Its delta is 5 files, +79/-32, and it is:

1. Flex gateway endpoints replacing the public ones.
2. `JevClient.last_error`, so a fail-open log line names its cause instead of "transport".
3. `provider_metadata` read in both casings. The Vercel gateway sends camelCase
   (`providerMetadata`), the Flex gateway sends snake_case (`provider_metadata`). Reading only
   camelCase made cost telemetry silently vanish, with every cost logged as null. **This is a
   real portability bug and is the one item here worth offering upstream on its own.**
4. `cron_exempt` (default true), skipping the gate inside cron runs, because an enforce-mode
   escalation there is auto-denied by `approvals.cron_mode` and hard-blocks the call.
5. The OpenRouter backend removed.

Items 1, 4 and 5 are installation-local and should not go upstream as-is. Items 2 and 3 are
general.

## Updating from upstream

```sh
git fetch upstream --prune --tags
git checkout main && git merge --ff-only upstream/main
git checkout aug/<topic> && git rebase upstream/main
python3 plugins/jev-judge/tests/test_destination.py
python3 plugins/jev-judge/tests/test_offline.py
python3 plugins/jev-judge/tests/test_offline_gate_v2.py
python3 plugins/jev-judge/tests/test_openrouter.py
```

Exercised at fork creation: `git fetch upstream --prune --tags` succeeded, `main` confirmed
`--ff-only`-able against `upstream/main`, no-op rebase reported up to date.

## Divergence inventory

| branch | base | change | upstreamable |
|---|---|---|---|
| `main` | `5dddbea` | Baseline plus this file. | No. Fork bookkeeping. |
| `local/installed-plugin-dfa109f2` | `dfa109f2` | The installed plugin's local state, preserved verbatim. | Partly: the `last_error` and `provider_metadata` items only. |
| `aug/dest-trust` | `5dddbea` | Compute the destination in code; derive `untrusted_destination`. | Yes. General, and inert by default. |

## The release manifest is stale upstream

`scripts/verify_release.py` reports 3 mismatches on **pristine `main`**, before any change from
this fork:

```
MISMATCH  plugins/jev-judge/gate.py
MISMATCH  plugins/jev-judge/jev.py
MISMATCH  plugins/jev-judge/plugin.yaml
# 7/10 íntegros
```

`jev.py` is mismatched at the baseline and this fork never touches it, so the manifest cannot
have been regenerated after the last changes to those files. The manifest is a release-integrity
gate, so a stale one means the gate currently proves nothing about the three files it covers.

This fork does **not** hand-edit the manifest, because a hand-computed hash is not evidence that
the file was reviewed. The fix is for upstream to add a generator (or a documented procedure)
and regenerate it, and this is worth reporting as an issue. `aug/dest-trust` therefore adds to
the mismatch rather than papering over it.

## Licensing

Upstream declares no license: no `LICENSE` at the repository root, no license field in
`plugins/jev-judge/plugin.yaml`, and no license statement in the README. The plugin installed
from it is therefore unlicensed code running in the pre-tool-call path.

This does not block local augmentation. It does block proposing changes upstream in the normal
way, and it is a reason for caution in depending on this implementation: without a license there
is no grant to use, modify or redistribute it. Worth raising with the maintainer directly.

## Why this fork has an update discipline

The failure this file exists to prevent is concrete and was observed on this machine: an
installed plugin 36 commits behind its upstream, holding local edits that no repository tracked,
with a release manifest that no longer verified the code it named. Three separate drifts in one
component, none of them visible from the running system.
