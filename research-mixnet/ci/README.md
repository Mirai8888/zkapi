# Prepared GitHub Actions workflow

`research-mixnet.yml` is a reviewed workflow template for Linux/macOS race tests,
vet, checksum verification, a pinned Go vulnerability scanner, a build and a
synthetic headless smoke test. The race suite includes a bounded comparison with
separate client, relay and worker processes, plus cancellation and scorer tests.
Official actions are pinned to commit hashes and
the job token has read-only repository permissions.

It is stored here rather than activated under `.github/workflows/` because the
current GitHub OAuth credential lacks `workflow` scope. GitHub rejected that
upload, and no existing SSH identity could authenticate. Source publication is
permitted. No interactive authentication or browser was launched.

With an appropriately authorized GitHub login, activate it by copying it to
`.github/workflows/research-mixnet.yml` and committing that file. Its workflow
dispatch trigger permits a manual first run. The template has not run on GitHub;
local results and their limits are recorded in `../evidence/README.md`.
