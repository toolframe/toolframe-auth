# CI and publishing

## Local validation

Use Python 3.14.7, uv 0.12.8 and Git. From the repository root:

```sh
python3.14 scripts/ci.py
```

The sibling Git repositories must contain these commits. The script uses
`git archive` at each pin; their current checkout and uncommitted changes are
never used or modified.

| Repository | Required commit |
| --- | --- |
| `toolframe-sdk` | `a9000ab6ad9743a8f68b5ae3ef7c54fdbf15d6de` |
| `toolframe-storage-sqlite` | `3812ccbc33beff87e03c93b750f750413c0786bd` |

By default, both repositories are siblings of this checkout. Use `--sdk-repo`
and `--storage-repo` to point to other local clones. Internet access is required
for public dependencies. To retain the two validated auth distributions:

```sh
artifact_dir=$(mktemp -d)
python3.14 scripts/ci.py --output "$artifact_dir/dist"
```

The output directory must be absent or empty. Validation starts with temporary
sources, an empty dependency wheelhouse, a fresh uv cache and fresh virtual
environments. It does not use the checkout's `.venv` or `dist`. All temporary
environments are removed on success or failure; artifacts are copied out only
after every check passes.

The script builds SDK and SQLite wheels from the commits above, exports public
dependencies with `uv export --locked --no-emit-local --no-hashes`, and builds
auth with `uv build --no-sources`. The auth wheel is built from its new sdist.
Both distributions must pass `twine check --strict`, retain exact `LICENSE` and
`NOTICE` contents, and match the project's version, runtime dependencies and
license metadata. Twine 7.0.0 is pinned because 6.2.0 rejects metadata 2.5 emitted
by the current allowed Hatchling build backend.

The test environment installs all three wheels and the locked development
dependencies, then runs `ruff check src tests scripts`, `pytest -q` and
`uv pip check`. A separate environment installs only the auth wheel, the SDK
wheel and real runtime dependencies; it checks imports from `site-packages`,
plugin entry-point loading, scrypt verification and dependency consistency.
SQLite is required for the integration tests and as a service when auth is
activated, but is not an auth Python runtime dependency. Neither environment
uses editable installs or `--no-deps`.

## GitHub Actions

`ci.yml` runs for pushes, pull requests, manual dispatch and calls from the
publish workflow. It runs the local script on `ubuntu-24.04`, Python 3.14.7 and
uv 0.12.8, then stores `toolframe-auth-dist` for seven days. Validation has a
20-minute timeout and read-only `contents` permission. Action versions are
pinned to full commit SHAs. The reusable workflow has no concurrency group that
could cancel its caller.

Before remote CI can run, publish the two sibling repositories and their pinned
commits under the base repository's owner, or set the repository variable
`TOOLFRAME_REPOSITORY_OWNER` to the owner hosting them. Fork pull requests still
fetch from the base repository's owner/variable, never the contributor's owner.
Public repositories need no additional secret. Private sibling repositories
require `TOOLFRAME_DEPENDENCIES_TOKEN` with read-only Contents access to both;
the default `GITHUB_TOKEN` cannot read another private repository. Fork pull
requests cannot access that secret and require publicly readable dependencies
to pass. Checkout credentials are not persisted.

`publish.yml` supports manual dispatch only, with `testpypi` as the default and
`pypi` as the other selection. Run it on an existing tag named exactly
`v<project.version>` (currently `v0.1.1`). A branch ref or mismatched tag fails
the version gate. The reusable CI workflow validates the selected `github.sha`,
and publishing downloads only that run's validated artifact. The publishing
job has a 10-minute timeout and is the only job with `id-token: write`. It does
not rebuild the distributions. Duplicate uploads fail; existing files are not
silently skipped. Publish runs for the same tag and index are serialized without
cancelling an in-progress run.

## External publishing setup

1. Make these workflows available on the GitHub repository's default branch and
   include them on the release tag, together with `scripts/ci.py`. Enable Actions
   and the pinned actions used here.
2. Create GitHub environments named exactly `testpypi` and `pypi`. Configure
   suitable reviewers and tag restrictions for each environment.
3. In each index separately, configure a Trusted Publisher for `toolframe-auth`
   (or a pending publisher if the project does not yet exist): the actual GitHub
   owner, repository `toolframe-auth`, workflow filename `publish.yml`, and the
   matching environment name. No PyPI API token is required.
4. Ensure `toolframe-sdk==0.2.0` is available from the index consumers use before
   expecting an ordinary index installation to work. CI currently supplies its
   pinned wheel locally; uploading auth does not upload SDK or SQLite. For a
   TestPyPI install, obtain trusted dependencies from PyPI or a controlled local
   wheelhouse rather than assuming TestPyPI mirrors them.
5. Create and push the matching version tag when authorized, then dispatch
   **Publish Python package** on that tag. Select TestPyPI first; select PyPI in
   a separate manual run when ready.

See the official [uv GitHub Actions guide](https://docs.astral.sh/uv/guides/integration/github/),
[PyPI Trusted Publishing guide](https://docs.pypi.org/trusted-publishers/using-a-publisher/)
and [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
