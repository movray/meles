# Contributing to meles

Thanks for helping. Bug reports, ideas and pull requests are welcome.

- **Bugs and ideas:** open an issue. For a bug, include the meles version,
  how meles runs (CLI, server, operator, Harbor adapter), the clamd
  version and the command or values you used.
- **Security problems:** do not open an issue, see [SECURITY.md](SECURITY.md).
- **Larger changes:** please open an issue first, so that we can agree on
  the approach before you spend time on it.

## Pull requests

1. Fork the repository and create a branch.
2. Build and test as described in
   [docs/development.md](docs/development.md): at least `make lint` and
   `make test`; changes to the scan chain also against a real clamd
   (`make test-integration`, a minimal clamd comes from
   `hack/ci/mini-clamd.sh`).
3. Open the pull request against `main`. CI runs after a maintainer
   approved the run.

Pull requests are squash-merged, so the pull request title becomes the
commit message.

## Conventions

The full list is in [docs/development.md](docs/development.md#conventions).
The ones that matter most for a pull request:

- Code, comments, commit messages and documentation in English.
- Commit messages and pull request titles follow
  [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:`, ...); the changelog is made from them.
- Errors are wrapped with context, logs go through `log/slog`, tests are
  table tests.
- **Never commit an EICAR file or real malware.** Test files with EICAR are
  generated at runtime (`internal/testimage`); a stored one would trigger
  virus scanners on every clone.
- Unpacking is security code: keep the path checks and the size and count
  limits.

## YARA rules

New default rules need a source with a license that allows redistribution,
and `author`, `source_url` and `license_url` in their `meta` block. See
`charts/meles/rules/README.md` and the YARA section of
[docs/development.md](docs/development.md#yara-rules).

## Developer Certificate of Origin

By contributing you certify that you wrote the change or otherwise have the
right to submit it under the project's license, as described in the
[Developer Certificate of Origin](https://developercertificate.org/). Sign
off every commit:

```sh
git commit -s
```

This adds a `Signed-off-by:` line with your name and email.

## License

meles is licensed under [Apache-2.0](LICENSE); contributions are accepted
under the same license. YARA rules keep the license of their source.
