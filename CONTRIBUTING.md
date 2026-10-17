# Contributing to Nuxut

Thanks for your interest! Nuxut is a young project; issues and pull requests are welcome.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Nuxut is split into several repositories that build side by side:
  [framework](https://github.com/nuxut/framework) (UI framework),
  [shell](https://github.com/nuxut/shell), [settings](https://github.com/nuxut/settings),
  [calendar](https://github.com/nuxut/calendar) and [accounts](https://github.com/nuxut/accounts).
  Clone them into one directory; path dependencies such as `../framework` expect that layout.
- Generic UI components and capabilities belong in the framework, not in the shell or apps.

## Code

- Everything is Rust. Please do not add scripts in other languages to the build or tooling;
  small POSIX shell scripts are fine.
- Identifiers are in English. Comments and design documents are written in Turkish; English
  is fine in pull requests and issues.
- Services stay independent of the UI and are covered by tests.
- New third-party crates or system packages are listed in `docs/DEPENDENCIES.md` with the
  reason, the alternatives considered and the Arch Linux runtime package.
- User-visible strings go through the i18n catalogs (`locales/*.ftl`).

## Checks

Every change must pass:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

UI changes should be tried in a running session (for example a nested or headless compositor)
and shown with a screenshot in the pull request. Screenshots must not contain personal data.

## Commits

Write commit messages in plain language: what changed and why. Keep commits focused.

By contributing you agree that your contribution is licensed under the MIT License of the
repository.
