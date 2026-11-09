# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.0.0] - 2026-11-09

First tagged release: the deterministic verification gate for agent-initiated payments
(RBI E-mandate envelope as executable predicates, the obligation-coverage rule that
separates "checked and passed" from "never checked", and hash-chained evidence for every
verdict), with the live gate and playground.

### Added
- Live gate and playground deployed on Vercel (#1).
- `.gitattributes`: LF line endings in the repository, CRLF only for Windows
  scripts (#4).
- Standard repository files: changelog, `.editorconfig`, Dependabot and CodeQL
  configuration.

### Changed
- Playground restyled as a sober, professional console UI (#2).
- Playground header stays on one line on phones (#3).
- Dependabot leaves `pytest` to the pinned AP2 dependency (which requires
  `pytest==9.0.2`), so the Python update group resolves (#10).

[Unreleased]: https://github.com/CODER7657/pramana/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/CODER7657/pramana/releases/tag/v1.0.0
