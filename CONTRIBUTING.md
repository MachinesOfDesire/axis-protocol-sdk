# Contributing to axis-protocol-sdk

Thanks for your interest in contributing to the AXIS Protocol JavaScript SDK.

## Ground rules

- The SDK is a downstream consumer of the [AXIS Protocol spec](https://github.com/MachinesOfDesire/axis-protocol). Wire-format and protocol-semantics decisions belong in the spec repo, not here. SDK changes should track the spec; contributions that propose new wire-level behavior should land there first.
- Zero runtime dependencies. The SDK ships as ESM source with no transpilation, no bundler, no shim. Pull requests that add a `dependencies` entry to `package.json` will be rejected unless there is a strong reason discussed in an issue first.
- Universal runtime support: Node 20+, Cloudflare Workers, Deno, Bun, modern browsers. New code uses Web Crypto, `fetch`, `TextEncoder`, `crypto.subtle` — built-ins available in every target.

## Workflow

1. Open an issue describing the change before sending a PR for anything non-trivial. For small fixes (typos, doc tweaks, obviously-correct bug fixes), a direct PR is fine.
2. Branch from `main`. Use conventional-commits-style branch names: `feat/<short-description>`, `fix/<short-description>`, `docs/<short-description>`, etc.
3. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/). Types in use: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `style`, `perf`.
4. Run the test suite: `npm test`. New behavior adds tests.
5. Open a PR against `main`. CI must pass. Maintainer review precedes merge.

## Contributor License Agreement (CLA)

By submitting a contribution to this repository you agree that your contribution is licensed under the same Apache License, Version 2.0 that covers the project, and you grant to **Kipple Labs, Inc.** (and any future foundation or successor organization that inherits stewardship of the AXIS Protocol project) a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, distribute, and sublicense your contribution under the Apache License, Version 2.0 or any future license adopted by Kipple Labs, Inc. for this project.

You retain copyright in your contribution. This agreement does not transfer copyright ownership.

You confirm that you have the legal right to grant this license — that your contribution is your original work, or that you have explicit permission from the copyright holder to contribute it under these terms.

## Security

Security issues: please report privately per [SECURITY.md](./SECURITY.md) (when present) rather than opening a public issue. If no SECURITY.md exists yet, email the project owner at the address listed in `package.json` `bugs` / `repository` references.

## Code of conduct

Be civil. Discussions stay on the technical merits. Personal attacks and harassment are not welcome.
