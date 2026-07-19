# Changelog

All notable changes to this project are documented here.
This project adheres to [Semantic Versioning](https://semver.org) and
[Conventional Commits](https://www.conventionalcommits.org).

## [0.3.0] - 2026-07-19

### Features
- v2 recipient-sealed node↔relay control + relay↔relay mesh wire (#1199, #1200). Adds a relay BLS G1
  identity, the BLS-G2-signed `RelayDescriptor`, the additive `relay_hello`/`sealed` `RelayMessage`
  variants, the `MeshMessage` mesh frame set (band `0x0900`), and — behind the new `seal` feature —
  the `seal` module (seal/open control + mesh frames via dig-message G1-DHKEM, descriptor signing +
  verification, seal-mode downgrade negotiation). v1 RLY-001..007 stays byte-identical (§5.1).

## [0.2.0] - 2026-07-18

### Features
- Add connect-leg addressing fields to Register + RelayPeerInfo (#924) (#2)

## [0.1.0] - 2026-07-17

### Features
- Node↔relay protocol crate — byte-identical RLY wire extraction (#1)

### Chores
- Initial commit — dig-relay-protocol scaffold (canonical node-to-relay protocol)

