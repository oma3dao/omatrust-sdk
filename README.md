# @oma3/omatrust

Framework-agnostic TypeScript SDK for OMATrust.

Current npm state:
- As of February 25, 2026:
  - `latest` -> `0.1.0-alpha.5`
  - `alpha` -> `0.1.0-alpha.5`
- Scope: `@oma3/omatrust`

## Install

Install current published package:

```bash
npm install @oma3/omatrust ethers
```

Install the current `alpha` tag explicitly:

```bash
npm install @oma3/omatrust@alpha ethers
```

If you want to pin an exact version:

```bash
npm install @oma3/omatrust@0.1.0-alpha.5 ethers
```

If you use the reputation module, also install EAS SDK:

```bash
npm install @ethereum-attestation-service/eas-sdk
```

## Module Map

- `@oma3/omatrust/identity`
  - DID normalization and hashing
  - DID address derivation
  - CAIP-10 / CAIP-2 helpers
  - JSON canonicalization helpers
- `@oma3/omatrust/reputation`
  - attestation submit/delegated flows
  - attestation query + verification
  - proof creation/verification helpers
  - controller witness client
- `@oma3/omatrust/app-registry`
  - ERC-8004 helpers
  - interface bitmap/status/version helpers
  - trait hashing + metadata keys
  - data hash verification

- Check current dist-tags:

```bash
npm dist-tag ls @oma3/omatrust
```

## Documentation

Use the OMATrust developer docs as the canonical source for quick starts and API examples:

- [SDK Getting Started](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/getting-started.md)
- [SDK Guides](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/guides.md)
- [Reputation SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/api-reference/reputation-sdk.md)
- [Identity SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/api-reference/identity-sdk.md)
- [App Registry SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/app-registry/registry-sdk-reference.md)

## Notes

- No React/Next/wallet framework dependency is required.
- Consumers provide signer/provider instances.
- Chain config (RPC URLs, deployed addresses, schema UIDs) is consumer-supplied.

## Release Notes

- Prereleases are published with the `alpha` dist-tag.
- Stable releases are published with the `latest` dist-tag.
- Install explicit prerelease:

```bash
npm install @oma3/omatrust@alpha
```

- Install latest stable:

```bash
npm install @oma3/omatrust
```

## License

MIT
