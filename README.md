# @oma3/omatrust

Framework-agnostic TypeScript SDK for OMATrust.

Current npm state:
- Published prerelease: `0.1.0-alpha.0`
- Scope: `@oma3/omatrust`

## Install

Install current published package:

```bash
npm install @oma3/omatrust ethers
```

If you want to pin the current prerelease explicitly:

```bash
npm install @oma3/omatrust@0.1.0-alpha.0 ethers
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

## Documentation

Use the OMATrust developer docs as the canonical source for quick starts and API examples:

- [SDK Getting Started](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/getting-started.md)
- [Reputation SDK Guide](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/reputation-sdk.md)
- [Reputation SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/reputation-reference.md)
- [Identity SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/identity-reference.md)
- [App Registry SDK Reference](https://github.com/oma3dao/developer-docs/blob/main/docs/sdk/app-registry-reference.md)

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
