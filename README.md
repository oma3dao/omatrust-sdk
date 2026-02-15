# @oma3/omatrust

Framework-agnostic TypeScript SDK for OMATrust.

## Install

```bash
npm install @oma3/omatrust ethers
```

If you use `@oma3/omatrust/reputation`, also install EAS SDK:

```bash
npm install @ethereum-attestation-service/eas-sdk
```

## Modules

- `@oma3/omatrust/identity`
- `@oma3/omatrust/reputation`
- `@oma3/omatrust/app-registry`

## Example

```ts
import { normalizeDid, didToAddress } from "@oma3/omatrust/identity";

const did = normalizeDid("did:web:example.com");
const address = didToAddress(did);
```
