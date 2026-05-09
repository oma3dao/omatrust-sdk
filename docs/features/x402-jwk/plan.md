# x402 JWS/JWK Verification — plan.md

## 1. Implementation Goal

Add first-class OMATrust SDK support for verifying x402 signed offers and receipts that use JWS Compact Serialization.

The implementation should support both:

1. **Resolution-based JWS** — use `kid` to resolve public key material.
2. **Self-contained JWS** — use embedded `jwk` for immediate/offline signature verification.

The product behavior and test expectations are defined in `spec.md`.

## 2. Guiding Implementation Decisions

1. Keep signature verification and authorization separate.
2. Do not treat embedded `jwk` as authorization.
3. Use `did:jwk` as the durable DID representation of JWS public key material.
4. Prefer JWK-native logic over adding `did:key` dependencies for this feature.
5. Do not force JWK controllers into EVM-address-only authorization functions.
6. Keep existing x402 helper names compatible where practical.
7. Use explicit errors/failure codes for frontend and developer debugging.
8. Keep this feature scoped to JWS/JWK. Do not refactor EIP-712 in this phase.
9. Update the x402 Offer and Receipt Extension spec so JWS headers require `alg` and at least one of `kid` or `jwk`; `kid` must not be mandatory when `jwk` is present.

## 2.1 x402 Extension Spec Prerequisite

Before or alongside the SDK implementation, update the x402 Offer and Receipt Extension specification.

Current direction:

- `alg` remains REQUIRED.
- `kid` becomes OPTIONAL.
- `jwk` remains OPTIONAL.
- At least one of `kid` or `jwk` MUST be present.

Rationale:

- `jwk` is sufficient for JWS signature verification.
- `kid` is useful for key resolution and authorization lookup, but x402 should not require a specific identity or authorization mechanism.
- Authorization and service identity binding are handled outside x402 by systems such as OMATrust, DID documents, DNS TXT records, Controller Witness, Key Binding, or other external trust systems.
- When `kid` is absent, verifiers can use `resourceUrl` from the signed payload plus the embedded `jwk` / `did:jwk` representation of the public key to perform OMATrust authorization checks.
- When both `kid` and `jwk` are present, verifiers should use `jwk` for immediate signature verification and may use `kid` for key resolution or authorization lookup. If `kid` resolves to a different public key than the embedded `jwk`, verification should fail.

Spec language should make clear:

- `kid` is RECOMMENDED when a service wants to provide a stable key identifier or DID URL for authorization lookup.
- `jwk` is RECOMMENDED when artifacts may be verified offline, stored for long-term auditability, or used when the resource server may not remain available.
- `jwk` does not establish authorization by itself.
- x402 provides signed artifacts and cryptographic verification material; identity and authorization policy remain external to the protocol.

## 3. Suggested Files and Modules

Use existing repo conventions where possible. Suggested structure:

```txt
src/identity/did-url.ts
src/identity/jwk.ts
src/identity/did-jwk.ts
src/identity/resolve-key.ts
src/x402/jws.ts
src/x402/types.ts
src/reputation/proof/x402.ts
src/reputation/verify.ts
```

If the repo already has equivalent files, extend those instead of creating duplicates.

Docs:

```txt
docs/features/x402-jwk/spec.md
docs/features/x402-jwk/plan.md
```

Potential developer-docs updates may live in the developer-docs repository or SDK docs, depending on current conventions.

## 4. Phase 1 — DID URL Parsing

### 4.1 Add DID URL Parser

Create a generic DID URL parser.

Input example:

```txt
did:web:api.example.com#key-1
```

Output concept:

```ts
type ParsedDidUrl = {
  didUrl: string;
  did: string;
  fragment: string | null;
};
```

Requirements:

- Use existing DID normalization helpers where appropriate.
- Reject malformed input.
- Preserve the original DID URL.
- Support fragment parsing.
- Do not make this helper x402-specific.

### 4.2 Tests

Add tests for:

- valid DID URL with fragment;
- valid DID without fragment, if supported;
- malformed DID URL;
- unsupported or malformed fragment format, if applicable.

## 4.3 Rename `getAttesterAuthorization` to `getControllerAuthorization`

Rename the existing `getAttesterAuthorization` function (and its associated types/params) to `getControllerAuthorization`. This reflects that the function checks whether a *controller* DID is authorized for a subject, not just whether an "attester" is authorized.

Rename targets:

- `getAttesterAuthorization` → `getControllerAuthorization`
- `GetAttesterAuthorizationParams` → `GetControllerAuthorizationParams`
- `AttesterAuthorizationResult` → `ControllerAuthorizationResult`

Preserve the old names as deprecated re-exports for backward compatibility during the alpha period.

## 5. Phase 2 — JWK and `did:jwk` Helpers

### 5.1 `did:jwk` Validation

Implement or complete helpers:

```ts
validatePrivateKeyDid(...)
isPrivateKeyDid(...)
normalizeDidJwk(...)
```

Expected behavior:

- parse `did:jwk`;
- base64url-decode;
- parse JSON;
- require `kty`;
- reject private key material such as `d`;
- support structurally valid public JWKs.

### 5.2 Conversion Helpers

Add helpers:

```ts
jwkToDidJwk(...)
didJwkToJwk(...)
```

Implementation guidance:

- Use deterministic JSON serialization for conversion.
- Avoid private key fields.
- Return normalized public JWK values.

### 5.3 JWK Comparison

Add helper:

```ts
publicJwkEquals(a, b): boolean
```

Behavior:

- compare public key material;
- ignore property order;
- reject or strip private fields before comparison;
- be deterministic.

### 5.4 Tests

Add tests for:

- valid `did:jwk`;
- malformed base64url;
- missing `kty`;
- private key field rejection;
- JWK to DID conversion;
- DID to JWK conversion;
- equivalent JWK comparison;
- mismatched JWK comparison.

## 6. Phase 3 — DID URL Key Resolution

### 6.1 Add Key Resolver and Controller DID Derivation

Implement helpers to resolve DID URL `kid` to public JWK and derive a durable `did:jwk` controller DID.

Suggested functions:

```ts
resolveDidUrlPublicKey(kid: string, options?: ResolveOptions): Promise<ResolvedPublicKey>
resolveDidUrlControllerDid(kid: string, options?: ResolveOptions): Promise<ResolvedControllerDid>
```

Suggested result for `resolveDidUrlControllerDid`:

```ts
type ResolvedControllerDid = {
  didUrl: string;
  did: string;
  fragment: string | null;
  publicKeyJwk: JsonWebKey;
  controllerDid: string; // did:jwk:<encoded-public-jwk>
};
```

`resolveDidUrlControllerDid` wraps `resolveDidUrlPublicKey` and adds the `did:jwk` conversion step. The returned `controllerDid` is the durable DID that callers should pass to `getControllerAuthorization`.

### 6.2 `did:web#fragment` Behavior

For `did:web#fragment`:

1. Parse DID URL.
2. Resolve base `did:web`.
3. Fetch or load DID document.
4. Find matching verification method.
5. Extract `publicKeyJwk`.
6. Validate that the JWK contains only public key material.
7. Convert the public JWK to `did:jwk`.

Matching should support:

- full ID match, e.g. `did:web:api.example.com#key-1`;
- fragment match, e.g. `#key-1` where applicable.

### 6.3 Resolver Boundaries

This resolver obtains key material and derives a durable `did:jwk`. It must not:

- decide whether the key is authorized for a service;
- check Controller Witness;
- check Key Binding;
- make policy decisions.

The derived `did:jwk` is a durable controller DID suitable for passing to `getControllerAuthorization`. The DID URL itself is a mutable key reference and should not be used as a controller DID.

### 6.4 Tests

Add mocked DID document tests:

- resolves public key from full DID URL;
- resolves public key from fragment;
- derives correct `did:jwk` from resolved public key;
- fails when verification method is missing;
- fails when `publicKeyJwk` is absent;
- fails cleanly for unsupported DID methods.

## 7. Phase 4 — Authorization Metadata Exposure

### 7.1 Return Data Needed for Authorization

JWS verification should expose enough information for callers to perform OMATrust authorization checks via `getControllerAuthorization`.

Return or expose:

- `kid` (as a key reference, not a controller DID);
- `resourceUrl`;
- `issuedAt` for receipts;
- public JWK used;
- `did:jwk` derived from the public key — this is the durable controller DID for downstream authorization.

### 7.2 Do Not Embed Authorization Policy

Do not make the JWS verifier decide whether the key is authorized.

Authorization will be handled by `getControllerAuthorization` using Controller Witness, Key Binding, live DID/DNS checks, or other external trust systems.

### 7.3 Intended Authorization Flow

After JWS verification, the caller should:

1. Take the `did:jwk` from the verification result (the durable controller DID).
2. Derive the subject DID from `resourceUrl` (e.g. `did:web:api.example.com`).
3. Call `getControllerAuthorization({ subjectDid, controllerDid: didJwk, purpose })`.
4. Evaluate the returned authorization window against their policy.

### 7.4 Controller Witness Key-Pinning Example

Document example:

```txt
subject:    did:web:api.example.com#key-1
controller: did:jwk:<encoded-public-jwk>
```

This Controller Witness means the witness verified that the DID URL resolved to that public key at `observedAt`. The DID URL is the subject (the mutable reference being pinned). The `did:jwk` is the controller (the immutable key material).

## 8. Phase 5 — x402 JWS Verification

### 8.1 Add Types

Add types for JWS x402 artifacts and verification results.

Conceptual artifact:

```ts
type X402JwsArtifact = {
  format: "jws";
  signature: string;
};
```

Conceptual result:

```ts
type X402JwsVerificationResult = {
  valid: boolean;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  kid: string;
  publicKeyJwk: JsonWebKey;
  publicKeySource: "embedded-jwk" | "kid-resolution";
  publicKeyDid: string; // did:jwk — durable controller DID for authorization
  error?: {
    code: string;
    message: string;
  };
};
```

Use existing repo error and type conventions if different.

### 8.2 Add Verification Functions

Suggested functions:

```ts
verifyX402JwsOffer(...)
verifyX402JwsReceipt(...)
verifyX402JwsArtifact(...)
```

Shared behavior:

1. Parse compact JWS.
2. Decode protected header.
3. Decode payload.
4. Require `alg`.
5. Require at least one of `kid` or `jwk`.
6. Select public key:
   - embedded `jwk`, if present;
   - otherwise resolve `kid`.
7. Verify JWS signature.
8. Convert the verified public key to `did:jwk` (durable controller DID).
9. Validate payload shape.
10. Return structured result including `did:jwk`.

### 8.3 Embedded `jwk` Behavior

When `jwk` is present:

- use it for signature verification;
- reject if it contains private key material;
- convert it to `did:jwk` if helper exists;
- optionally resolve `kid` if configured;
- reject if resolved key conflicts with embedded key.

### 8.4 `kid`-Only Behavior

When `jwk` is absent:

- resolve `kid` to public key material;
- convert the resolved public key to `did:jwk`;
- use resolved public JWK for signature verification;
- return the derived `did:jwk` as the durable controller DID;
- fail if key cannot be resolved.

### 8.5 Payload Validation

Offer payload requires:

```txt
version
resourceUrl
scheme
network
asset
payTo
amount
```

Optional:

```txt
validUntil
```

Receipt payload requires:

```txt
version
network
resourceUrl
payer
issuedAt
```

Optional:

```txt
transaction
```

### 8.6 Tests

Add tests for:

- valid offer with embedded `jwk`;
- valid receipt with embedded `jwk`;
- valid offer with `kid` resolution;
- valid receipt with `kid` resolution;
- missing `alg`;
- missing `kid`;
- invalid signature;
- malformed compact JWS;
- private JWK in header;
- conflict between embedded `jwk` and resolved `kid`;
- missing required offer field;
- missing required receipt field;
- absence of artifact-level `payload`.

## 8b. Phase 5b — x402 EIP-712 Verification

### 8b.1 Goal

Add EIP-712 signature verification for x402 signed offers and receipts alongside the existing JWS path.

EIP-712 is the simpler path: the signer address is recovered directly from the signature using ethers `verifyTypedData`. There is no DID URL resolution or JWK handling — the recovered address is the verification output.

### 8b.2 Artifact Shape

Per the x402 Offer and Receipt Extension spec, EIP-712 artifacts have:

```ts
type X402Eip712Artifact = {
  format: "eip712";
  payload: Record<string, unknown>;
  signature: string; // hex-encoded, 0x-prefixed, 65 bytes (r+s+v)
};
```

The `payload` field is REQUIRED for EIP-712 (unlike JWS where it's inside the compact string).

### 8b.3 EIP-712 Domain

All x402 EIP-712 signatures use a fixed domain:

```ts
{
  name: "<artifact-specific>",  // "x402 offer" or "x402 receipt"
  version: "1",
  chainId: 1  // constant — EIP-712 is used off-chain; payment network is in payload
}
```

The `chainId: 1` is intentional and hardcoded. EIP-712 is used purely as an off-chain signing format. The actual payment network is identified by the `network` field in the payload.

### 8b.4 Canonical EIP-712 Types

**Offer types (primaryType: "Offer"):**

```ts
{
  Offer: [
    { name: "version", type: "uint256" },
    { name: "resourceUrl", type: "string" },
    { name: "scheme", type: "string" },
    { name: "network", type: "string" },
    { name: "asset", type: "string" },
    { name: "payTo", type: "string" },
    { name: "amount", type: "string" },
    { name: "validUntil", type: "uint256" }
  ]
}
```

**Receipt types (primaryType: "Receipt"):**

```ts
{
  Receipt: [
    { name: "version", type: "uint256" },
    { name: "network", type: "string" },
    { name: "resourceUrl", type: "string" },
    { name: "payer", type: "string" },
    { name: "issuedAt", type: "uint256" },
    { name: "transaction", type: "string" }
  ]
}
```

These types are normative and MUST NOT be transmitted on the wire. Signers and verifiers both use these canonical definitions.

### 8b.5 Optional Field Handling

For EIP-712, all fields must be present in the signed message (fixed schema). Optional fields use zero-values:

- `validUntil`: `0` means absent
- `transaction`: `""` (empty string) means absent

Verifiers MUST treat zero-value optional fields as equivalent to absence.

### 8b.6 Verification Functions

Suggested functions:

```ts
verifyX402Eip712Offer(artifact: X402Eip712Artifact): Eip712VerificationResult | Eip712VerificationFailure
verifyX402Eip712Receipt(artifact: X402Eip712Artifact): Eip712VerificationResult | Eip712VerificationFailure
verifyX402Eip712Artifact(artifact: X402Eip712Artifact, artifactType: "offer" | "receipt"): ...
```

Shared behavior:

1. Validate artifact envelope (`format`, `payload`, `signature` all present).
2. Validate payload shape (required fields for offer or receipt).
3. Construct EIP-712 typed data using the canonical domain and types.
4. Verify signature and recover signer address using `verifyTypedData` from ethers.
5. Return structured result with recovered signer, decoded payload, and artifact type.

### 8b.7 Verification Result

```ts
type Eip712VerificationResult = {
  valid: true;
  payload: Record<string, unknown>;
  signer: string;           // recovered EVM address (checksummed)
  artifactType: "offer" | "receipt";
};

type Eip712VerificationFailure = {
  valid: false;
  error: { code: string; message: string };
  payload?: Record<string, unknown>;
  signer?: string;
};
```

### 8b.8 Signer Authorization Is External

Like JWS verification, EIP-712 verification only proves the signature is valid and returns the recovered signer address. It does NOT determine whether the signer is authorized.

The simplest authorization check: compare the recovered signer to `payload.payTo`. If they match, the payment recipient signed the artifact.

For more complex authorization, callers can:
1. Convert the signer address to `did:pkh:eip155:1:<address>`.
2. Call `getControllerAuthorization({ subjectDid, controllerDid })`.

### 8b.9 Integration with `verifyProof`

Update `verifyProof` so that:

- `x402-offer` with `format: "eip712"` calls `verifyX402Eip712Offer`;
- `x402-receipt` with `format: "eip712"` calls `verifyX402Eip712Receipt`;
- verification is cryptographic (recovers signer), not shape-only.

### 8b.10 Tests

Add tests for:

- valid EIP-712 offer verification (recover signer);
- valid EIP-712 receipt verification (recover signer);
- missing `payload` field;
- missing `signature` field;
- invalid signature (recovery fails);
- missing required offer payload fields;
- missing required receipt payload fields;
- `validUntil: 0` treated as absent;
- `transaction: ""` treated as absent;
- `verifyProof` routes EIP-712 offers to cryptographic verification;
- `verifyProof` routes EIP-712 receipts to cryptographic verification.

## 9. Phase 6 — Integrate with Existing x402 Proof Helpers / GitHub Issue #2

This phase addresses the GitHub issue #2 work: adding first-class x402 signed offer/receipt support in the OMATrust SDK.

This should happen after the lower-level JWS/JWK building blocks are implemented:

1. DID URL parsing
2. `did:jwk` helpers
3. JWK comparison
4. DID URL key resolution
5. authorization metadata exposure
6. standalone JWS verification

The reason for doing this late is that issue #2 depends on the lower-level primitives above. Once those primitives are stable, integrating x402 proof helpers and `verifyProof` should be mostly wiring, typing, tests, and documentation.

### 9.1 Stronger x402 Proof Types

Update x402 proof object types so they are not just `Record<string, unknown>` where practical.

Support JWS offer and receipt artifacts explicitly.

### 9.2 Existing Helpers

Preserve existing helpers where practical:

```ts
createX402OfferProof(...)
createX402ReceiptProof(...)
```

Update them so they can carry strongly typed JWS artifacts.

If signatures or return shapes must change, provide a deprecation path.

### 9.3 `verifyProof` Integration

Update `verifyProof` so that:

- `x402-offer` with `format: "jws"` calls JWS offer verification;
- `x402-receipt` with `format: "jws"` calls JWS receipt verification;
- `x402-offer` with `format: "eip712"` calls EIP-712 offer verification;
- `x402-receipt` with `format: "eip712"` calls EIP-712 receipt verification;
- verification is cryptographic, not shape-only;
- unknown formats return a clear unsupported-format error.

### 9.4 Tests

Add tests that:

- x402 offer proof invokes JWS verification;
- x402 receipt proof invokes JWS verification;
- invalid JWS proof fails;
- existing wrapper helpers still work.

## 10. Phase 7 — Developer Documentation

Update SDK/developer docs to explain the new JWS path.

### 10.1 Topics to Cover

Add docs covering:

- x402 JWS offer/receipt structure;
- `kid` as DID URL;
- optional `jwk`;
- resolution-based verification;
- self-contained verification;
- why `jwk` verifies signatures but does not authorize keys;
- `did:jwk` as durable key representation;
- Controller Witness as durable key pinning;
- key rotation via newer witness records;
- how `verifyProof` handles x402 JWS proofs.

### 10.2 Example Flow

Include an example flow:

1. Service returns JWS receipt.
2. SDK verifies JWS signature using embedded `jwk`.
3. SDK converts public JWK to `did:jwk`.
4. Verifier checks Controller Witness / Key Binding for authorization.
5. Verifier accepts, rejects, or downgrades based on policy.

### 10.3 Migration Notes

Document:

- old x402 proof wrappers were shape-oriented;
- new verification performs cryptographic checks for JWS;
- callers may need to pass resolver options for `kid`-only artifacts;
- embedded `jwk` is recommended for durable/offline verification.

## 11. Rollout Notes

### 11.1 Backward Compatibility

Keep existing exported helper names where practical.

If return types expand, prefer additive changes.

### 11.2 Feature Completeness

This feature is complete when:

- JWS x402 offers and receipts verify cryptographically;
- EIP-712 x402 offers and receipts verify cryptographically;
- `kid`-only and `kid + jwk` paths both work for JWS;
- EIP-712 signer recovery works with the canonical domain and types;
- `did:jwk` helpers exist and are tested;
- developer docs explain both the JWS and EIP-712 models;
- `verifyProof` no longer treats any x402 proofs as shape-only.

## 12. Risks and Mitigations

### 12.1 Risk: Authorization Confusion

Mitigation:

- Keep verifier output explicit.
- Document that signature verification is not authorization.
- Do not auto-approve based on `jwk`.

### 12.2 Risk: DID Resolution Fragility

Mitigation:

- Support embedded `jwk`.
- Allow `kid` resolution when needed.
- Clearly document the durability tradeoff.

### 12.3 Risk: Adding Excess DID Complexity

Mitigation:

- Support `did:jwk` for this path.
- Defer full `did:key` support.
- Keep DID URL parsing generic.

### 12.4 Risk: Conflicting Key Material

Mitigation:

- Reject artifacts when embedded `jwk` and resolved `kid` key conflict.
- Add tests for this case.

### 12.5 Risk: Breaking Existing x402 Helpers

Mitigation:

- Preserve helper names.
- Make changes additive where possible.
- Add compatibility tests.
