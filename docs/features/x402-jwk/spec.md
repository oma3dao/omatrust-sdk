# x402 JWS/JWK Verification and Controller Authorization — spec.md

## 1. Purpose

This specification defines SDK behavior for the generic DID/JWK primitives, controller authorization utilities, and x402 JWS/JWK verification support needed by OMATrust.

The design separates three layers:

1. **Generic identity/key primitives**
   - DID URL parsing
   - `did:jwk` validation and conversion
   - public JWK comparison
   - DID URL key resolution

2. **Controller authorization**
   - determining whether a controller DID is authorized for a subject DID
   - returning an authorization window and supporting evidence
   - supporting Controller Witness, Key Binding, and live verification sources

3. **x402 JWS offer/receipt verification**
   - decoding x402 JWS artifacts
   - verifying JWS signatures
   - integrating with x402 proof helpers and `verifyProof`

The x402-specific pieces partially address GitHub issue #2, "Add first-class x402 signed offer/receipt support in OMATrust SDK after coinbase/x402#935 merges." The lower-level DID/JWK and controller authorization primitives are not x402-specific and should be usable by future OMATrust features.

This specification is intended for product review, SDK API review, QA planning, and test-case development.

## 2. Scope

### 2.1 In Scope

This feature covers:

- Parsing DID URLs separately from bare DIDs.
- Ensuring subject DID parsers reject DID URLs where a bare DID is expected.
- Supporting `did:jwk` as a durable DID representation of public JWK key material.
- Validating public JWKs and rejecting private key material.
- Converting public JWKs to and from `did:jwk`.
- Comparing public JWKs deterministically.
- Resolving DID URL key references such as `did:web:api.example.com#key-1` to public JWKs and deriving durable `did:jwk` controller DIDs.
- Supporting controller authorization checks where controllers are durable DIDs (`did:pkh`, `did:jwk`).
- Supporting optional W3C `purpose` filtering for key authorization.
- Returning a single authorization window plus evidence metadata.
- Parsing x402 JWS signed offer and receipt artifacts.
- Decoding JWS protected headers and payloads.
- Verifying JWS signatures using either:
  - embedded `jwk`; or
  - public key material resolved from `kid`.
- Returning structured JWS signature verification results.
- Integrating JWS cryptographic verification into existing x402 proof verification.
- Updating developer docs to explain the relationship between:
  - signature verification,
  - `kid`,
  - `jwk`,
  - `did:jwk`,
  - Controller Witness,
  - Key Binding,
  - and OMATrust authorization.

### 2.2 Out of Scope

This feature does not define or implement:

- EIP-712 x402 verification changes.
- x402 payment execution.
- x402 settlement or facilitator logic.
- Subscription, billing, or x402 payment-for-API-access flows.
- Full `did:key` support.
- Social-handle Controller Witness automation.
- A complete refactor of all OMATrust authorization APIs beyond the controller-authorization behavior described here.
- Any requirement that all JWS receipts must have a Controller Witness.
- Any requirement that `jwk` alone establishes authorization.

## 3. Product and Security Principles

### 3.1 Signature Verification and Authorization Are Separate

The SDK must distinguish between:

- **Signature verification**: proving that a JWS artifact was signed by a public key.
- **Authorization**: proving that the public key or controller DID was authorized for the service/resource.

An embedded JWS `jwk` can verify a signature. It does not prove that the key is authorized for a service.

### 3.2 DID URLs Are Mutable Key References, Not Durable Controller DIDs

A DID URL is not the same identifier as its base DID, and it is not a durable controller identifier.

Example bare DID:

```txt
did:web:api.example.com
```

Example DID URL:

```txt
did:web:api.example.com#key-1
```

The base DID identifies the service/domain subject. The DID URL identifies a verification method, key reference, or other resource under the DID.

A DID URL like `did:web:api.example.com#key-1` is **mutable** because the domain owner can update the DID document so that `#key-1` points to different key material at any time.

Therefore a DID URL is appropriate as:

- a JWS `kid`;
- a DID document verification method reference;
- a DNS TXT / JWKS key reference;
- a lookup handle;
- a Controller Witness **subject** for key-pinning.

But a DID URL must **not** be treated as a durable controller DID. The durable controller DID should be derived from the actual resolved public key material:

```txt
did:jwk:<encoded-public-jwk>
```

SDK functions must not silently collapse a DID URL into the same normalized value as its base DID. SDK functions must not use a DID URL as a `controllerDid` when a resolved `did:jwk` is available.

### 3.3 `did:jwk` Represents Public Key Material

`did:jwk` is the preferred durable DID representation for JWS/JWK public key material in this feature.

Reason:

- JWS and JOSE are JWK-native.
- `did:jwk` represents the same public JWK key material in DID form.
- This avoids adding `did:key`, multicodec, or multibase dependencies for the JWS/JWK path.

`did:jwk` must never contain private key material.

### 3.4 Controller Authorization Is Evidence, Not Policy

The SDK authorization utility returns evidence and a computed authorization window.

It must not decide whether a verifier should accept a receipt, review, attestation, or other trust record. Verifiers apply their own policies based on the returned evidence.

### 3.5 Conflicting Keys Must Be Rejected

If a JWS includes embedded `jwk` and the SDK also resolves `kid` to public key material, the two keys must match.

If they conflict, signature verification must fail.

This prevents an attacker from embedding their own key while reusing a legitimate `kid`.

## 4. Generic DID and Public Key Primitives

This section defines reusable SDK primitives. These primitives are not specific to x402.

### 4.1 DID URL Parsing

The SDK must define a generic DID URL parser:

```ts
parseDidUrl(input: string)
```

Example input:

```txt
did:web:api.example.com#key-1
```

The parser must return:

- the original DID URL;
- the base DID;
- the fragment, if present.

Example result:

```json
{
  "didUrl": "did:web:api.example.com#key-1",
  "did": "did:web:api.example.com",
  "fragment": "key-1"
}
```

Malformed DID URLs must be rejected.

This parser must be separate from any existing `did:web` parser. A parser that expects a bare `did:web` subject DID must not silently accept or normalize a DID URL with a fragment.

### 4.2 Bare DID Inputs Must Reject DID URLs

SDK functions that expect a bare subject DID MUST reject DID URLs.

For example, a function expecting:

```txt
did:web:api.example.com
```

must reject:

```txt
did:web:api.example.com#key-1
```

The rejection should be explicit and should direct callers to use `parseDidUrl` or a DID URL-aware function.

Reason:

- `did:web:api.example.com` identifies the service/domain subject.
- `did:web:api.example.com#key-1` identifies a key reference or verification method under that subject.

These are different identifiers and must not be collapsed into the same normalized value.

### 4.3 DID URL Key Resolution and Controller DID Derivation

DID URLs are mutable key references. The SDK must support resolving them to public key material and deriving a durable `did:jwk` controller DID.

The SDK should expose the following helpers:

```ts
parseDidUrl(input: string)
resolveDidUrlPublicKey(didUrl: string, options?: ResolveOptions): Promise<ResolvedPublicKey>
resolveDidUrlControllerDid(didUrl: string, options?: ResolveOptions): Promise<ResolvedControllerDid>
```

#### Resolution Behavior

For `did:web#fragment` values, the SDK must:

1. Parse the DID URL.
2. Resolve the base `did:web`.
3. Load the DID document.
4. Search for a verification method matching:
   - the full DID URL; or
   - the fragment reference.
5. Extract `publicKeyJwk`.
6. Validate that the JWK contains only public key material (reject if `d` is present).
7. Convert the public JWK to `did:jwk`.
8. Return both the resolved public JWK and the derived `did:jwk`.

If the key cannot be found or resolved, the helper must fail with a clear error.

#### `resolveDidUrlControllerDid` Result

Example input:

```txt
did:web:api.example.com#key-1
```

Example result:

```ts
{
  didUrl: "did:web:api.example.com#key-1",
  did: "did:web:api.example.com",
  fragment: "key-1",
  publicKeyJwk: { kty: "EC", crv: "P-256", x: "...", y: "..." },
  controllerDid: "did:jwk:<encoded-public-jwk>"
}
```

The `controllerDid` field is the durable `did:jwk` derived from the resolved public key material. This is the value callers should pass to `getControllerAuthorization` as the `controllerDid` parameter.

#### Boundaries

DID URL key resolution only obtains key material and derives a durable DID. It must not:

- decide whether the key is authorized for a service;
- check Controller Witness;
- check Key Binding;
- make policy decisions.

### 4.4 `did:jwk` Validation

A valid `did:jwk` must:

- use base64url encoding;
- decode to valid JSON;
- contain public JWK key material;
- include at least `kty`;
- not include private key material such as `d`.

The SDK should support structurally valid public JWKs for common key families, including:

- `EC`;
- `OKP`;
- and `RSA`, if practical.

### 4.5 `did:jwk` Conversion

The SDK should expose helpers to:

- convert public JWK to `did:jwk`;
- convert `did:jwk` back to public JWK;
- normalize `did:jwk`;
- validate public-key DID inputs such as `did:jwk`, including rejecting private key material.

### 4.6 Public JWK Validation and Comparison

The SDK must provide reusable helpers for validating and comparing public JWKs.

A valid public JWK must:

- include required public key fields for its key type;
- not include private key material such as `d`;
- be usable for signature verification when paired with a supported JWS `alg`.

The SDK must provide a deterministic way to compare public JWKs so callers can determine whether two JWK objects represent the same public key.

This is required when:

- a JWS header includes embedded `jwk`;
- `kid` resolution also returns a public JWK;
- the verifier needs to reject the artifact if the two keys conflict.

The comparison must not rely on JSON property order.

The SDK should also expose or internally use a standards-based thumbprint where appropriate. For JWKs, the preferred compact fingerprint is an RFC 7638 JWK Thumbprint, represented in OMATrust DNS TXT records as:

```txt
jkt=S256:<base64url-thumbprint>
```

The `jkt` value identifies the public key compactly. It does not replace the full JWK when full key material is needed for signature verification.

## 5. Controller Authorization Resolution

The SDK must support authorization checks where both the subject and controller are represented as DIDs or DID URLs.

This authorization layer is separate from JWS signature verification.

### 5.0 Rename

The existing `getAttesterAuthorization` function must be renamed to `getControllerAuthorization`. Associated types must also be renamed:

- `GetAttesterAuthorizationParams` → `GetControllerAuthorizationParams`
- `AttesterAuthorizationResult` → `ControllerAuthorizationResult`

The old names should be preserved as deprecated re-exports for backward compatibility during the alpha period.

The rename reflects that this function checks whether a *controller* DID is authorized for a subject — a concept broader than "attester" authorization and applicable to x402 JWS verification, key pinning, and other trust checks.

### 5.1 Purpose

The authorization utility (`getControllerAuthorization`, renamed from the existing `getAttesterAuthorization`) answers:

```txt
Is this controller authorized for this subject?
```

It does not decide whether a verifier should accept a receipt, review, attestation, or other trust record. It returns an authorization window and supporting evidence. Verifiers apply their own policy.

### 5.2 Inputs

`getControllerAuthorization` should accept:

```ts
{
  subjectDid: string;
  controllerDid: string;
  purpose?: W3CKeyPurpose[];
}
```

Where `purpose` is optional and uses W3C DID verification relationship values:

```ts
type W3CKeyPurpose =
  | "authentication"
  | "assertionMethod"
  | "keyAgreement";
```

If `purpose` is omitted or empty, the SDK must default to:

```ts
["authentication", "assertionMethod"]
```

### 5.3 Supported Subject Identifiers

The subject should usually be a bare DID, such as:

```txt
did:web:api.example.com
```

SDK functions that expect a subject DID must reject DID URLs unless the function explicitly supports DID URL subjects.

### 5.4 Supported Controller Identifiers

Controllers must be durable controller DIDs:

```txt
did:pkh:eip155:1:0x...
did:jwk:<encoded-public-jwk>
```

DID URLs are **not** durable controller DIDs. They are mutable key references that should be resolved to public key material and converted to `did:jwk` before authorization checks.

If a caller has a DID URL such as `did:web:api.example.com#key-1`, they should use `resolveDidUrlControllerDid()` to obtain the derived `did:jwk` and pass that as `controllerDid`.

The `controllerDid` parameter of `getControllerAuthorization` should be `did:pkh` or `did:jwk`, not a DID URL.

### 5.5 Evidence Sources

The authorization utility may use:

- Controller Witness attestations;
- Key Binding attestations;
- live DNS TXT checks;
- live DID document checks;
- live JWKS checks, where applicable.

### 5.6 Key Purpose Matching

When evaluating Key Binding attestations, the SDK must only treat a Key Binding as satisfying the request if its `keyPurpose` contains all requested purposes.

If no matching Key Binding exists, the SDK must report the key-purpose status rather than silently treating the purpose as satisfied.

Recommended status values:

```ts
type KeyPurposeStatus =
  | "matched"
  | "unknown"
  | "mismatch";
```

Meanings:

- `matched`: at least one Key Binding contains all requested purposes.
- `unknown`: no Key Binding was found, so explicit key purpose is unknown.
- `mismatch`: Key Bindings exist, but none contain all requested purposes.

### 5.7 Return Value

The authorization utility should return one computed authorization window plus evidence metadata.

Conceptual result:

```ts
type ControllerAuthorizationResult = {
  authorized: boolean;
  requestedPurpose: W3CKeyPurpose[];
  keyPurposeStatus: "matched" | "unknown" | "mismatch";
  anchoredFrom: bigint | null;
  until: bigint | null;
  currentlyVerified: boolean;
  liveMethod: "dns" | "did-document" | "jwks" | null;
  controllerWitnesses: ControllerWitnessEvidence[];
  keyBindingUid: Hex | null;
  keyBindingUids?: Hex[];
};
```

This type replaces the existing `AttesterAuthorizationResult`.

`anchoredFrom` is the earliest timestamp of durable authorization evidence, usually the first relevant Controller Witness. It is `null` when authorization is only currently verified through live DNS, DID document, or JWKS checks.

`until` is the end of the authorization window. It is `null` when there is no known closing event.

The SDK must not return a confidence score or final verifier policy decision. It must return evidence and window metadata so the verifier can decide how to use it.

### 5.8 Controller Witness as Durable Key Pinning

Controller Witness can be used to durably pin a mutable DID URL key reference to actual public key material.

Example:

```txt
subject:    did:web:api.example.com#key-1
controller: did:jwk:<encoded-public-jwk>
```

This does **not** mean the DID URL is the controller. It means:

```txt
At observedAt, the witness verified that did:web:api.example.com#key-1 resolved to this public key.
```

This is a durable key-pinning relationship. The DID URL is the subject (the mutable reference being pinned), and the `did:jwk` is the controller (the immutable key material it resolved to at that point in time).

This is distinct from broader service authorization:

```txt
subject:    did:web:api.example.com
controller: did:jwk:<encoded-public-jwk>
```

The first form pins a mutable key reference to actual key material. The second form asserts that a controller key is authorized for the service identity.

If a later Controller Witness for the same DID URL subject points to a different `did:jwk` controller, verifiers may interpret that as key rotation and evaluate receipts against the relevant authorization window.

## 6. x402 JWS Offer and Receipt Verification

This section addresses the x402-specific integration work tracked by GitHub issue #2: first-class x402 signed offer/receipt support in the OMATrust SDK.

This section depends on the generic DID URL, JWK, `did:jwk`, and Controller Authorization primitives defined earlier.

The SDK must support x402 JWS offer and receipt artifacts as defined by the x402 Offer and Receipt Extension. The SDK must not define a new x402 wire format.

### 6.1 x402 JWS Artifact Input

The SDK must consume the x402 JWS artifact envelope:

```json
{
  "format": "jws",
  "signature": "<JWS Compact Serialization>"
}
```

For JWS artifacts, the artifact-level `payload` field is not required because the signed payload is encoded inside the JWS compact serialization.

The SDK should validate only the envelope fields needed to determine that the artifact is a JWS x402 offer or receipt, then decode and verify the compact JWS.

### 6.2 JWS Header Handling

The decoded JWS protected header must include:

| Field | Required | Meaning |
| --- | --- | --- |
| `alg` | Yes | JWS signing algorithm |
| `kid` | Conditional | DID URL identifying the signing key |
| `jwk` | Conditional | Public JWK for immediate signature verification |

The SDK must follow the x402 extension rule that `alg` is required and at least one of `kid` or `jwk` must be present.

If `jwk` is present, the SDK may verify the signature without resolving `kid`.

If `kid` is present, the SDK may resolve it to public key material. The resolved public key should be converted to `did:jwk` for use as the durable controller DID in downstream authorization checks. `kid` itself is a mutable key reference, not a controller DID.

If both `kid` and `jwk` are present and the SDK resolves `kid`, the resolved key must match the embedded `jwk`. If they conflict, verification must fail.

### 6.3 JWS Payload Handling

The SDK must decode the JWS payload and expose it to callers.

This section partially addresses GitHub issue #2. Full x402 offer/receipt payload support belongs to that issue. This feature includes the payload handling needed for the JWS/JWK path so that signature verification and later authorization checks have access to the signed data.

For offers, the decoded payload should contain at least:

- `version`
- `resourceUrl`
- `scheme`
- `network`
- `asset`
- `payTo`
- `amount`

Optional offer field:

- `validUntil`

For receipts, the decoded payload should contain at least:

- `version`
- `network`
- `resourceUrl`
- `payer`
- `issuedAt`

Optional receipt field:

- `transaction`

The SDK must use the decoded JWS payload exactly as signed. It must not reconstruct payload fields from surrounding x402 context.

The most important fields for downstream OMATrust authorization are:

- `resourceUrl`, to identify the service/resource associated with the signed artifact;
- `issuedAt`, for receipt-time authorization-window checks when present.

### 6.4 JWS Signature Verification Paths

The SDK must support two JWS signature verification paths.

#### 6.4.1 Embedded JWK Path

This path applies when the JWS header contains `jwk`.

Expected behavior:

1. Parse compact JWS.
2. Decode protected header.
3. Decode payload.
4. Require `alg`.
5. Validate the embedded public `jwk`.
6. Reject the JWS if the embedded `jwk` contains private key material.
7. Verify the JWS signature using the embedded `jwk`.
8. Return a structured signature verification result.

The SDK must not require live DID resolution for signature verification when `jwk` is present.

#### 6.4.2 KID Resolution Path

This path applies when the JWS header contains `kid` and no `jwk`.

Expected behavior:

1. Parse compact JWS.
2. Decode protected header.
3. Decode payload.
4. Require `alg`.
5. Require `kid`.
6. Parse `kid` as a DID URL.
7. Resolve `kid` to public key material.
8. Convert the resolved public key to `did:jwk` for downstream authorization.
9. Verify the JWS signature using the resolved public key.
10. Return a structured signature verification result including the derived `did:jwk`.

If the SDK cannot resolve `kid`, verification must fail for this path.

### 6.5 Structured JWS Signature Verification Result

JWS verification functions must return structured results describing the outcome of JWS parsing, payload decoding, and cryptographic signature verification.

This result is not an authorization result. It does not determine whether the signing key was authorized to act for the service identified by `resourceUrl`.

A successful result must include at least:

- validity status;
- decoded JWS header;
- decoded JWS payload;
- `kid`, if present (as a key reference, not a controller DID);
- public JWK used for signature verification;
- source of the public key:
  - `embedded-jwk`;
  - `kid-resolution`;
- `did:jwk` representation of the public key — this is the durable controller DID for downstream authorization checks.

A failed result must include:

- validity status;
- failure code;
- failure message.

The result should give callers enough information to perform later authorization checks, such as:

- deriving the service subject from signed `resourceUrl`;
- using the returned `did:jwk` as the `controllerDid` for `getControllerAuthorization`;
- checking Controller Witness or Key Binding records;
- evaluating whether authorization existed at `issuedAt` for receipts.

The exact TypeScript shape may follow existing SDK conventions.

### 6.6 Integration with x402 Proofs

The SDK currently has x402 proof helper behavior. This feature must make x402 JWS proof verification meaningful.

Expected behavior:

- x402 offer proofs with `format: "jws"` are cryptographically verified.
- x402 receipt proofs with `format: "jws"` are cryptographically verified.
- x402 offer proofs with `format: "eip712"` are cryptographically verified.
- x402 receipt proofs with `format: "eip712"` are cryptographically verified.
- `verifyProof` must not treat x402 proofs as shape-only checks when a recognized format is present.
- Existing helper names should remain compatible where practical.
- Backward compatibility should be preserved where it does not weaken verification.

This integration should be implemented after the lower-level DID URL, JWK, `did:jwk`, and authorization primitives are in place.

## 6b. x402 EIP-712 Offer and Receipt Verification

This section defines EIP-712 signature verification for x402 signed offers and receipts.

EIP-712 is the simpler verification path: the signer address is recovered directly from the signature. There is no DID URL resolution or JWK handling.

### 6b.1 x402 EIP-712 Artifact Input

The SDK must consume the x402 EIP-712 artifact envelope:

```json
{
  "format": "eip712",
  "payload": { ... },
  "signature": "0x..."
}
```

For EIP-712 artifacts:
- `payload` is REQUIRED and contains the canonical payload fields.
- `signature` is a hex-encoded ECDSA signature (`0x`-prefixed, 65 bytes: r+s+v).

### 6b.2 EIP-712 Domain

All x402 EIP-712 signatures use a fixed domain:

| Field     | Value                                    |
| --------- | ---------------------------------------- |
| `name`    | `"x402 offer"` or `"x402 receipt"`       |
| `version` | `"1"`                                    |
| `chainId` | `1` (constant — off-chain signing only)  |

The `chainId` is hardcoded to `1` (Ethereum mainnet). EIP-712 is used purely as an off-chain signing format. The actual payment network is identified by the `network` field in the payload.

### 6b.3 Canonical EIP-712 Types

The SDK must use the canonical EIP-712 types defined in the x402 Offer and Receipt Extension specification. These types are normative and must not be transmitted on the wire.

**Offer (primaryType: "Offer"):**

```
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
```

**Receipt (primaryType: "Receipt"):**

```
Receipt: [
  { name: "version", type: "uint256" },
  { name: "network", type: "string" },
  { name: "resourceUrl", type: "string" },
  { name: "payer", type: "string" },
  { name: "issuedAt", type: "uint256" },
  { name: "transaction", type: "string" }
]
```

### 6b.4 Optional Field Handling

EIP-712 requires all fields to be present in the signed message (fixed schema). Optional fields use zero-values when absent:

- `validUntil`: `0` means absent.
- `transaction`: `""` (empty string) means absent.

Verifiers MUST treat zero-value optional fields as equivalent to absence.

### 6b.5 Payload Validation

For EIP-712 offers, the `payload` object must contain:

- `version` (number)
- `resourceUrl` (string)
- `scheme` (string)
- `network` (string)
- `asset` (string)
- `payTo` (string)
- `amount` (string)

Optional: `validUntil` (number, defaults to `0` if absent).

For EIP-712 receipts, the `payload` object must contain:

- `version` (number)
- `network` (string)
- `resourceUrl` (string)
- `payer` (string)
- `issuedAt` (number)

Optional: `transaction` (string, defaults to `""` if absent).

The SDK must use the `payload` object exactly as transmitted. It must not reconstruct payload fields from surrounding x402 context.

### 6b.6 EIP-712 Verification Behavior

Expected behavior:

1. Validate the artifact envelope: `format` is `"eip712"`, `payload` is a non-null object, `signature` is a non-empty hex string.
2. Validate required payload fields for the artifact type (offer or receipt).
3. Construct the EIP-712 typed data using the canonical domain and types for the artifact type.
4. Verify the signature and recover the signer address using `verifyTypedData` (ethers).
5. Return a structured result with the recovered signer address and decoded payload.

### 6b.7 Structured EIP-712 Verification Result

A successful result must include:

- validity status;
- decoded payload;
- recovered signer address (checksummed EVM address);
- artifact type (`"offer"` or `"receipt"`).

A failed result must include:

- validity status;
- failure code;
- failure message.

### 6b.8 Signer Authorization Is External

EIP-712 verification only proves the signature is valid and returns the recovered signer address. It does NOT determine whether the signer is authorized.

The simplest authorization check: compare the recovered signer to `payload.payTo`. If they match, the payment recipient signed the artifact.

For more complex authorization, callers can:
1. Convert the signer address to `did:pkh:eip155:1:<address>`.
2. Derive the subject DID from `resourceUrl` (e.g., `did:web:<domain>`).
3. Call `getControllerAuthorization({ subjectDid, controllerDid })`.

### 6b.9 Relationship to JWS Verification

Both EIP-712 and JWS verification share the same design principle: signature verification is separate from authorization.

Key differences:

| Aspect | JWS | EIP-712 |
| --- | --- | --- |
| Key material | JWK (embedded or resolved) | Recovered from signature |
| Controller DID | `did:jwk` | `did:pkh:eip155:1:<address>` |
| DID resolution | May be needed (kid path) | Never needed |
| Offline verification | Supported (embedded jwk) | Always offline |
| Payload location | Inside JWS compact string | Separate `payload` field |

## 7. Developer Documentation Requirements

Developer docs must explain:

1. The difference between a bare DID and a DID URL.
2. That DID URLs are mutable key references, not durable controller DIDs.
3. That `parseDidWeb` or equivalent bare DID parsers must reject DID URLs.
4. Why `did:jwk` is used for JWS public keys and as the durable controller DID.
5. How to resolve a DID URL to public key material and derive a `did:jwk`.
6. That `did:jwk` (not the DID URL) should be passed to `getControllerAuthorization`.
7. How to convert public JWKs to and from `did:jwk`.
8. How Controller Witness can durably bind a DID URL to a public key (key-pinning).
9. How key rotation affects historical verification.
10. The difference between signature verification and authorization.
11. The x402 JWS verification paths:
    - `jwk` embedded in header;
    - `kid` resolution → `did:jwk` derivation.
12. The x402 EIP-712 verification path:
    - signer recovery from signature;
    - canonical domain and types;
    - `did:pkh` as the controller DID for EIP-712 signers.
13. That `jwk` enables signature verification but does not establish authorization.
14. That EIP-712 signer recovery does not establish authorization.
15. That verifiers choose their own authorization policy.
16. How `verifyProof` handles both JWS and EIP-712 x402 proofs.

## 8. Acceptance Criteria

### 8.1 DID URL Parsing

- SDK parses `did:web:api.example.com#key-1`.
- SDK returns base DID and fragment.
- SDK rejects malformed DID URLs.
- SDK functions that expect bare subject DIDs reject DID URLs.

### 8.2 `did:jwk`

- SDK validates a structurally valid `did:jwk`.
- SDK rejects malformed base64url.
- SDK rejects decoded JSON without `kty`.
- SDK rejects JWKs containing private key field `d`.
- SDK converts public JWK to `did:jwk`.
- SDK converts `did:jwk` back to public JWK.

### 8.3 JWK Comparison and Thumbprint

- SDK treats equivalent public JWKs as equal despite property ordering.
- SDK rejects mismatched public keys.
- SDK rejects private key material.
- SDK supports or internally uses an RFC 7638 JWK Thumbprint where appropriate.
- SDK can represent compact public-key fingerprints as `jkt=S256:<base64url-thumbprint>` where DNS TXT proof logic requires it.

### 8.4 DID URL Key Resolution

- SDK resolves mocked `did:web#fragment` to `publicKeyJwk`.
- SDK converts resolved `publicKeyJwk` to `did:jwk`.
- SDK returns the derived `did:jwk` as `controllerDid` from resolution helpers.
- SDK fails when the fragment is missing and a fragment is required.
- SDK fails when no verification method matches.
- SDK fails clearly on unsupported DID methods.
- SDK does not treat DID URLs as durable controller DIDs when a resolved `did:jwk` is available.

### 8.5 Controller Authorization

- `getAttesterAuthorization` is renamed to `getControllerAuthorization`.
- `GetAttesterAuthorizationParams` is renamed to `GetControllerAuthorizationParams`.
- `AttesterAuthorizationResult` is renamed to `ControllerAuthorizationResult`.
- Old names are preserved as deprecated re-exports.
- SDK accepts `controllerDid` as durable DIDs: `did:pkh` or `did:jwk`.
- SDK does not accept raw DID URLs as `controllerDid` — callers must resolve to `did:jwk` first.
- SDK uses `did:jwk` as the downstream controller DID for authorization checks after DID URL resolution.
- SDK rejects DID URLs when a bare subject DID is expected.
- SDK supports optional W3C `purpose` filtering.
- SDK defaults omitted purpose to `authentication` and `assertionMethod`.
- SDK reports `keyPurposeStatus` as `matched`, `unknown`, or `mismatch`.
- SDK returns structured Controller Witness evidence, not only witness UIDs.
- SDK returns `anchoredFrom` and `until` for the computed authorization window.
- Controller Witness key-pinning examples use `subject: did:web:api.example.com#key-1` / `controller: did:jwk:<encoded-public-jwk>`.

### 8.6 JWS Signature Verification

- SDK verifies a JWS offer with embedded `jwk`.
- SDK verifies a JWS receipt with embedded `jwk`.
- SDK verifies a JWS offer by resolving `kid` when no embedded `jwk` exists.
- SDK verifies a JWS receipt by resolving `kid` when no embedded `jwk` exists.
- SDK rejects missing `alg`.
- SDK rejects a JWS header missing both `kid` and `jwk`.
- SDK accepts a JWS header with `jwk` and no `kid` for signature verification.
- SDK accepts a JWS header with `kid` and no `jwk` when `kid` can be resolved.
- SDK accepts a JWS header with both `kid` and `jwk` when they match.
- SDK rejects a JWS header with both `kid` and `jwk` when resolved key material conflicts with embedded `jwk`.
- SDK rejects malformed compact JWS.
- SDK rejects invalid signatures.
- SDK rejects private JWK in header.
- SDK validates required offer payload fields.
- SDK validates required receipt payload fields.
- SDK does not require artifact-level `payload` for JWS artifacts.

### 8.7 x402 Proof Integration

- `verifyProof` cryptographically verifies `x402-offer` when the artifact is JWS.
- `verifyProof` cryptographically verifies `x402-receipt` when the artifact is JWS.
- `verifyProof` cryptographically verifies `x402-offer` when the artifact is EIP-712.
- `verifyProof` cryptographically verifies `x402-receipt` when the artifact is EIP-712.
- Existing x402 wrapper helpers remain usable.
- Documentation explains any compatibility or migration behavior.

### 8.8 EIP-712 Signature Verification

- SDK verifies an EIP-712 offer and recovers the signer address.
- SDK verifies an EIP-712 receipt and recovers the signer address.
- SDK uses the canonical domain: `name` is `"x402 offer"` or `"x402 receipt"`, `version` is `"1"`, `chainId` is `1`.
- SDK uses the canonical EIP-712 types from the x402 Offer and Receipt Extension spec.
- SDK rejects artifacts with missing `payload`.
- SDK rejects artifacts with missing or empty `signature`.
- SDK rejects invalid signatures (recovery fails or produces unexpected result).
- SDK validates required offer payload fields: `version`, `resourceUrl`, `scheme`, `network`, `asset`, `payTo`, `amount`.
- SDK validates required receipt payload fields: `version`, `network`, `resourceUrl`, `payer`, `issuedAt`.
- SDK treats `validUntil: 0` as absent for offers.
- SDK treats `transaction: ""` as absent for receipts.
- SDK does not require artifact-level `payload` for JWS artifacts (only EIP-712 requires it).
- SDK returns the recovered signer address in the verification result.
- SDK does not make authorization decisions — signer recovery is not authorization.

## 9. Non-Goals and Constraints

- Do not implement EIP-712 verification changes in this feature.
- Do not implement full `did:key` support unless already available.
- Do not treat embedded `jwk` as authorization.
- Do not require Controller Witness for all JWS verification.
- Do not implement subscription or payment logic.
- Do not implement social-handle witness automation.
- Do not refactor the entire authorization system beyond the DID/JWK/controller behavior described in this specification.
