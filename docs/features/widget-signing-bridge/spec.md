# Widget Signing Bridge — Spec

Status: Implemented

## Goal

Provide a secure, validated postMessage bridge between a host page and an embedded OMATrust widget iframe. The bridge handles the handshake, validates signing requests against the OMA3 trust policy, and forwards valid requests to the host's wallet.

## postMessage Protocol

This is the canonical protocol definition. All implementations (widget-side and host-side) must conform to this spec.

### Message types

```
Widget → Host:   { type: "omatrust:ready" }
Host → Widget:   { type: "omatrust:hostReady" }

Widget → Host:   { type: "omatrust:signTypedData", id: string, domain: object, types: object, message: object }
Host → Widget:   { type: "omatrust:signature", id: string, signature: string }
Host → Widget:   { type: "omatrust:signatureError", id: string, error: string }

Widget → Host:   { type: "omatrust:close" }
```

### Handshake

1. Widget sends `omatrust:ready` on load, retries at 500ms, 1s, and 2s
2. Host responds with `omatrust:hostReady`
3. If no response within 3 seconds, widget falls back to basic mode (own wallet connect)

### Signing flow

1. Widget sends `omatrust:signTypedData` with a unique `id` (UUID) and the EIP-712 typed data
2. Host validates the request (see validation rules below)
3. Host calls the wallet's `signTypedData` and returns `omatrust:signature` with the same `id`
4. On error, host returns `omatrust:signatureError` with the same `id` and an error message

### Close

Widget sends `omatrust:close` when the user clicks Cancel or Done. Host should close the modal/iframe.

## Trust Policy

The bridge fetches the OMA3 trust policy from `https://api.omatrust.org/v1/trust-policy` on creation.

### Policy shape

```json
{
  "version": 1,
  "updatedAt": "2026-04-13T00:00:00Z",
  "widgetOrigins": [],
  "chains": {
    "66238": {
      "name": "OMAchain Testnet",
      "easContract": "0x8835...",
      "schemas": ["0x7ab3...", "0x26e2...", "0x807b...", "0xc814..."]
    }
  }
}
```

### Fail-closed behavior

If the trust policy cannot be fetched, `createSigningBridge` throws and the bridge does not start. No signing requests are processed without a valid policy.

## Validation Rules

Every `omatrust:signTypedData` request is validated before the wallet is called.

### Origin check

Message origin must be:
- A subdomain of the trust policy domain (`*.omatrust.org`), OR
- Listed in the policy's `widgetOrigins` array, OR
- The `devOriginOverride` (for local development only)

### Source check

`event.source` must equal the `contentWindow` of the iframe element resolved by `document.getElementById(iframeId)` at message time. The element is looked up lazily on each message, so the bridge works even if the iframe is mounted after the bridge is created.

### EAS request validation

| Field                      | Check                                              |
|----------------------------|----------------------------------------------------|
| `domain.name`              | Must be `"EAS"`                                    |
| `domain.version`           | Must be `"1.4.0"`                                  |
| `domain.chainId`           | Must be a positive integer                         |
| `domain.verifyingContract` | Must be a valid hex address AND in the trust policy |
| `message.schema`           | Must be a valid bytes32 AND in the trust policy     |
| `message.attester`         | Must be a valid hex address                        |
| `message.deadline`         | Must be in the future                              |
| `id`                       | Must be a non-empty string                         |

### Rejection behavior

If any check fails, the bridge sends `omatrust:signatureError` with a descriptive reason and never calls the wallet.

## API

### `createSigningBridge(options): Promise<SigningBridge>`

| Option              | Type                                          | Required | Description                                    |
|---------------------|-----------------------------------------------|----------|------------------------------------------------|
| `iframeId`          | `string`                                      | Yes      | The ID of the widget iframe element            |
| `signTypedData`     | `(domain, types, message) => Promise<string>` | Yes      | Wallet signing callback                        |
| `devOriginOverride` | `string`                                      | No       | Override origin for local dev                  |

Returns `SigningBridge` with a `destroy()` method to remove listeners.

## Acceptance Criteria

- [ ] Bridge fetches trust policy on creation
- [ ] Bridge rejects requests from untrusted origins
- [ ] Bridge rejects requests where `event.source !== iframe.contentWindow`
- [ ] Bridge rejects requests with invalid EAS domain fields
- [ ] Bridge rejects requests with contracts not in the trust policy
- [ ] Bridge rejects requests with schemas not in the trust policy
- [ ] Bridge rejects requests with expired deadlines
- [ ] Bridge calls `signTypedData` callback only after all checks pass
- [ ] Bridge returns signature to the widget via `omatrust:signature`
- [ ] Bridge returns errors via `omatrust:signatureError`
- [ ] Bridge responds to `omatrust:ready` with `omatrust:hostReady`
- [ ] `destroy()` removes all event listeners
- [ ] Bridge throws if trust policy fetch fails (fail closed)

## Edge Cases

- Widget sends `omatrust:ready` before bridge is created → bridge responds on next retry
- Iframe remounts (React key change) → iframe resolved by ID at message time, always current
- Multiple concurrent signing requests → each has a unique `id`, responses are correlated
- Trust policy cache expires → next `createSigningBridge` call fetches fresh
- `devOriginOverride` set in production → only affects origin check, all other validation still applies
