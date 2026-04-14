# Widget Signing Bridge — Plan

Status: Implemented

This feature is part of the OMATrust Review Widget system. The full build plan lives in:

→ [omatrust-widgets/docs/features/review-widget/plan.md](https://github.com/oma3dao/omatrust-widgets/blob/main/docs/features/review-widget/plan.md)

## SDK scope

The SDK provides:

1. `createSigningBridge()` — async factory that sets up the host-side postMessage bridge
2. Trust policy fetcher — loads allowed contracts, schemas, and origins from `api.omatrust.org`
3. EAS request validation — validates every signing request before calling the wallet
4. Protocol types and constants — shared message type definitions
