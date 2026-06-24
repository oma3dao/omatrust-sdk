/**
 * DID Method Migration Helpers
 *
 * Provides conversion functions for deprecated DID methods:
 * - did:ethr → did:pkh:eip155 (wallet addresses)
 * - did:key → did:jwk (non-blockchain keys)
 *
 * These methods are being deprecated in favor of their canonical replacements.
 * Use these functions to convert existing identifiers to the preferred format.
 */

import { base58btc } from "multiformats/bases/base58";
import { isAddress, getAddress } from "ethers";
import { base64url } from "jose";
import { OmaTrustError } from "../shared/errors";
import { jwkToDidJwk } from "./jwk";

// ---------------------------------------------------------------------------
// did:ethr → did:pkh
// ---------------------------------------------------------------------------

/**
 * Convert a did:ethr DID to the equivalent did:pkh:eip155 DID.
 *
 * did:ethr format: did:ethr:<address> or did:ethr:<chainId>:<address>
 * did:pkh format:  did:pkh:eip155:<chainId>:<address>
 *
 * If the did:ethr DID omits the chain ID, defaults to chain 1 (Ethereum mainnet).
 *
 * @param did - A did:ethr DID string
 * @returns The equivalent did:pkh:eip155 DID
 * @throws OmaTrustError if the input is not a valid did:ethr DID
 */
export function didEthrToDidPkh(did: string): string {
  if (typeof did !== "string" || !did.startsWith("did:ethr:")) {
    throw new OmaTrustError("INVALID_DID", "Expected a did:ethr DID", { did });
  }

  const remainder = did.slice("did:ethr:".length);
  if (!remainder) {
    throw new OmaTrustError("INVALID_DID", "Missing identifier in did:ethr DID", { did });
  }

  let chainId: string;
  let address: string;

  // Check for chain-specific format: did:ethr:<network>:<address>
  // Networks can be hex chain IDs (0x1), named networks, or numeric
  const parts = remainder.split(":");
  if (parts.length === 1) {
    // did:ethr:<address> — default to chain 1
    chainId = "1";
    address = parts[0];
  } else if (parts.length === 2) {
    // did:ethr:<chainId>:<address>
    const rawChainId = parts[0];
    address = parts[1];

    // Parse chain ID: support hex (0x1), numeric, and named networks
    if (rawChainId.startsWith("0x")) {
      chainId = String(parseInt(rawChainId, 16));
    } else if (/^\d+$/.test(rawChainId)) {
      chainId = rawChainId;
    } else {
      // Named networks — map common names
      const networkMap: Record<string, string> = {
        mainnet: "1",
        goerli: "5",
        sepolia: "11155111",
        polygon: "137",
        arbitrum: "42161",
        optimism: "10",
        base: "8453",
      };
      const mapped = networkMap[rawChainId.toLowerCase()];
      if (!mapped) {
        throw new OmaTrustError(
          "INVALID_DID",
          `Unknown did:ethr network "${rawChainId}"`,
          { did, network: rawChainId }
        );
      }
      chainId = mapped;
    }
  } else {
    throw new OmaTrustError("INVALID_DID", "Invalid did:ethr format", { did });
  }

  if (!isAddress(address)) {
    throw new OmaTrustError("INVALID_DID", "Invalid Ethereum address in did:ethr DID", {
      did,
      address,
    });
  }

  const checksummed = getAddress(address);
  return `did:pkh:eip155:${chainId}:${checksummed.toLowerCase()}`;
}

// ---------------------------------------------------------------------------
// did:key → did:jwk
// ---------------------------------------------------------------------------

/**
 * Multicodec prefixes for key types used in did:key.
 * Each prefix identifies the key algorithm and curve.
 */
const MULTICODEC_KEY_TYPES: Record<number, { kty: string; crv: string; coordSize?: number }> = {
  // Ed25519 public key: 0xed (varint encoded as [0xed, 0x01])
  0xed: { kty: "OKP", crv: "Ed25519" },
  // X25519 public key: 0xec (varint encoded as [0xec, 0x01])
  0xec: { kty: "OKP", crv: "X25519" },
  // secp256k1 public key (compressed): 0xe7 (varint encoded as [0xe7, 0x01])
  0xe7: { kty: "EC", crv: "secp256k1", coordSize: 33 },
  // P-256 public key (compressed): 0x80 0x24 (varint 0x1200)
  0x1200: { kty: "EC", crv: "P-256", coordSize: 33 },
  // P-384 public key (compressed): 0x81 0x24 (varint 0x1201)
  0x1201: { kty: "EC", crv: "P-384", coordSize: 49 },
};

/**
 * Read a varint from a byte array (unsigned LEB128).
 * Returns the decoded value and the number of bytes consumed.
 */
function readVarint(bytes: Uint8Array, offset: number): { value: number; bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;

  while (offset + bytesRead < bytes.length) {
    const byte = bytes[offset + bytesRead];
    value |= (byte & 0x7f) << shift;
    bytesRead++;
    if ((byte & 0x80) === 0) {
      return { value, bytesRead };
    }
    shift += 7;
    if (shift > 28) {
      throw new OmaTrustError("INVALID_DID", "Varint too long in did:key multicodec prefix");
    }
  }

  throw new OmaTrustError("INVALID_DID", "Truncated varint in did:key multicodec prefix");
}

/**
 * Decompress a compressed EC public key to x, y coordinates.
 * Supports secp256k1, P-256, and P-384 (all use the same compressed format).
 *
 * For OKP keys (Ed25519, X25519), the raw bytes ARE the public key — no decompression needed.
 */
function decompressEcKey(
  compressedKey: Uint8Array,
  crv: string
): { x: Uint8Array; y: Uint8Array } {
  // For EC curves, a compressed key is 33 bytes (P-256, secp256k1) or 49 bytes (P-384)
  // Format: 0x02/0x03 prefix + x-coordinate
  // We can't decompress to y without doing the curve math, but for did:jwk we can
  // use the compressed representation directly IF the curve supports it.
  // However, JWK requires uncompressed x and y for EC keys.
  //
  // Since full decompression requires curve-specific modular arithmetic that's complex
  // to implement in pure JS, and the did:key spec stores compressed keys, we'll use
  // a simpler approach: for secp256k1 keys (the most common case in did:ethr migration),
  // we store just the x-coordinate and mark it with the compression prefix.
  //
  // Actually, for did:key → did:jwk conversion, the standard approach is:
  // - Ed25519/X25519: x = raw 32-byte key (base64url encoded)
  // - EC keys: requires the full uncompressed point
  //
  // The practical path: since did:key typically stores compressed EC keys,
  // and converting compressed → uncompressed requires elliptic curve operations,
  // we reject compressed EC keys that we can't fully decompress and suggest
  // using did:pkh for EVM keys instead.

  throw new OmaTrustError(
    "UNSUPPORTED_KEY_TYPE",
    `Cannot convert compressed EC key (${crv}) from did:key to did:jwk. ` +
      `Decompressing EC points requires elliptic curve arithmetic. ` +
      `For EVM keys, use didEthrToDidPkh() instead.`,
    { crv, keyLength: compressedKey.length }
  );
}

/**
 * Convert a did:key DID to the equivalent did:jwk DID.
 *
 * did:key encodes a public key as a multicodec-prefixed, base58btc-encoded value.
 * This function decodes the key, identifies the algorithm from the multicodec prefix,
 * constructs a JWK, and wraps it as did:jwk.
 *
 * Supported key types:
 * - Ed25519 (multicodec 0xed)
 * - X25519 (multicodec 0xec)
 *
 * EC keys (secp256k1, P-256, P-384) are stored compressed in did:key and require
 * elliptic curve decompression to produce a valid JWK. This is not supported;
 * use didEthrToDidPkh() for EVM wallet keys instead.
 *
 * @param did - A did:key DID string
 * @returns The equivalent did:jwk DID
 * @throws OmaTrustError if the input is invalid or uses an unsupported key type
 */
export function didKeyToDidJwk(did: string): string {
  if (typeof did !== "string" || !did.startsWith("did:key:")) {
    throw new OmaTrustError("INVALID_DID", "Expected a did:key DID", { did });
  }

  const identifier = did.slice("did:key:".length);
  if (!identifier || !identifier.startsWith("z")) {
    throw new OmaTrustError(
      "INVALID_DID",
      "did:key identifier must start with 'z' (base58btc multibase prefix)",
      { did }
    );
  }

  // Decode base58btc (the 'z' prefix is the multibase indicator)
  let decoded: Uint8Array;
  try {
    decoded = base58btc.decode(identifier);
  } catch (err) {
    throw new OmaTrustError(
      "INVALID_DID",
      "Failed to decode base58btc from did:key identifier",
      { did, cause: err }
    );
  }

  if (decoded.length < 3) {
    throw new OmaTrustError("INVALID_DID", "did:key decoded bytes too short", { did });
  }

  // Read the multicodec prefix (varint)
  const { value: codecValue, bytesRead } = readVarint(decoded, 0);

  const keyType = MULTICODEC_KEY_TYPES[codecValue];
  if (!keyType) {
    throw new OmaTrustError(
      "UNSUPPORTED_KEY_TYPE",
      `Unsupported multicodec key type 0x${codecValue.toString(16)} in did:key`,
      { did, codec: `0x${codecValue.toString(16)}` }
    );
  }

  // Extract the raw key bytes after the multicodec prefix
  const keyBytes = decoded.slice(bytesRead);

  if (keyType.kty === "OKP") {
    // Ed25519 or X25519: raw 32-byte key → JWK with x field
    if (keyBytes.length !== 32) {
      throw new OmaTrustError(
        "INVALID_DID",
        `Expected 32-byte ${keyType.crv} key, got ${keyBytes.length} bytes`,
        { did, crv: keyType.crv }
      );
    }

    const jwk = {
      kty: keyType.kty,
      crv: keyType.crv,
      x: base64url.encode(keyBytes),
    };

    return jwkToDidJwk(jwk);
  }

  // EC keys — compressed, need decompression
  return decompressEcKey(keyBytes, keyType.crv).x.toString(); // This throws
}
