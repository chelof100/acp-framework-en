#!/usr/bin/env node
/**
 * Compute ACP AgentID from a seed (hex) and print it to stdout.
 *
 * Usage:
 *   node compute_agent_id.js <seed_hex_32_bytes>
 *
 * Requires Node.js >= 16 (built-in crypto module).
 */
"use strict";
const { createHash } = require("crypto");
const { generateKeyPairSync } = require("crypto");

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58Encode(buf) {
  let n = BigInt("0x" + buf.toString("hex") || "0");
  const result = [];
  while (n > 0n) {
    const rem = Number(n % 58n);
    n = n / 58n;
    result.push(ALPHABET[rem]);
  }
  for (const b of buf) {
    if (b === 0) result.push(ALPHABET[0]);
    else break;
  }
  return result.reverse().join("");
}

function derivePublicKey(seedHex) {
  // Node.js doesn't expose raw Ed25519 seed→pubkey directly before Node 23,
  // but we can use the SubtleCrypto API via generateKeyPairSync with a trick:
  // Instead, use the webcrypto subtle API available in Node >= 16.
  // For simplicity, call out to the pure-JS implementation via tweetnacl if available,
  // or use Node's built-in key import.
  const seed = Buffer.from(seedHex, "hex");
  if (seed.length !== 32) {
    process.stderr.write("seed must be 32 bytes\n");
    process.exit(1);
  }

  // Node >= 16: importKey from JWK or PKCS8 — easiest path is PKCS8 DER
  // Ed25519 PKCS8 structure: 04 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes seed>
  const pkcs8Header = Buffer.from(
    "302e020100300506032b657004220420",
    "hex"
  );
  const pkcs8Key = Buffer.concat([pkcs8Header, seed]);

  const { privateKey } = require("crypto").createPrivateKey({
    key: pkcs8Key,
    format: "der",
    type: "pkcs8",
  });

  const pubKey = require("crypto")
    .createPublicKey(privateKey)
    .export({ type: "spki", format: "der" });

  // SPKI for Ed25519: 30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte pubkey>
  const rawPub = pubKey.subarray(pubKey.length - 32);
  return rawPub;
}

const args = process.argv.slice(2);
if (args.length !== 1) {
  process.stderr.write("usage: compute_agent_id.js <seed_hex>\n");
  process.exit(1);
}

const pub = derivePublicKey(args[0]);
const digest = createHash("sha256").update(pub).digest();
process.stdout.write(base58Encode(digest) + "\n");
