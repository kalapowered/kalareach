// Makes `signed-matrix.json`: a release matrix, the bytes the website's publisher signs for it, and
// an Ed25519 signature over them.
//
// The bytes come from the publisher's own encoder and its own field order; the signature comes
// from `node:crypto`. Nothing here is the Rust code the vector checks. Run it with Node 22:
//
//   node --experimental-transform-types make-vector.mjs <path to cbor.ts> <web commit> > signed-matrix.json
//
// `cbor.ts` is `packages/service-contracts/src/cbor.ts` of the web repository at <web commit>,
// which has no imports of its own. `signingInput` below is `signingInput` of
// `workers/api/src/ops/release.ts` at the same commit, with the types removed.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [, , encoderPath, webCommit] = process.argv;
if (!encoderPath || !webCommit) {
  console.error('usage: make-vector.mjs <path to cbor.ts> <web commit>');
  process.exit(2);
}
const { encodeCbor } = await import(pathToFileURL(resolve(encoderPath)).href);

const matrix = {
  schemaVersion: 1,
  revision: '2',
  issuedAt: '2026-10-27',
  note: 'Prose the signature does not cover.',
  installedClientWindowDays: 90,
  alternatives: ['direct', 'self-hosted-relay', 'self-hosted-discovery'],
  tiers: [
    {
      id: '2026-10-compatible',
      compatible: true,
      note: 'The tier every supported client can reach.',
      client: { minimum: '0.77.0', maximum: '0.79.99' },
      relay: { minimum: '1.2.0', maximum: '1.2.99' },
      discovery: { minimum: '1.2.0', maximum: '1.2.99' },
    },
    {
      id: '2026-10-current',
      compatible: false,
      note: 'What a current client is served by.',
      client: { minimum: ' 0.78.0', maximum: '0.78.99 ' },
      relay: { minimum: '1.3.0', maximum: '1.3.99' },
      discovery: { minimum: '1.2.0', maximum: '1.3.99' },
    },
  ],
};

function signingInput(matrix) {
  const range = (held) => ({ minimum: held.minimum, maximum: held.maximum });
  const tiers = matrix.tiers.map((tier) => ({
    id: tier.id,
    compatible: tier.compatible,
    client: range(tier.client),
    relay: range(tier.relay),
    discovery: range(tier.discovery),
  }));
  return encodeCbor({
    'kr-release-matrix/1': {
      schema_version: matrix.schemaVersion,
      revision: matrix.revision,
      issued_at: matrix.issuedAt,
      installed_client_window_days: matrix.installedClientWindowDays,
      alternatives: [...matrix.alternatives],
      tiers,
    },
  });
}

// The publisher imports a 32-byte seed inside this PKCS#8 wrapper.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// A fixed seed, so the vector is the same every time it is made.
const seed = createHash('sha256').update('kr-release-matrix-test-vector/1').digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, seed]),
  format: 'der',
  type: 'pkcs8',
});
const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const publicKey = publicDer.subarray(publicDer.length - 32);

const input = Buffer.from(signingInput(matrix));
const signature = sign(null, input, privateKey);
const base64url = (bytes) => Buffer.from(bytes).toString('base64url');

process.stdout.write(
  JSON.stringify(
    {
      web_commit: webCommit,
      public_key: base64url(publicKey),
      signing_input_hex: input.toString('hex'),
      published: {
        matrix,
        signature: base64url(signature),
        signing_key: base64url(publicKey),
        serve: null,
      },
    },
    null,
    2,
  ) + '\n',
);
