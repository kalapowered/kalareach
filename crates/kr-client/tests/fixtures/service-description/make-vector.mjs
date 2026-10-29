// Makes `signed-description.json`: a service description, the bytes the website's publisher signs
// for it, and an Ed25519 signature over them. It also keeps the release matrix's signature for the
// same key and the bytes that signature covers, so that a test can offer each signature for the
// other's bytes.
//
// The bytes come from the publisher's own encoder and its own field order; the signatures come
// from `node:crypto`. Nothing here is the Rust code the vector checks. Run it with Node 22:
//
//   node --experimental-transform-types make-vector.mjs <path to cbor.ts> <web commit> > signed-description.json
//
// `cbor.ts` is `packages/service-contracts/src/cbor.ts` of the web repository at <web commit>,
// which has no imports of its own. `descriptionSigningInput` below is
// `serviceDescriptionSigningInput` of `packages/service-contracts/src/service-description.ts` at
// the same commit, with the types removed (the website's suite pins its bytes for both descriptions
// below), and `matrixSigningInput` is `signingInput` of `workers/api/src/ops/release.ts`.

import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

const [, , encoderPath, webCommit] = process.argv;
if (!encoderPath || !webCommit) {
  console.error('usage: make-vector.mjs <path to cbor.ts> <web commit>');
  process.exit(2);
}
const { encodeCbor } = await import(pathToFileURL(resolve(encoderPath)).href);

const DOMAIN = 'kalareach-service-description-v1';

const description = {
  schema_version: 1,
  network: {
    relay_urls: ['https://relay-1.reach.kala.to', 'https://relay-2.reach.kala.to'],
    pkarr_publisher_url: 'https://ns1.reach.kala.to/pkarr',
    pkarr_resolver_url: 'https://ns1.reach.kala.to/pkarr',
  },
  authority: { origin: 'https://reach.kala.to' },
  mailbox: { origin: 'https://reach.kala.to' },
  relay: { origin: 'https://reach.kala.to' },
};

// A description that names few services: no relay map, no authority feed, mailbox or lease service,
// and a DNS origin. What it leaves out is signed as null, and an absent relay map as an empty list.
const sparse = {
  schema_version: 1,
  network: {
    pkarr_publisher_url: 'https://ns1.example.test/pkarr',
    pkarr_resolver_url: 'https://ns1.example.test/pkarr',
    dns_origin: 'discovery.example.test',
  },
};

// The origin a service is served at, which its description is signed for.
const ORIGIN = 'https://reach.kala.to';

function descriptionSigningInput(held, origin) {
  const named = (section) => ({ origin: section?.origin ?? null });
  return encodeCbor({
    [DOMAIN]: {
      origin,
      schema_version: held.schema_version,
      network: {
        relay_urls: [...(held.network?.relay_urls ?? [])],
        pkarr_publisher_url: held.network?.pkarr_publisher_url ?? null,
        pkarr_resolver_url: held.network?.pkarr_resolver_url ?? null,
        dns_origin: held.network?.dns_origin ?? null,
      },
      authority: named(held.authority),
      mailbox: named(held.mailbox),
      relay: named(held.relay),
    },
  });
}

// A release matrix, signed with the same key, so that neither signature can be passed for the other.
const matrix = {
  schemaVersion: 1,
  revision: '2',
  issuedAt: '2026-10-27',
  installedClientWindowDays: 90,
  alternatives: ['direct', 'self-hosted-relay', 'self-hosted-discovery'],
  tiers: [
    {
      id: '2026-10-compatible',
      compatible: true,
      client: { minimum: '0.77.0', maximum: '0.79.99' },
      relay: { minimum: '1.2.0', maximum: '1.2.99' },
      discovery: { minimum: '1.2.0', maximum: '1.2.99' },
    },
  ],
};

function matrixSigningInput(held) {
  const range = (range) => ({ minimum: range.minimum, maximum: range.maximum });
  return encodeCbor({
    'kr-release-matrix/1': {
      schema_version: held.schemaVersion,
      revision: held.revision,
      issued_at: held.issuedAt,
      installed_client_window_days: held.installedClientWindowDays,
      alternatives: [...held.alternatives],
      tiers: held.tiers.map((tier) => ({
        id: tier.id,
        compatible: tier.compatible,
        client: range(tier.client),
        relay: range(tier.relay),
        discovery: range(tier.discovery),
      })),
    },
  });
}

// The publisher imports a 32-byte seed inside this PKCS#8 wrapper.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// A fixed seed, so the vector is the same every time it is made.
const seed = createHash('sha256').update('kalareach-service-description-test-vector/1').digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([PKCS8_PREFIX, seed]),
  format: 'der',
  type: 'pkcs8',
});
const publicDer = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const publicKey = publicDer.subarray(publicDer.length - 32);

const base64url = (bytes) => Buffer.from(bytes).toString('base64url');
const descriptionInput = Buffer.from(descriptionSigningInput(description, ORIGIN));
const sparseInput = Buffer.from(descriptionSigningInput(sparse, ORIGIN));
const matrixInput = Buffer.from(matrixSigningInput(matrix));

process.stdout.write(
  JSON.stringify(
    {
      web_commit: webCommit,
      origin: ORIGIN,
      public_key: base64url(publicKey),
      signing_input_hex: descriptionInput.toString('hex'),
      published: {
        description,
        signature: base64url(sign(null, descriptionInput, privateKey)),
      },
      sparse: {
        signing_input_hex: sparseInput.toString('hex'),
        published: {
          description: sparse,
          signature: base64url(sign(null, sparseInput, privateKey)),
        },
      },
      matrix,
      matrix_signing_input_hex: matrixInput.toString('hex'),
      matrix_signature: base64url(sign(null, matrixInput, privateKey)),
    },
    null,
    2,
  ) + '\n',
);
