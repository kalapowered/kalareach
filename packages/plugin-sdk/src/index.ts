/**
 * The KalaReach plugin package contract for TypeScript.
 *
 * Rust is canonical. The types re-exported here are generated from the JSON Schema in `schema/`,
 * which is generated from `crates/kr-plugin-sdk`. The runtime values below come from the same
 * generator, so a build tool that reads the effect table and a host that enforces it agree.
 *
 * `validatePluginManifest` and its neighbours parse a manifest against the schema. They answer
 * whether a document is shaped like a manifest; they do not answer whether a package is safe. The
 * digest, size, path and grant checks are the host's, and a signature proves provenance rather
 * than safety.
 */

// Ajv publishes CommonJS. Node's interop puts the constructor on the module's default export,
// and the module object carries `default` as well, so this reaches the class under both views.
import ajv2020 from 'ajv/dist/2020.js'
import type { ErrorObject, ValidateFunction } from 'ajv'

const Ajv2020 = ajv2020.default

import contract from '../schema/package-contract.json' with { type: 'json' }
import schema from '../schema/kalareach-plugin-sdk.schema.json' with { type: 'json' }

export type * from './generated/plugin-sdk.js'

import type {
  CatalogueIndex,
  ConnectorManifest,
  PluginManifest,
  PresentationManifest
} from './generated/plugin-sdk.js'

/** The package contract as data: effect classes, capabilities, limits and bounds. */
export const packageContract = contract

/** The generated JSON Schema bundle. */
export const packageSchema = schema

/** The SDK version this package implements. */
export const sdkVersion: string = contract.sdk_version

/** The WIT package version this release publishes. */
export const witVersion: string = contract.wit_version

/** The functions a component exports. */
export const componentExports: readonly string[] = contract.wit_package.exports

/** The capabilities a newly enrolled repository permits without any further grant. */
export const defaultRepositoryCeiling: readonly string[] = contract.default_repository_ceiling

/** The document node kinds a client renders. Anything else is unsupported content. */
export const documentNodeKinds: readonly string[] = contract.document_node_kinds

/**
 * The per-instance execution limits from the package contract.
 *
 * Byte counts and durations are decimal strings, as section 4 requires of every unsigned 64-bit
 * value in the JSON representation. Read them with `BigInt` where the exact value matters.
 */
export const instanceLimits = contract.instance_limits

/** The default repository budgets from the package contract. */
export const repositoryBudgets = contract.repository_budgets

/** Returns the rights the broker intersects for one effect class, or undefined if unknown. */
export function requiredRights(effect: string): readonly string[] | undefined {
  return contract.effect_classes.find((entry) => entry.effect === effect)?.required_rights
}

/** Returns true when the effect class changes something outside the host's own presentation. */
export function isMutation(effect: string): boolean {
  return contract.effect_classes.find((entry) => entry.effect === effect)?.mutation ?? true
}

/** Why a document is not the manifest it claims to be. */
export interface SchemaProblem {
  /** Where in the document the problem is, as a JSON pointer. */
  readonly pointer: string
  /** What is wrong there. */
  readonly message: string
}

/** The outcome of checking a document against the schema. */
export type SchemaResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly problems: readonly SchemaProblem[] }

const ajv = new Ajv2020({ allErrors: true, strict: false })

/**
 * The exact range each Rust integer type accepts.
 *
 * The schema carries these as a `format`, which a validator ignores unless it is told what the
 * format means. Without them a document could declare a 33-bit count, pass validation here, and
 * then be rejected by the host that actually reads it.
 */
const integerFormats: Record<string, { min: number; max: number }> = {
  uint8: { min: 0, max: 255 },
  uint16: { min: 0, max: 65535 },
  uint32: { min: 0, max: 4294967295 },
  uint64: { min: 0, max: Number.MAX_SAFE_INTEGER },
  uint: { min: 0, max: Number.MAX_SAFE_INTEGER },
  int8: { min: -128, max: 127 },
  int16: { min: -32768, max: 32767 },
  int32: { min: -2147483648, max: 2147483647 },
  int64: { min: Number.MIN_SAFE_INTEGER, max: Number.MAX_SAFE_INTEGER }
}

for (const [name, range] of Object.entries(integerFormats)) {
  ajv.addFormat(name, {
    type: 'number',
    validate: (value: number) =>
      Number.isInteger(value) && value >= range.min && value <= range.max
  })
}

/** The largest value a decimal 64-bit counter may spell. */
const maxDecimalU64 = 18446744073709551615n

/**
 * Unsigned 64-bit counters travel as decimal strings, because a JavaScript number cannot carry one
 * exactly. The pattern alone admits a value one past the range, which Rust rejects, so the range
 * is checked here where the value is still exact.
 */
ajv.addFormat('uint64_decimal', {
  type: 'string',
  validate: (value: string) => {
    try {
      const parsed = BigInt(value)
      return parsed >= 0n && parsed <= maxDecimalU64
    } catch {
      return false
    }
  }
})

ajv.addSchema(schema, 'kalareach-plugin-sdk')

const validators = new Map<string, ValidateFunction>()

function validatorFor(root: string): ValidateFunction {
  const existing = validators.get(root)
  if (existing) return existing
  const compiled = ajv.compile({
    $ref: `kalareach-plugin-sdk#/properties/${root}`
  })
  validators.set(root, compiled)
  return compiled
}

function problems(errors: ErrorObject[] | null | undefined): SchemaProblem[] {
  return (errors ?? []).map((error) => ({
    pointer: error.instancePath === '' ? '/' : error.instancePath,
    message: error.message ?? 'does not match the schema'
  }))
}

function check<T>(root: string, document: unknown): SchemaResult<T> {
  const validate = validatorFor(root)
  if (validate(document)) return { ok: true, value: document as T }
  return { ok: false, problems: problems(validate.errors) }
}

/** Checks a `plugin.json` document against the schema. */
export function validatePluginManifest(document: unknown): SchemaResult<PluginManifest> {
  return check<PluginManifest>('plugin_manifest', document)
}

/** Checks a `presentation.json` document against the schema. */
export function validatePresentationManifest(
  document: unknown
): SchemaResult<PresentationManifest> {
  return check<PresentationManifest>('presentation_manifest', document)
}

/** Checks a `connector.json` document against the schema. */
export function validateConnectorManifest(document: unknown): SchemaResult<ConnectorManifest> {
  return check<ConnectorManifest>('connector_manifest', document)
}

/** Checks a catalogue index against the schema. */
export function validateCatalogueIndex(document: unknown): SchemaResult<CatalogueIndex> {
  return check<CatalogueIndex>('catalogue_index', document)
}
