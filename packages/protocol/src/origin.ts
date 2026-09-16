/**
 * One origin, spelled one way.
 *
 * An origin travels inside signed payloads, so what matters is not only that it names the right
 * service but that everyone writes it identically. `https://reach.kala.to`,
 * `https://reach.kala.to:443` and `https://REACH.kala.to` address one service and are three signing
 * inputs, and a verifier comparing text would refuse two of the three from a caller that did nothing
 * wrong. So the grammar below admits exactly one spelling of each address, and refuses the rest
 * rather than canonicalising them.
 *
 * This is the TypeScript half of the validator in `kr_protocol::pairing`, which
 * `kr_protocol::service::GatewayOrigin` and `RendezvousOrigin` both use. The rules and the messages
 * are the same in both languages, so an origin one side admits is one the other admits.
 */

/** The port an `https://` origin omits. */
export const HTTPS_DEFAULT_PORT = 443

/** The port an `http://` origin omits. */
export const HTTP_DEFAULT_PORT = 80

/** An origin that is not one, naming the rule it breaks. */
export class OriginError extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'OriginError'
  }
}

function refuse (message: string): never {
  throw new OriginError(message)
}

/** The host, the optional port, and whether the host arrived bracketed. */
interface Authority {
  readonly host: string
  readonly port: string | null
  readonly bracketed: boolean
}

/**
 * Splits `host[:port]`, keeping an IPv6 literal inside its brackets.
 *
 * `bracketed` says whether the host arrived in brackets, so an unbracketed IPv6 literal is refused
 * rather than read as a host and a port.
 */
export function splitAuthority (authority: string): Authority {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']')
    if (end < 0) {
      refuse('an IPv6 origin closes its bracket')
    }
    const host = authority.slice(1, end)
    const tail = authority.slice(end + 1)
    if (tail === '') {
      return { host, port: null, bracketed: true }
    }
    if (!tail.startsWith(':')) {
      refuse('an IPv6 origin has nothing but a port after its bracket')
    }
    return { host, port: tail.slice(1), bracketed: true }
  }
  if (authority.includes('[') || authority.includes(']')) {
    refuse('only an IPv6 literal uses brackets, and it starts with one')
  }
  const separator = authority.lastIndexOf(':')
  if (separator < 0) {
    return { host: authority, port: null, bracketed: false }
  }
  return {
    host: authority.slice(0, separator),
    port: authority.slice(separator + 1),
    bracketed: false
  }
}

/** Validates the port of an origin, given the port its scheme omits. */
export function validateOriginPort (port: string, defaultPort: number): void {
  if (port === '' || !/^[0-9]+$/.test(port)) {
    refuse('an origin port is decimal')
  }
  if (port.length > 1 && port.startsWith('0')) {
    refuse('an origin port has no leading zero')
  }
  const value = Number(port)
  if (value > 65535) {
    refuse('an origin port is a 16-bit port')
  }
  if (value === 0) {
    refuse('an origin port is not zero')
  }
  if (value === defaultPort) {
    refuse('a canonical origin omits its default port')
  }
}

/** The eight groups of an IPv6 literal, or null when the text is not one. */
function parseIpv6 (text: string): number[] | null {
  const parts = text.split('::')
  if (parts.length > 2) {
    return null
  }
  const readGroups = (piece: string): number[] | null => {
    if (piece === '') {
      return []
    }
    const groups: number[] = []
    for (const group of piece.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
        return null
      }
      groups.push(Number.parseInt(group, 16))
    }
    return groups
  }
  const head = readGroups(parts[0] as string)
  if (head === null) {
    return null
  }
  if (parts.length === 1) {
    return head.length === 8 ? head : null
  }
  const tail = readGroups(parts[1] as string)
  if (tail === null || head.length + tail.length > 7) {
    return null
  }
  const filler = new Array<number>(8 - head.length - tail.length).fill(0)
  return [...head, ...filler, ...tail]
}

/**
 * Writes the eight groups the one way RFC 5952 writes them.
 *
 * Lower-case hexadecimal with no leading zeros, and the longest run of two or more zero groups
 * replaced by `::`, leftmost run on a tie. It is the spelling Rust's `Ipv6Addr` writes, so the two
 * languages agree on which literals are canonical.
 */
function formatIpv6 (groups: readonly number[]): string {
  let bestStart = -1
  let bestLength = 0
  let start = -1
  for (let index = 0; index <= groups.length; index += 1) {
    if (index < groups.length && groups[index] === 0) {
      if (start < 0) {
        start = index
      }
      continue
    }
    if (start >= 0) {
      const length = index - start
      if (length > bestLength) {
        bestStart = start
        bestLength = length
      }
      start = -1
    }
  }
  if (bestLength < 2) {
    return groups.map((group) => group.toString(16)).join(':')
  }
  const head = groups.slice(0, bestStart).map((group) => group.toString(16)).join(':')
  const tail = groups.slice(bestStart + bestLength).map((group) => group.toString(16)).join(':')
  return `${head}::${tail}`
}

/** True when the address is `::` or `::1`. */
function isLoopbackOrUnspecified (groups: readonly number[]): boolean {
  return groups.slice(0, 7).every((group) => group === 0) && (groups[7] === 0 || groups[7] === 1)
}

/** True when the address carries an IPv4 address inside it. */
function carriesIpv4 (groups: readonly number[]): boolean {
  const mapped =
    groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff
  const compatible = groups.slice(0, 6).every((group) => group === 0)
  return mapped || compatible
}

/** Validates the host half of an origin: a bracketed IPv6 literal, or lower-case DNS labels. */
export function validateOriginHost (host: string, bracketed: boolean): void {
  if (host === '') {
    refuse('an origin has a host')
  }
  if (bracketed) {
    // One address has many spellings. The canonical one is what the standard library writes, so an
    // origin that spells it differently is rejected rather than producing a second transcript for
    // the same service.
    const groups = parseIpv6(host)
    if (groups === null) {
      refuse('a bracketed origin host is an IPv6 literal')
    }
    if (formatIpv6(groups) !== host) {
      refuse('an IPv6 origin uses the canonical spelling of its address')
    }
    if (carriesIpv4(groups) && !isLoopbackOrUnspecified(groups)) {
      // An IPv4-mapped or IPv4-compatible address is one host with two spellings, and URL parsers
      // do not agree on which to write. An IPv4 service is named by its IPv4 literal. The loopback
      // and unspecified addresses are not IPv4 addresses in disguise.
      refuse('an IPv4 address is written as an IPv4 origin, not as a mapped IPv6 literal')
    }
    return
  }
  if (host.includes(':')) {
    refuse('an IPv6 origin host is bracketed')
  }
  if (host.endsWith('.')) {
    refuse('an origin host has no trailing dot')
  }
  // An IPv4 literal is a host as well, and it too has one canonical spelling.
  if (/^[0-9.]+$/.test(host)) {
    const octets = host.split('.')
    const canonical =
      octets.length === 4 &&
      octets.every((octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255)
    if (!canonical) {
      refuse('a numeric origin host is an IPv4 literal')
    }
    return
  }
  // A host whose last label is a number is an address, not a name: a URL parser reads `0xc0000201`
  // as 192.0.2.1. An origin that two parsers read differently is two origins, so the last label
  // must be a name.
  const labels = host.split('.')
  const last = labels[labels.length - 1] as string
  if (/^[0-9]/.test(last) || !/[a-z]/.test(last)) {
    refuse('an origin host ends in a name, not a number')
  }
  for (const label of labels) {
    if (label === '' || label.length > 63) {
      refuse('an origin host label is 1 to 63 characters')
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      refuse('an origin host label does not start or end with a hyphen')
    }
    if (!/^[a-z0-9-]+$/.test(label)) {
      refuse('an origin host is lower-case ASCII; encode an international name as A-label punycode')
    }
  }
}

/**
 * Validates the `host[:port]` half of an origin.
 *
 * One address has one spelling here. A port that repeats the scheme's default, a leading zero, an
 * uppercase host or a non-canonical address literal would each give one service two origins, and two
 * origins are two different signing inputs for the same request.
 */
export function validateAuthority (authority: string, defaultPort: number): void {
  if (authority === '' || authority.length > 255) {
    refuse('an origin has a host')
  }
  for (const character of authority) {
    const code = character.codePointAt(0) as number
    if (code < 0x21 || code > 0x7e) {
      refuse('an origin is printable ASCII without spaces')
    }
  }
  if (
    authority.includes('/') ||
    authority.includes('?') ||
    authority.includes('#') ||
    authority.includes('@')
  ) {
    refuse('an origin carries no path, query, fragment or user information')
  }
  const { host, port, bracketed } = splitAuthority(authority)
  if (port !== null) {
    validateOriginPort(port, defaultPort)
  }
  validateOriginHost(host, bracketed)
}

/** True when `authority` names a loopback host, with or without a port. */
export function isLoopbackAuthority (authority: string): boolean {
  try {
    const { host, bracketed } = splitAuthority(authority)
    return bracketed ? host === '::1' : host === 'localhost' || host === '127.0.0.1'
  } catch {
    return false
  }
}
