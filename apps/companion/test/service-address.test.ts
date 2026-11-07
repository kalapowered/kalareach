/**
 * A service's address as a person says it aloud.
 *
 * KR-REQ-11.48: a screen reader reads what the screen says, and an address is dots, colons and
 * brackets. Left as written, it is run together, spelled, or read by the reader's punctuation
 * setting, which a person may have turned down. The page therefore gives the reader the address as
 * words, for every host an origin may name (`validate_origin_host` in `crates/kr-protocol`): a name,
 * a name with a port, an IPv4 address, and an IPv6 literal, each with or without a port. The sync
 * service names its host with the brackets and the port an origin has; the pairing service names it
 * without either (`origin_host` in `crates/kr-client`), so an IPv6 literal also comes bare.
 */

import { describe, expect, it } from 'vitest'

import { spokenAddress } from '../src/components/ServiceAddress'

const SAID: readonly (readonly [written: string, said: string])[] = [
  ['reach.kala.to', 'reach dot kala dot to'],
  ['localhost', 'localhost'],
  ['sync.example.org:8443', 'sync dot example dot org port 8443'],
  ['192.0.2.1', '192 dot 0 dot 2 dot 1'],
  ['192.0.2.1:8443', '192 dot 0 dot 2 dot 1 port 8443'],
  ['[2001:db8::1]', '2001 colon db8 colon colon 1'],
  ['[2001:db8::1]:8443', '2001 colon db8 colon colon 1 port 8443'],
  ['[::1]', 'colon colon 1'],
  ['[::1]:8443', 'colon colon 1 port 8443'],
  ['[::]', 'colon colon'],
  [
    '[2001:db8:85a3::8a2e:370:7334]:8443',
    '2001 colon db8 colon 85a3 colon colon 8a2e colon 370 colon 7334 port 8443'
  ],
  // The pairing service's host: the same literals with no brackets and no port.
  ['::1', 'colon colon 1'],
  ['::', 'colon colon'],
  ['2001:db8::1', '2001 colon db8 colon colon 1'],
  ['2001:db8:85a3::8a2e:370:7334', '2001 colon db8 colon 85a3 colon colon 8a2e colon 370 colon 7334']
]

describe('the address a screen reader says', () => {
  it.each(SAID)('says %s as words', (written, said) => {
    expect(spokenAddress(written)).toBe(said)
  })

  it('leaves no dot, colon or bracket for the reader to read as punctuation', () => {
    for (const [written] of SAID) {
      expect(spokenAddress(written), written).not.toMatch(/[.:[\]]/)
    }
  })
})
