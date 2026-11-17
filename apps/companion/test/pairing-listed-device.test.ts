/**
 * The words the pairing sheet says when the host still lists the device, and when the device holds
 * a record of the host itself: neither one offers a retry, because pairing again is what fails.
 */

import { describe, expect, it } from 'vitest'

import { failureWords } from '../src/pairing/words'

describe('a pairing the host refuses because it still lists the device', () => {
  it('says so and offers no retry, in either mode', () => {
    for (const mode of ['code', 'direct'] as const) {
      const words = failureWords({ kind: 'host_still_lists_device' }, 'rendezvous.example', mode)
      expect(words.sentence).toBe(
        "This host still lists this device as paired. Ask the host's owner to remove this device from the host, then pair with a new invitation."
      )
      expect(words.action).toBe('done')
    }
  })

  it('is never the generic try-again failure, which a retry cannot cure', () => {
    const words = failureWords({ kind: 'host_still_lists_device' }, 'rendezvous.example')
    expect(words.sentence).not.toContain('Try again')
    expect(words.action).not.toBe('try_again')
  })

  it('tells a device that holds a record of the host to forget the host first', () => {
    const words = failureWords({ kind: 'already_paired' }, 'rendezvous.example')
    expect(words.sentence).toBe(
      "This device already holds a pairing with this host. If the host's owner removed this device or its pairing ran out, forget the host here first, then pair with a new invitation."
    )
    expect(words.action).toBe('done')
  })
})
