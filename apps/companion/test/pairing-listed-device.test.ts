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

describe('a direct invitation that did not finish', () => {
  // The host refuses a new invitation for a device it still lists, so the same invitation again
  // or a new one cannot pair a device that the host holds as paired.
  it('offers the invitation again or a new one, and says a new one works only after the host ends the pairing', () => {
    for (const [reading, again] of [
      ['camera', 'Scan the invitation again'],
      ['photo', 'Choose the picture again'],
      ['pasteboard', 'Copy the invitation from the host again']
    ] as const) {
      const words = failureWords({ kind: 'did_not_finish' }, 'rendezvous.example', 'direct', reading)
      expect(words.sentence).toBe(
        `Pairing did not finish. ${again}, or ask the host for a new one. If the host still lists this device as paired, a new invitation works only after that pairing has ended.`
      )
      expect(words.action).toBe('new_invitation')
    }
  })
})

// Each sentence that offers a new invitation says when it can work: the host refuses a new
// invitation for a device it still lists, however the attempt ended.
describe('the other sentences that offer a new invitation', () => {
  const WHEN =
    'If the host still lists this device as paired, a new invitation works only after that pairing has ended.'

  it('say when a new invitation works after an invitation that expired, in either mode', () => {
    for (const [mode, action] of [
      ['code', 'start_again'],
      ['direct', 'new_invitation']
    ] as const) {
      const words = failureWords({ kind: 'expired' }, 'rendezvous.example', mode)
      expect(words.sentence, mode).toBe(
        `The host reports that the invitation expired. Ask it for a new one. ${WHEN}`
      )
      expect(words.action, mode).toBe(action)
    }
  })

  it('say when a new invitation works after a code pairing that did not finish', () => {
    const words = failureWords({ kind: 'did_not_finish' }, 'rendezvous.example', 'code')
    expect(words.sentence).toBe(
      `Pairing did not finish. Try again, or ask the host for a new invitation. ${WHEN}`
    )
    expect(words.action).toBe('try_again')
  })
})
