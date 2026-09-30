/**
 * The words for a failure (KR-REQ-23.57).
 *
 * Section 23: the interface translates a code into a direct action and does not display raw
 * protocol internals by default. Native code attaches the action a code maps to, by its key, to
 * each failure it answers with, and the page says that action beside the host's own words.
 */

import { describe, expect, it } from 'vitest'

import { failureMessage, USER_ACTIONS } from '../src/host/port'

import retrySource from '../../../crates/kr-client/src/retry.rs?raw'

describe('the words for a failure', () => {
  it('offer the direct action its code translates to, and never the code', () => {
    const said = failureMessage({
      code: 'OUTCOME_UNKNOWN',
      message: 'The host lost the answer.',
      user_action: 'check_the_outcome'
    })
    expect(said).toContain('Check whether this went through before trying it again.')
    expect(said).not.toContain('OUTCOME_UNKNOWN')
  })

  it('say the host’s own words first and the action after them, for each action there is', () => {
    for (const [key, action] of Object.entries(USER_ACTIONS)) {
      expect(
        failureMessage({ code: 'PERMISSION_DENIED', message: 'The host said no.', user_action: key }),
        key
      ).toBe(`The host said no. ${action}`)
    }
    expect(Object.keys(USER_ACTIONS)).toHaveLength(7)
  })

  it('offer the action of a failure that came with no words of its own too', () => {
    expect(failureMessage({ code: 'PAIRING_EXPIRED', message: ' ', user_action: 'pair_again' })).toBe(
      'Something went wrong. Pair this device with the host again.'
    )
  })

  it('keep the message alone for an action that asks nothing of the person, and for one it does not know', () => {
    expect(failureMessage({ code: 'SESSION_CLOSED', message: 'The session closed.', user_action: 'nothing' })).toBe(
      'The session closed.'
    )
    expect(failureMessage({ code: 'X', message: 'The host said no.', user_action: 'retry' })).toBe(
      'The host said no.'
    )
    expect(failureMessage({ code: 'X', message: 'The host said no.' })).toBe('The host said no.')
    expect(failureMessage(new Error('The call failed.'))).toBe('The call failed.')
  })

  it('word each action exactly as the client library does', () => {
    // The library's own sentence for each action, read from its source: the arms of
    // `UserAction::as_str` name the keys and the arms of `UserAction::message` the words.
    const arms = (from: string, to: string) => {
      const start = retrySource.indexOf(from)
      const end = retrySource.indexOf(to, start)
      const body = retrySource.slice(start, end)
      return Array.from(body.matchAll(/Self::(\w+) => "((?:[^"\\]|\\.)*)"/g), (arm) => [arm[1], arm[2]] as const)
    }
    const keys = new Map(arms('pub const fn as_str(self)', 'pub const fn message(self)'))
    const words = arms('pub const fn message(self)', '\n}\n')
    const described: Record<string, string> = {}
    for (const [variant, sentence] of words) {
      const key = keys.get(variant)
      if (key === undefined) throw new Error(`${variant} has no key`)
      if (sentence !== '') described[key] = sentence
    }
    expect(described).toEqual(USER_ACTIONS)
  })
})
