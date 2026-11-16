/**
 * What the voice start page says when the managed service refuses to start a call (KR-REQ-17.48):
 * the service's own words and the paths it names, in the form the other pages use.
 */

import { describe, expect, it } from 'vitest'

import { unavailableWords } from '../../src/voice/model'

describe('the voice start page when the service refuses', () => {
  it('says the service’s words whole, then "Until then:" and each path as it was written', () => {
    expect(
      unavailableWords({
        message: 'Managed voice is not available now.',
        alternatives: ['A provider credential of your own, which uses no managed credit.', 'A path of its own.']
      })
    ).toBe(
      'Managed voice is not available now. Until then: A provider credential of your own, which uses no managed credit. A path of its own.'
    )
  })

  it('says the words alone when the service named no path', () => {
    expect(unavailableWords({ message: 'Managed voice could not start this call.', alternatives: [] })).toBe(
      'Managed voice could not start this call.'
    )
  })
})
