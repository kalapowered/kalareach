/**
 * How the page names a share by the roles the host writes grants for.
 *
 * A role is a label for a person reading a share: the host decides from a grant's actions and a
 * grant keeps no role. The page names a share by the widest role whose actions it carries in full,
 * and says every action beside the role. The roles and what each carries by default are the host's,
 * recorded in a fixture the host's own test holds it to.
 */

import { describe, expect, it } from 'vitest'

import type { ActionRight } from '@kalareach/protocol'

import roles from '../../../fixtures/protocol/session-roles.json'
import { accessOf, rightsBeyond, roleOfRights } from '../src/model/sharing'

const entries = roles.roles as unknown as ReadonlyArray<{ role: string; default_actions: ActionRight[] }>

describe('the page names a share by the host’s roles', () => {
  // KR-REQ-10.42
  it('names the actions each role carries by default as that role, with nothing beside it', () => {
    for (const entry of entries) {
      expect(roleOfRights(entry.default_actions)).toBe(entry.role)
      expect(rightsBeyond(entry.default_actions)).toEqual([])
      expect(accessOf(entry.default_actions).beyond).toBe('')
    }
  })

  // KR-REQ-10.42
  it('names a role short of one action as the role below it, with the action beside that role', () => {
    for (let index = 1; index < entries.length; index += 1) {
      const entry = entries[index]
      const below = entries[index - 1]
      const lacking = entry.default_actions.filter((right) => !below.default_actions.includes(right))
      for (const missing of lacking) {
        const short = entry.default_actions.filter((right) => right !== missing)
        const named = roleOfRights(short)
        // A role short of an action is named as the widest role whose actions it still holds in
        // full, and every action beyond that role is said beside it.
        expect(entries.map((candidate) => candidate.role)).toContain(named)
        const held = entries.find((candidate) => candidate.role === named)?.default_actions ?? []
        expect(held.every((right) => short.includes(right))).toBe(true)
        expect(rightsBeyond(short)).toEqual(short.filter((right) => !held.includes(right)))
        expect(named).not.toBe(entry.role)
      }
    }
  })
})
