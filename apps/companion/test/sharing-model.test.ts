/**
 * The words and the small rules of the sharing screens that need no screen to check.
 */

import { describe, expect, it } from 'vitest'

import { EVERY_RIGHT, actionsOf } from '../src/host/fake-state'
import { accessOf, actionWords, rightsBeyond, roleOfRights, visibly } from '../src/model/sharing'
import { SharingDesk } from '../src/model/sharing-desk'

describe('what an invitation carries, in words', () => {
  it('has words for every right a share can carry, so no protocol name reaches the person', () => {
    const carried = new Set(
      (['viewer', 'reviewer', 'controller', 'owner'] as const).flatMap((role) =>
        actionsOf({
          role,
          history_from_cursor_ms: null,
          include_live_screen: false,
          include_question_respond: false,
          named_questions: [],
          named_approvals: []
        })
      )
    )
    expect(carried.size).toBeGreaterThan(8)
    for (const right of EVERY_RIGHT) {
      if (carried.has(right)) expect(actionWords(right), right).not.toBe(right)
    }
  })
})

// KR-REQ-10.42, the part about labels: a share is named by what it allows. The role is the widest one
// whose rights the share carries in full, and any right the role does not cover is named beside it,
// so no right a share carries is left out of its words.
describe('what a share allows, in words (KR-REQ-10.42)', () => {
  const ROLES = ['viewer', 'reviewer', 'controller', 'owner'] as const
  const rightsOf = (role: (typeof ROLES)[number]) =>
    actionsOf({
      role,
      history_from_cursor_ms: null,
      include_live_screen: false,
      include_question_respond: false,
      named_questions: [],
      named_approvals: []
    })

  it('names a share that carries exactly a role’s rights by that role alone', () => {
    for (const role of ROLES) {
      expect(roleOfRights(rightsOf(role)), role).toBe(role)
      expect(rightsBeyond(rightsOf(role)), role).toEqual([])
      expect(accessOf(rightsOf(role)).beyond, role).toBe('')
    }
  })

  it('names every right a role does not cover beside the role, whichever role it is', () => {
    for (const role of ROLES) {
      for (const right of EVERY_RIGHT) {
        const actions = [...new Set([...rightsOf(role), right])]
        const beyond = rightsBeyond(actions)
        // The role the host would name is at least this one, and nothing the share carries is lost.
        const named = roleOfRights(actions)
        expect(named, `${role} and ${right}`).not.toBeNull()
        const covered = new Set(rightsOf(named ?? 'viewer'))
        for (const carried of actions) {
          expect(covered.has(carried) || beyond.includes(carried), `${role} and ${right}: ${carried}`).toBe(true)
        }
        if (!covered.has(right)) expect(accessOf(actions).beyond, `${role} and ${right}`).not.toBe('')
      }
    }
  })

  it('does not call a share a viewer when it holds no view of the session', () => {
    const voice = ['agent.approval.respond', 'agent.prompt', 'voice.use'] as const
    expect(roleOfRights(voice)).toBeNull()
    expect(accessOf(voice).role).toBe('Custom access')
    expect(rightsBeyond(voice)).toEqual([...voice])
  })
})

describe('text from a session or a device', () => {
  it('shows every character that can hide or reorder text, as `kr` does', () => {
    expect(visibly('a­b​c d\u{e0041}e')).toBe('a‹U+00AD›b‹U+200B›c‹U+2028›d‹U+E0041›e')
    expect(visibly('x‮y')).toBe('x‹U+202E›y')
    expect(visibly('plain text, 100%')).toBe('plain text, 100%')
  })
})

describe('what the page keeps of a result', () => {
  it('takes a result in once, and keeps the time and the revision of a revocation when it is checked again', () => {
    const desk = new SharingDesk()
    expect(desk.firstTime('action-1')).toBe(true)
    expect(desk.firstTime('action-1')).toBe(false)
    expect(desk.firstTime('action-2')).toBe(true)

    desk.keepRevocation('grant-1', 'Sam', 1_000, '7', 2)
    desk.checked('grant-1', 1)
    expect(desk.snapshot().revoked).toEqual([
      { grantId: 'grant-1', name: 'Sam', atMs: 1_000, revision: '7', pending: 1 }
    ])
  })

  it('tells a listener when something it draws changes', () => {
    const desk = new SharingDesk()
    let told = 0
    const stop = desk.subscribe(() => {
      told += 1
    })
    const before = desk.snapshot()
    desk.keepRevocation('grant-1', 'Sam', 1_000, '7', 0)
    expect(told).toBe(1)
    expect(desk.snapshot()).not.toBe(before)
    stop()
    desk.dismissRevocation('grant-1')
    expect(told).toBe(1)
  })
})
