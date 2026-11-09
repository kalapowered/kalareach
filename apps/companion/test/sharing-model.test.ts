/**
 * The words and the small rules of the sharing screens that need no screen to check.
 */

import { describe, expect, it } from 'vitest'

import { EVERY_RIGHT, actionsOf } from '../src/host/fake-state'
import { actionWords, visibly } from '../src/model/sharing'
import { SharingDesk } from '../src/model/sharing-desk'
import { waitingOn, workersHave, workersListed } from '../src/model/sharing-results'

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

    desk.keepRevocation('grant-1', 'Sam', 1_000, '7', {
      sessions: ['session-a', 'session-b'],
      confirmed: [],
      ended: [],
      cut: false
    })
    desk.checked('grant-1', {
      sessions: ['session-b'],
      confirmed: ['session-a'],
      ended: ['session-c'],
      cut: false
    })
    expect(desk.snapshot().revoked).toEqual([
      {
        grantId: 'grant-1',
        name: 'Sam',
        atMs: 1_000,
        revision: '7',
        waiting: ['session-b'],
        confirmed: ['session-a'],
        ended: ['session-c'],
        cut: false
      }
    ])
  })

  it('tells a listener when something it draws changes', () => {
    const desk = new SharingDesk()
    let told = 0
    const stop = desk.subscribe(() => {
      told += 1
    })
    const before = desk.snapshot()
    desk.keepRevocation('grant-1', 'Sam', 1_000, '7', { sessions: [], confirmed: [], ended: [], cut: false })
    expect(told).toBe(1)
    expect(desk.snapshot()).not.toBe(before)
    stop()
    desk.dismissRevocation('grant-1')
    expect(told).toBe(1)
  })
})

describe('the session workers a revocation still waits for', () => {
  // KR-REQ-18.14: the host names the workers that have not confirmed before any that has, and says
  // how many there were in all, so a list it cut is a floor and the words say "at least".
  it('says "at least" when the host cut its list, and names the workers it did list', () => {
    const answer = {
      barrier: {
        authority_revision: '6',
        workers: [{ session_id: 'session-a', state: 'pending' }],
        workers_total: '5'
      }
    } as unknown as Parameters<typeof waitingOn>[0]
    const waiting = waitingOn(answer)
    expect(waiting).toEqual({ sessions: ['session-a'], confirmed: [], ended: [], cut: true })
    expect(workersHave(waiting.sessions.length, waiting.cut)).toBe('at least 1 session worker has')
    expect(workersHave(2, false)).toBe('2 session workers have')
  })

  // KR-REQ-18.14, each worker: the page keeps which sessions' workers have confirmed as well as which
  // have not, so the person is told each worker's completion and not only the ones still owed.
  it('names every worker that has not confirmed and every one that has', () => {
    const answer = {
      barrier: {
        authority_revision: '6',
        workers: [
          { session_id: 'session-a', state: 'pending' },
          { session_id: 'session-b', state: 'acknowledged' },
          { session_id: 'session-c', state: 'pending' }
        ],
        workers_total: '3'
      }
    } as unknown as Parameters<typeof waitingOn>[0]
    expect(waitingOn(answer)).toEqual({
      sessions: ['session-a', 'session-c'],
      confirmed: ['session-b'],
      ended: [],
      cut: false
    })
  })

  // KR-REQ-18.14, each worker: a worker whose execution has ended confirmed nothing, so it is kept
  // and worded as ended, not as confirmed; and the workers the host listed are said whether or not
  // any is still owed.
  it('names a worker that has ended as ended, and says each listed worker once none is owed', () => {
    const answer = {
      barrier: {
        authority_revision: '6',
        workers: [
          { session_id: 'aaaaaaaa-0000', state: 'acknowledged' },
          { session_id: 'bbbbbbbb-0000', state: 'ended' }
        ],
        workers_total: '2'
      }
    } as unknown as Parameters<typeof waitingOn>[0]
    const waiting = waitingOn(answer)
    expect(waiting).toEqual({
      sessions: [],
      confirmed: ['aaaaaaaa-0000'],
      ended: ['bbbbbbbb-0000'],
      cut: false
    })
    expect(workersListed(waiting)).toBe(' Confirmed: session aaaaaaaa. Ended: session bbbbbbbb.')
    expect(workersListed({ confirmed: [], ended: [], cut: false })).toBe('')
    expect(workersListed({ ...waiting, cut: true })).toBe(
      ' Confirmed among those the host listed: session aaaaaaaa. Ended among those the host listed: session bbbbbbbb.'
    )
  })
})
