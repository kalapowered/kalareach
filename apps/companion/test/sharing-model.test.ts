/**
 * The words and the small rules of the sharing screens that need no screen to check.
 */

import { describe, expect, it } from 'vitest'

import { EVERY_RIGHT, actionsOf } from '../src/host/fake-state'
import type { AttemptView } from '../src/host/port'
import { actionWords, attemptWords, visibly } from '../src/model/sharing'
import { SharingDesk } from '../src/model/sharing-desk'
import { handedOver, tookBack, waitingOn, workersHave, workersListed } from '../src/model/sharing-results'

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

    desk.keepRevocation('grant-1', 'Sam', false, 1_000, '7', {
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
        withdrawing: false,
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
    desk.keepRevocation('grant-1', 'Sam', false, 1_000, '7', { sessions: [], confirmed: [], ended: [], cut: false })
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

// What an attempt whose answer was lost, and that the host then shows to have happened, is told as.
const LOST_ANSWER = (kind: AttemptView['kind']): AttemptView => ({
  action_id: 'action-1',
  kind,
  phase: 'closed',
  outcome: 'happened',
  label: 'Invitation to Sam',
  hidden: false,
  follow_up: false,
  session_id: null,
  device_id: null,
  grant_id: null,
  revoked_grant_id: null,
  composed_at_ms: '0',
  can_happen_until_ms: null,
  repeats: 1,
  refusal: null,
  result: null
})

describe('what an attempt whose answer was lost is told as', () => {
  // KR-REQ-18.14: the page never says "done" for an answer it did not receive. It says what the host
  // shows, as it does for a revocation and a hand-over.
  it('does not say done for an invitation or an acceptance that the host shows to have happened', () => {
    for (const kind of ['invite', 'redeem'] as const) {
      const words = attemptWords(LOST_ANSWER(kind), 0)
      expect(words, kind).toBe('Invitation to Sam: the host shows that it happened.')
      expect(words, kind).not.toMatch(/done/i)
    }
  })
})

const REVOKED_ANSWER = (pending: number): Parameters<typeof tookBack>[2] =>
  ({
    authority_revision: '6',
    barrier: {
      authority_revision: '6',
      workers: Array.from({ length: pending }, (_, at) => ({ session_id: `session-${String(at)}`, state: 'pending' })),
      workers_total: String(pending)
    }
  }) as unknown as Parameters<typeof tookBack>[2]

describe('what a revocation, a withdrawal and a hand-over say while a worker has not confirmed', () => {
  const told = (run: (say: (words: string) => void) => void): string[] => {
    const said: string[] = []
    run((words) => said.push(words))
    return said
  }

  // KR-REQ-18.14: a pending withdrawal says "withdrawal" in its toast and in the line the desk keeps,
  // and a pending revocation says "revocation" in both, so one thing has one word.
  it('keeps the word the toast used for the line that stays', () => {
    const desk = new SharingDesk()
    const said = told((say) => {
      tookBack(desk, say, REVOKED_ANSWER(1), 'grant-1', 'Sam', true, 1_000)
    })
    expect(said).toEqual(['The withdrawal of the invitation to Sam is recorded, and not done: 1 session worker has not confirmed yet.'])
    expect(desk.snapshot().revoked[0]?.withdrawing).toBe(true)
    tookBack(desk, () => undefined, REVOKED_ANSWER(1), 'grant-2', 'Kim', false, 1_000)
    expect(desk.snapshot().revoked[1]?.withdrawing).toBe(false)
  })

  // KR-REQ-18.14: a hand-over is told as `kr` tells it: the giving device's access "is revoked" once
  // every worker has confirmed, and until then the revocation is recorded and not done, with the count
  // of workers still to confirm.
  it('says a hand-over’s revocation is recorded and not done, or that it is revoked', () => {
    const desk = new SharingDesk()
    const done = (pending: number): Parameters<typeof handedOver>[2] =>
      ({ revoked: REVOKED_ANSWER(pending) }) as unknown as Parameters<typeof handedOver>[2]
    const waiting = told((say) => {
      handedOver(desk, say, done(2), 'grant-1', 'Sam', 'Session 5 is now with Kim.', 1_000)
    })
    expect(waiting).toEqual([
      'Session 5 is now with Kim. The revocation for Sam is recorded, and not done: 2 session workers have not confirmed yet.'
    ])
    const finished = told((say) => {
      handedOver(desk, say, done(0), 'grant-1', 'Sam', 'Session 5 is now with Kim.', 1_000)
    })
    expect(finished).toEqual(['Session 5 is now with Kim. Access for Sam is revoked.'])
  })
})
