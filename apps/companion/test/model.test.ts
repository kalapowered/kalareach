/**
 * The model's own rules, without a screen in front of them.
 *
 * Each of these is a sentence from the specification, written as an assertion.
 */

import { describe, expect, it, vi } from 'vitest'

import type { DocumentNode } from '@kalareach/plugin-sdk'

import {
  applyNode,
  applyNodes,
  emptyConversation,
  isNewer,
  nodesAbove,
  prependHistory,
  setFollowing,
  setWindowStart,
  visibleNodes,
  WINDOW_SIZE
} from '../src/model/conversation'
import { FrameBatcher } from '../src/model/frame'
import {
  connectionLost,
  edit,
  notSubmittableBecause,
  readInsertionRefusal,
  rebind,
  retarget,
  startDraft,
  submittable
} from '../src/model/drafts'
import {
  describeState,
  failed,
  queued,
  reconnectBanner,
  sent,
  settled,
  stateOfReceipt,
  unresolved
} from '../src/model/receipts'
import { emptyControlState, evaluate, isRendered, visibilityOf } from '../src/model/controls'
import { drawCell, drawRow, REPLACEMENT } from '../src/terminal/clusters'
import { routeWheel, zoomBy, ZOOM_STEPS } from '../src/terminal/modes'
import { projectEndpoint, rubberband, shouldDismiss, stepSpring } from '../src/motion'

function node(id: string, revision: string, text = id): DocumentNode {
  return {
    id,
    revision,
    body: { kind: 'message', author: 'agent', text }
  } as unknown as DocumentNode
}

describe('the conversation', () => {
  it('replaces a node with the same identity rather than adding one', () => {
    let state = applyNode(emptyConversation(), node('a', '1', 'first'))
    state = applyNode(state, node('a', '2', 'second'))
    expect(state.nodes).toHaveLength(1)
    expect((state.nodes[0].body as { text: string }).text).toBe('second')
  })

  it('ignores a revision that is not newer, so an out-of-order delivery does not go backwards', () => {
    let state = applyNode(emptyConversation(), node('a', '5', 'current'))
    state = applyNode(state, node('a', '4', 'stale'))
    expect((state.nodes[0].body as { text: string }).text).toBe('current')
  })

  it('compares revisions as counters even when they are longer than a safe integer', () => {
    expect(isNewer('10', '9')).toBe(true)
    expect(isNewer('9', '10')).toBe(false)
    expect(isNewer('9007199254740993', '9007199254740992')).toBe(true)
  })

  it('renders a bounded window however long the conversation is', () => {
    const many = Array.from({ length: 5_000 }, (_, index) => node(`n${index}`, '1'))
    const state = applyNodes(emptyConversation(), many)
    expect(state.nodes).toHaveLength(5_000)
    expect(visibleNodes(state).length).toBeLessThanOrEqual(WINDOW_SIZE + 40)
  })

  it('follows the live end only while the view is at it', () => {
    let state = applyNodes(
      emptyConversation(),
      Array.from({ length: 300 }, (_, index) => node(`n${index}`, '1'))
    )
    const followingStart = state.windowStart
    state = setFollowing(state, false)
    state = applyNode(state, node('later', '1'))
    expect(state.windowStart).toBe(followingStart)

    state = setFollowing(state, true)
    state = applyNode(state, node('later-still', '1'))
    expect(state.windowStart).toBeGreaterThan(followingStart)
  })

  it('keeps the reader anchored when a page of older content is loaded', () => {
    let state = applyNodes(
      emptyConversation(),
      Array.from({ length: 300 }, (_, index) => node(`n${index}`, '1'))
    )
    state = setWindowStart(state, 100)
    const anchorNode = state.nodes[100]
    const before = nodesAbove(state)

    state = prependHistory(
      state,
      Array.from({ length: 40 }, (_, index) => node(`older${index}`, '1'))
    )

    expect(nodesAbove(state)).toBe(before + 40)
    expect(state.nodes[140]).toBe(anchorNode)
    expect(state.following).toBe(false)
  })

  it('ignores a history page it already holds', () => {
    let state = applyNodes(emptyConversation(), [node('a', '1'), node('b', '1')])
    state = prependHistory(state, [node('a', '1')])
    expect(state.nodes).toHaveLength(2)
  })
})

describe('batching per animation frame', () => {
  it('publishes many events as one batch', () => {
    const flushed: number[] = []
    let scheduled: (() => void) | null = null
    const batcher = new FrameBatcher<number>(
      (batch) => {
        flushed.push(batch.length)
      },
      (run) => {
        scheduled = run
      }
    )

    for (let index = 0; index < 40; index += 1) batcher.push(index)
    expect(flushed).toHaveLength(0)
    expect(batcher.pending).toBe(40)

    scheduled!()
    expect(flushed).toEqual([40])
    expect(batcher.frames).toBe(1)
    expect(batcher.published).toBe(40)
  })

  it('puts what arrives during a flush into the next frame rather than dropping it', () => {
    const batches: number[][] = []
    const scheduled: (() => void)[] = []
    const batcher: FrameBatcher<number> = new FrameBatcher<number>(
      (batch) => {
        batches.push([...batch])
        if (batches.length === 1) batcher.push(99)
      },
      (run) => {
        scheduled.push(run)
      }
    )

    batcher.push(1)
    scheduled[0]()
    expect(batches).toEqual([[1]])
    scheduled[1]()
    expect(batches).toEqual([[1], [99]])
  })
})

describe('what the person sent', () => {
  it('maps every receipt state, and never rounds an unknown outcome up', () => {
    expect(stateOfReceipt({ state: 'received' } as never)).toBe('sent')
    expect(stateOfReceipt({ state: 'accepted' } as never)).toBe('sent')
    expect(stateOfReceipt({ state: 'dispatching' } as never)).toBe('sent')
    expect(stateOfReceipt({ state: 'applied' } as never)).toBe('applied')
    expect(stateOfReceipt({ state: 'refused' } as never)).toBe('refused')
    expect(stateOfReceipt({ state: 'rejected' } as never)).toBe('rejected')
    expect(stateOfReceipt({ state: 'unknown' } as never)).toBe('unknown')
  })

  it('moves one submission through queued, sent and applied', () => {
    let submission = queued('s1', 'hello', 0)
    expect(submission.state).toBe('queued')
    submission = sent(submission, 'a1')
    expect(submission.state).toBe('sent')
    submission = settled(submission, {
      action_id: 'a1',
      state: 'applied',
      error: null
    } as never)
    expect(submission.state).toBe('applied')
    expect(describeState(submission.state)).toBe('Applied')
  })

  it('leaves an unconfirmed outcome unknown rather than calling it a failure', () => {
    const submission = failed(queued('s1', 'hello', 0), {
      code: 'OUTCOME_UNKNOWN',
      message: 'the connection ended after the request was sent'
    })
    expect(submission.state).toBe('unknown')
    expect(unresolved([submission])).toHaveLength(1)
  })

  it('never lets the reconnect banner imply success', () => {
    const pending = [sent(queued('s1', 'hello', 0), 'a1')]

    const disconnected = reconnectBanner(false, pending)
    expect(disconnected?.detail).toMatch(/no confirmed outcome/)
    expect(disconnected?.detail).not.toMatch(/succeeded|applied|done/i)

    const reconnected = reconnectBanner(true, pending)
    expect(reconnected?.title).toBe('Connected again')
    expect(reconnected?.detail).toMatch(/still waiting for a receipt/)

    expect(reconnectBanner(true, [])).toBeNull()
  })
})

describe('drafts', () => {
  const target = { sessionId: 's1', applicationInstanceId: 'app1', agentBindingRevision: '4' }

  it('keeps the text when the connection goes away, and only drops the association', () => {
    const draft = edit(startDraft('d1', target, 0), 'half a thought', 1)
    const detached = connectionLost(draft)
    expect(detached.text).toBe('half a thought')
    expect(detached.revision).toBe(draft.revision)
    expect(detached.state).toBe('detached')
    expect(detached.attachmentId).toBeNull()
  })

  it('rebinds to an unchanged target, and conflicts on a changed binding', () => {
    const draft = connectionLost(edit(startDraft('d1', target, 0), 'text', 1))
    expect(rebind(draft, target, 'att-2').state).toBe('bound')
    expect(rebind(draft, { ...target, agentBindingRevision: '5' }, 'att-2').state).toBe('conflicted')
    expect(rebind(draft, { ...target, applicationInstanceId: 'app2' }, 'att-2').state).toBe(
      'conflicted'
    )
    expect(rebind(draft, null, 'att-2').state).toBe('orphaned')
  })

  it('never submits a conflicted draft, and clears the conflict only on an explicit retarget', () => {
    const conflicted = rebind(
      connectionLost(edit(startDraft('d1', target, 0), 'text', 1)),
      { ...target, agentBindingRevision: '9' },
      'att-2'
    )
    expect(submittable(conflicted)).toBe(false)
    expect(notSubmittableBecause(conflicted)).toMatch(/Choose where this draft should go/)

    const retargeted = retarget(conflicted, { ...target, agentBindingRevision: '9' }, 'att-2')
    expect(retargeted.state).toBe('bound')
    expect(submittable(retargeted)).toBe(true)
  })

  it('retains the draft on every refused insertion and offers the terminal workflow', () => {
    for (const code of ['DRAFT_CONFLICT', 'LEASE_LOST', 'EDITOR_BUSY', 'SOMETHING_ELSE']) {
      const refusal = readInsertionRefusal(code)
      expect(refusal.retained).toBe(true)
      expect(refusal.fallback).toMatch(/terminal/)
    }
    expect(readInsertionRefusal('DRAFT_CONFLICT').fallback).toMatch(/qualified boundary/)
  })
})

describe('declarative controls', () => {
  it('answers three values, so an unknown fact is not a false one', () => {
    const state = emptyControlState()
    expect(evaluate({ op: 'always' }, state)).toBe('true')
    expect(evaluate({ op: 'never' }, state)).toBe('false')
    expect(evaluate({ op: 'capability', capability: 'terminal.input', state: 'qualified_available' }, state)).toBe(
      'unknown'
    )
  })

  it('does not show a control whose condition it cannot evaluate, even under a negation', () => {
    const control = {
      id: 'c1',
      revision: '1',
      label: 'Do the thing',
      accessible_description: 'Do the thing',
      action_id: 'thing',
      visible_when: {
        op: 'not' as const,
        term: { op: 'capability' as const, capability: 'terminal.input', state: 'qualified_available' }
      }
    }
    expect(visibilityOf(control, emptyControlState()).kind).toBe('hidden')
  })

  it('shows a control whose usability is unknown, and does not enable it', () => {
    const control = {
      id: 'c1',
      revision: '1',
      label: 'Do the thing',
      accessible_description: 'Do the thing',
      action_id: 'thing',
      enabled_when: { op: 'flag' as const, flag: 'ready' }
    }
    const visibility = visibilityOf(control, emptyControlState())
    expect(visibility.kind).toBe('shown')
    if (visibility.kind === 'shown') {
      expect(visibility.enabled).toBe(false)
      expect(visibility.disabledReason).toMatch(/cannot tell/)
    }
  })

  it('uses the published operator names, so a real control evaluates', () => {
    const state = {
      ...emptyControlState(),
      bindingState: 'bound',
      presentNodes: new Set(['n-1'])
    }
    expect(evaluate({ op: 'binding', state: 'bound' }, state)).toBe('true')
    expect(evaluate({ op: 'binding', state: 'disabled' }, state)).toBe('false')
    expect(evaluate({ op: 'node_present', node_id: 'n-1' }, state)).toBe('true')
    expect(evaluate({ op: 'node_present', node_id: 'n-2' }, state)).toBe('false')
  })

  it('does not treat an unknown right as a right the client does not hold', () => {
    expect(evaluate({ op: 'grant', right: 'terminal.input' }, emptyControlState())).toBe('unknown')
    expect(
      evaluate(
        { op: 'grant', right: 'terminal.input' },
        { ...emptyControlState(), rights: new Set(['session.view']) }
      )
    ).toBe('false')
  })

  it('answers an empty combinator the way the host does', () => {
    expect(evaluate({ op: 'all', terms: [] }, emptyControlState())).toBe('true')
    expect(evaluate({ op: 'any', terms: [] }, emptyControlState())).toBe('false')
  })

  it('bounds the predicate depth rather than recursing on a deep one', () => {
    let predicate = { op: 'always' } as Parameters<typeof evaluate>[0]
    for (let index = 0; index < 12; index += 1) predicate = { op: 'not', term: predicate }
    expect(evaluate(predicate, emptyControlState())).toBe('unknown')
  })

  it('knows exactly which node kinds it draws', () => {
    expect(isRendered('markdown')).toBe(true)
    expect(isRendered('command_palette')).toBe(true)
    expect(isRendered('holographic_widget')).toBe(false)
  })
})

describe('the raw terminal', () => {
  const drawsEverything = () => true
  const drawsNothingWide = (cluster: string) => [...cluster].length === 1

  it('draws a cluster it can reproduce, unchanged', () => {
    const drawn = drawCell({ text: 'a', width: 1 }, drawsEverything)
    expect(drawn).toEqual({ text: 'a', columns: 1, substituted: false, original: null })
  })

  it('replaces an unreproducible cluster with exactly its own column count', () => {
    const drawn = drawCell({ text: '\u{1F468}‍\u{1F469}‍\u{1F467}', width: 2 }, drawsNothingWide)
    expect(drawn.columns).toBe(2)
    expect(drawn.text).toBe(REPLACEMENT.repeat(2))
    expect(drawn.substituted).toBe(true)
  })

  it('clips to the base character when the marks are what cannot be composed', () => {
    const drawn = drawCell({ text: 'é̂̃', width: 1 }, (cluster) => cluster === 'e')
    expect(drawn.text).toBe('e')
    expect(drawn.columns).toBe(1)
    expect(drawn.substituted).toBe(true)
  })

  it('never moves a following cell, whatever it had to substitute', () => {
    const cells = [
      { text: 'o', width: 1 },
      { text: 'k', width: 1 },
      { text: '\u{1F468}‍\u{1F469}‍\u{1F467}', width: 2 },
      { text: '', width: 0 },
      { text: '!', width: 1 }
    ]
    const reproduced = drawRow(cells, drawsEverything)
    const substituted = drawRow(cells, drawsNothingWide)
    expect(substituted.columns).toBe(reproduced.columns)
    expect(substituted.text.endsWith('!')).toBe(true)
    expect(substituted.substituted).toBe(1)
  })

  it('gives the wheel to the application in control mode, whatever is held', () => {
    expect(routeWheel('control', { deltaX: 0, deltaY: 48, zoomGesture: false })).toEqual({
      kind: 'application',
      lines: 3
    })
    expect(routeWheel('control', { deltaX: 0, deltaY: 48, zoomGesture: true })).toEqual({
      kind: 'application',
      lines: 3
    })
  })

  it('pans and zooms only in view mode', () => {
    expect(routeWheel('view', { deltaX: 16, deltaY: 32, zoomGesture: false })).toEqual({
      kind: 'pan',
      rows: 2,
      columns: 1
    })
    expect(routeWheel('view', { deltaX: 0, deltaY: -16, zoomGesture: true })).toEqual({
      kind: 'zoom',
      steps: 1
    })
  })

  it('keeps the zoom inside its own range', () => {
    expect(zoomBy(0, -5)).toBe(0)
    expect(zoomBy(ZOOM_STEPS.length - 1, 5)).toBe(ZOOM_STEPS.length - 1)
  })
})

describe('motion', () => {
  it('settles without overshooting when it is critically damped', () => {
    let state = { value: 400, velocity: 0 }
    let maximumBelowTarget = 0
    for (let step = 0; step < 240; step += 1) {
      state = stepSpring(state, 0, { damping: 1, response: 0.35 }, 1 / 60)
      maximumBelowTarget = Math.min(maximumBelowTarget, state.value)
    }
    expect(Math.abs(state.value)).toBeLessThan(0.5)
    expect(maximumBelowTarget).toBeGreaterThan(-1)
  })

  it('projects a flick further the faster it was', () => {
    expect(projectEndpoint(0, 1000)).toBeGreaterThan(projectEndpoint(0, 500))
    expect(projectEndpoint(100, 0)).toBe(100)
  })

  it('resists more the further past the boundary a drag goes', () => {
    const little = rubberband(20, 400)
    const lot = rubberband(200, 400)
    expect(little).toBeLessThan(20)
    expect(lot).toBeLessThan(200)
    expect(lot / 200).toBeLessThan(little / 20)
  })

  it('dismisses on a flick that has barely moved, and not on a slow drag that has not', () => {
    expect(shouldDismiss(30, 1500, 400)).toBe(true)
    expect(shouldDismiss(30, 0, 400)).toBe(false)
    expect(shouldDismiss(260, 0, 400)).toBe(true)
  })

  it('does not dismiss when the gesture reversed, however far it had travelled', () => {
    expect(shouldDismiss(300, -900, 400)).toBe(false)
  })
})

describe('the frame scheduler', () => {
  it('uses the animation frame when there is one', () => {
    const frame = vi.fn((callback: FrameRequestCallback) => {
      callback(0)
      return 1
    })
    vi.stubGlobal('requestAnimationFrame', frame)
    const flushed: number[][] = []
    const batcher = new FrameBatcher<number>((batch) => {
      flushed.push([...batch])
    })
    batcher.push(1)
    expect(frame).toHaveBeenCalledOnce()
    expect(flushed).toEqual([[1]])
    vi.unstubAllGlobals()
  })
})
