/**
 * The conversation: stable identities, a bounded window, and where the view is anchored.
 *
 * Section 13 asks for four things together and they are one design. Nodes are keyed by their stable
 * identifier, so a revision replaces a node rather than adding one. The rendered set is bounded, so
 * a session with fifty thousand nodes renders the same number of elements as one with fifty. New
 * output is followed only while the view is at the live end. And when older content is loaded, the
 * anchor the person is looking at keeps its place rather than jumping.
 */

import type { DocumentNode } from '@kalareach/plugin-sdk'

/** How many nodes are rendered at once. */
export const WINDOW_SIZE = 120

/** How many nodes above and below the window are kept ready, so a scroll does not tear. */
export const WINDOW_OVERSCAN = 20

/** Where the reader is. */
export interface Anchor {
  /** The node the view is holding in place. */
  readonly nodeId: string
  /** How far that node's top is from the top of the viewport, in pixels. */
  readonly offset: number
}

/** The conversation's state. */
export interface ConversationState {
  /** Every node, in order, keyed by identity. */
  readonly nodes: readonly DocumentNode[]
  /** True while the view is at the live end and should follow new output. */
  readonly following: boolean
  /** Where the reader is, while they are not following. */
  readonly anchor: Anchor | null
  /** The first index of the rendered window. */
  readonly windowStart: number
}

/** An empty conversation, following the live end. */
export function emptyConversation(): ConversationState {
  return { nodes: [], following: true, anchor: null, windowStart: 0 }
}

/**
 * Folds one node in, replacing a node with the same identity.
 *
 * A revision that is not newer is ignored: an out-of-order delivery must not take the view
 * backwards.
 */
export function applyNode(state: ConversationState, node: DocumentNode): ConversationState {
  const index = state.nodes.findIndex((existing) => existing.id === node.id)
  if (index === -1) {
    const nodes = [...state.nodes, node]
    return follow({ ...state, nodes })
  }
  const existing = state.nodes[index]
  if (existing && !isNewer(node.revision, existing.revision)) return state
  const nodes = [...state.nodes]
  nodes[index] = node
  return { ...state, nodes }
}

/** Folds a batch in as one change, which is what one animation frame publishes. */
export function applyNodes(
  state: ConversationState,
  batch: readonly DocumentNode[]
): ConversationState {
  return batch.reduce(applyNode, state)
}

/**
 * Prepends a page of older nodes and keeps the reader's anchor.
 *
 * The window moves by exactly the number of nodes that were added, so the node the person was
 * looking at is still at the same place in the rendered window.
 */
export function prependHistory(
  state: ConversationState,
  older: readonly DocumentNode[]
): ConversationState {
  if (older.length === 0) return state
  const known = new Set(state.nodes.map((node) => node.id))
  const added = older.filter((node) => !known.has(node.id))
  if (added.length === 0) return state
  return {
    ...state,
    nodes: [...added, ...state.nodes],
    windowStart: state.windowStart + added.length,
    following: false
  }
}

/** Records that the view reached the live end, or left it. */
export function setFollowing(state: ConversationState, following: boolean): ConversationState {
  if (state.following === following) return state
  return following
    ? follow({ ...state, following: true, anchor: null })
    : { ...state, following: false }
}

/** Records where the reader is, so a page of history can keep it. */
export function setAnchor(state: ConversationState, anchor: Anchor | null): ConversationState {
  return { ...state, anchor }
}

/** Moves the window, for a view that scrolled away from the end. */
export function setWindowStart(state: ConversationState, start: number): ConversationState {
  const clamped = Math.max(0, Math.min(start, Math.max(0, state.nodes.length - WINDOW_SIZE)))
  if (clamped === state.windowStart) return state
  return { ...state, windowStart: clamped, following: false }
}

/** The nodes the view actually renders. */
export function visibleNodes(state: ConversationState): readonly DocumentNode[] {
  const start = Math.max(0, state.windowStart - WINDOW_OVERSCAN)
  const end = Math.min(state.nodes.length, state.windowStart + WINDOW_SIZE + WINDOW_OVERSCAN)
  return state.nodes.slice(start, end)
}

/** How many nodes are above the rendered window, which is the space a scrollbar needs. */
export function nodesAbove(state: ConversationState): number {
  return Math.max(0, state.windowStart - WINDOW_OVERSCAN)
}

/** How many nodes are below it. */
export function nodesBelow(state: ConversationState): number {
  return Math.max(
    0,
    state.nodes.length - (state.windowStart + WINDOW_SIZE + WINDOW_OVERSCAN)
  )
}

/** Puts the window at the live end, where a following view keeps it. */
function follow(state: ConversationState): ConversationState {
  if (!state.following) return state
  return { ...state, windowStart: Math.max(0, state.nodes.length - WINDOW_SIZE) }
}

/**
 * Whether one revision supersedes another.
 *
 * A revision is a decimal string on the wire and can be longer than a safe integer, so it is
 * compared by length and then lexically rather than as a number.
 */
export function isNewer(candidate: string, existing: string): boolean {
  const left = candidate.replace(/^0+(?=\d)/, '')
  const right = existing.replace(/^0+(?=\d)/, '')
  if (left.length !== right.length) return left.length > right.length
  return left > right
}
