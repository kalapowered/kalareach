/**
 * What a declarative control shows, and whether a person may invoke it.
 *
 * A package contributes a control with a stable identity, a registered action, a parameter schema
 * and two bounded predicates: one for whether it is visible and one for whether it is usable. The
 * grammar has no scripts and this evaluator has no way to run one. Every answer is one of three,
 * because a client may simply not know a fact, and treating an unknown as false would, under a
 * `not`, show a control the package meant to hide.
 *
 * The host rechecks the condition when the action is invoked. This is what the person sees, not
 * what is permitted.
 */

/** A fact the client either knows or does not. */
export type Truth = 'true' | 'false' | 'unknown'

/** What the client knows about this session right now. */
export interface ControlState {
  /** Capability states by capability name. */
  readonly capabilities: ReadonlyMap<string, string>
  /** The rights this connection holds, or null when the client has not been told. */
  readonly rights: ReadonlySet<string> | null
  /** The binding's state, when the client knows it. */
  readonly bindingState: string | null
  /** The nodes present in the document. */
  readonly presentNodes: ReadonlySet<string>
  /** Presentation flags the client has been told about. */
  readonly flags: ReadonlyMap<string, boolean>
}

/** An empty state: nothing known, which hides everything conditional. */
export function emptyControlState(): ControlState {
  return {
    capabilities: new Map(),
    rights: null,
    bindingState: null,
    presentNodes: new Set(),
    flags: new Map()
  }
}

/** The predicate grammar, as the package contract types it. */
export type Predicate =
  | { readonly op: 'always' }
  | { readonly op: 'never' }
  | { readonly op: 'not'; readonly term: Predicate }
  | { readonly op: 'all'; readonly terms: readonly Predicate[] }
  | { readonly op: 'any'; readonly terms: readonly Predicate[] }
  | { readonly op: 'capability'; readonly capability: string; readonly state: string }
  | { readonly op: 'grant'; readonly right: string }
  | { readonly op: 'binding'; readonly state: string }
  | { readonly op: 'node_present'; readonly node_id: string }
  | { readonly op: 'flag'; readonly flag: string }

/** The bounds the contract puts on a predicate, repeated here so the client applies them too. */
export const MAX_PREDICATE_DEPTH = 4
export const MAX_PREDICATE_TERMS = 8

/** Evaluates a predicate against what the client knows. */
export function evaluate(predicate: Predicate, state: ControlState, depth = 0): Truth {
  if (depth > MAX_PREDICATE_DEPTH) return 'unknown'
  switch (predicate.op) {
    case 'always':
      return 'true'
    case 'never':
      return 'false'
    case 'not': {
      const inner = evaluate(predicate.term, state, depth + 1)
      if (inner === 'unknown') return 'unknown'
      return inner === 'true' ? 'false' : 'true'
    }
    case 'all': {
      // An empty `all` is vacuously true and an empty `any` vacuously false, which is what the
      // host's own evaluator answers. A client that disagreed would show or hide a control the
      // host would then decide differently about.
      if (predicate.terms.length > MAX_PREDICATE_TERMS) return 'unknown'
      let sawUnknown = false
      for (const term of predicate.terms) {
        const value = evaluate(term, state, depth + 1)
        if (value === 'false') return 'false'
        if (value === 'unknown') sawUnknown = true
      }
      return sawUnknown ? 'unknown' : 'true'
    }
    case 'any': {
      if (predicate.terms.length > MAX_PREDICATE_TERMS) return 'unknown'
      let sawUnknown = false
      for (const term of predicate.terms) {
        const value = evaluate(term, state, depth + 1)
        if (value === 'true') return 'true'
        if (value === 'unknown') sawUnknown = true
      }
      return sawUnknown ? 'unknown' : 'false'
    }
    case 'capability': {
      const known = state.capabilities.get(predicate.capability)
      if (known === undefined) return 'unknown'
      return known === predicate.state ? 'true' : 'false'
    }
    case 'grant':
      // A client that has not been told which rights it holds does not know. Answering "false"
      // would, under a negation, show a control the package's condition meant to hide.
      if (state.rights === null) return 'unknown'
      return state.rights.has(predicate.right) ? 'true' : 'false'
    case 'binding':
      if (state.bindingState === null) return 'unknown'
      return state.bindingState === predicate.state ? 'true' : 'false'
    case 'node_present':
      return state.presentNodes.has(predicate.node_id) ? 'true' : 'false'
    case 'flag': {
      const flag = state.flags.get(predicate.flag)
      if (flag === undefined) return 'unknown'
      return flag ? 'true' : 'false'
    }
    default:
      // A predicate this client does not understand hides the control. A client that showed it
      // would be showing something the package's own condition may have meant to hide.
      return 'unknown'
  }
}

/** What the interface does with a control. */
export type Visibility =
  | { readonly kind: 'shown'; readonly enabled: boolean; readonly disabledReason: string | null }
  | { readonly kind: 'hidden'; readonly because: string }

/** One control, in the shape the package contract publishes. */
export interface Control {
  readonly id: string
  readonly revision: string
  readonly label: string
  readonly accessible_description: string
  readonly action_id: string
  readonly icon?: string
  readonly priority?: string
  readonly disabled_reason?: { readonly text?: string } | string | null
  readonly visible_when?: Predicate
  readonly enabled_when?: Predicate
}

/** Decides what to do with one control. */
export function visibilityOf(control: Control, state: ControlState): Visibility {
  const visible = control.visible_when
    ? evaluate(control.visible_when, state)
    : ('true' as Truth)
  if (visible === 'false') return { kind: 'hidden', because: 'its condition is not met' }
  if (visible === 'unknown') {
    return { kind: 'hidden', because: 'this client does not know whether its condition is met' }
  }
  const enabled = control.enabled_when ? evaluate(control.enabled_when, state) : ('true' as Truth)
  return {
    kind: 'shown',
    // A control whose usability is unknown is shown and not usable. Showing it keeps the layout
    // stable; enabling it would invite an invocation the host would refuse.
    enabled: enabled === 'true',
    disabledReason:
      enabled === 'true'
        ? null
        : (disabledText(control) ??
          (enabled === 'unknown'
            ? 'This device cannot tell whether this is available.'
            : 'Not available right now.'))
  }
}

function disabledText(control: Control): string | null {
  const reason = control.disabled_reason
  if (typeof reason === 'string') return reason
  if (reason && typeof reason === 'object' && typeof reason.text === 'string') return reason.text
  return null
}

/** An unknown node's block, which can invoke nothing. */
export interface UnsupportedNode {
  readonly id: string
  readonly kind: string
}

/**
 * Reads a document node body, separating what this client renders from what it does not.
 *
 * A node kind this client does not know renders an unsupported-content block. That block carries no
 * action, which is the point: a package must not be able to reach an action by sending a shape the
 * client will guess at.
 */
export function readNodeKind(body: unknown): string {
  if (typeof body === 'object' && body !== null && 'kind' in body) {
    const kind = (body).kind
    if (typeof kind === 'string') return kind
  }
  return 'unknown'
}

/** The node kinds this client draws. */
export const RENDERED_NODE_KINDS = [
  'message',
  'markdown',
  'tool',
  'diff',
  'progress',
  'form',
  'attachment',
  'approval_ref',
  'terminal_ref',
  'action_button',
  'action_group',
  'command_palette',
  'attachment_entry'
] as const

/** Whether this client has a renderer for a node kind. */
export function isRendered(kind: string): boolean {
  return (RENDERED_NODE_KINDS as readonly string[]).includes(kind)
}
