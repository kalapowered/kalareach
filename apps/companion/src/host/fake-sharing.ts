/**
 * The scripted host's sharing: the grants it has issued, the invitations being written, the
 * hand-overs waiting for an owner device, and the attempts native code keeps its word about.
 *
 * It answers as the real commands do. The four actions that change who holds a session (an
 * invitation, an acceptance, a withdrawal and a hand-over of control) each answer with the attempt
 * and the host's result; an answer the connection lost leaves the attempt unfinished, with the
 * action written or not, and the page reads where it stands from the list of attempts. What a
 * test can do to the host is in [`FakeSharing`]: it changes the screen, loses an answer or a
 * request, lets the application's repeats succeed, passes the bound that keeps a read from
 * counting, holds a revocation's barrier, and answers for the owner device.
 */

import type {
  DeviceSummary,
  GrantCreateParams,
  GrantCreateResult,
  GrantListParams,
  GrantListResult,
  GrantRedeemParams,
  GrantRedeemResult,
  GrantRevokeParams,
  GrantSummary,
  GrantTransferParams,
  GrantTransferResult,
  HeldShare,
  RevocationResult,
  RoleSelection,
  SessionScreenPreviewResult,
  ShareOffer
} from '@kalareach/protocol'

import { FakeHostError } from './fake'
import {
  GRANT_CREATE_PARAMS,
  GRANT_LIST_PARAMS,
  GRANT_REDEEM_PARAMS,
  GRANT_REVOKE_PARAMS,
  GRANT_TRANSFER_PARAMS,
  PREVIEW_PARAMS,
  decodeParams
} from './fake-decode'
import { actionsOf, idOf, noticesFor } from './fake-state'
import type {
  AttemptKind,
  AttemptOutcome,
  AttemptPhase,
  AttemptView,
  Attempted,
  Attempts,
  HandoverAsked,
  HandoverState,
  Held
} from './port'

function refuse(code: string, message: string): never {
  // eslint-disable-next-line @typescript-eslint/only-throw-error -- a command's failure crosses as data
  throw new FakeHostError(code, message).toPayload()
}

/** The identities and the clock the sharing is written against. */
export interface SharingIds {
  readonly environment: string
  /** The session an invitation to the phone is about, until a test says another. */
  readonly session: string
  readonly nowMs: number
  /** The device the host issues from: itself. */
  readonly issuer: string
}

/** What an invitation to the phone is, where a test does not say. */
export interface OfferSpec {
  /** The session's number on the host. */
  readonly session?: string
  readonly role?: RoleSelection['role']
  /** Whether the live view of the screen is included. */
  readonly live?: boolean
  /** How long the invitation lasts from now, in milliseconds. */
  readonly lastsMs?: number
  /** Where the session's history begins, in milliseconds before now. */
  readonly historyFromAgoMs?: number
}

/** What a test can do to the scripted host's sharing. */
export interface FakeSharing {
  /**
   * The host is one the phone is paired with: it tells the device what it is offered and holds, and
   * the device accepts an invitation rather than issuing one. Before this the host is the one on
   * the computer, which holds no share of itself and refuses both reads.
   */
  asPhone(): void
  /** The host issues an invitation that names this device. */
  offer(spec?: OfferSpec): ShareOffer
  /** The host's invitation goes: withdrawn by its issuer, or run out. */
  withdrawOffer(invitationId: string): void
  /** The host stops listing a share the device holds: taken back, run out or its session gone. */
  endShare(grantId: string): void
  /** The shares the device holds, as the host would list them. */
  held(): readonly HeldShare[]
  /** The next read of what is held fails the way a lost connection does, for any reason but the host's refusal of the method. */
  failNextHeld(message: string): void
  /** The host answers the read of what is held as one built before the method existed does. */
  doesNotServeHeld(): void
  /** How many times the page has asked what the device is offered and holds. */
  heldReads(): number
  /**
   * The host refuses the next acceptance in its words. `committed` says whether it had written the
   * share before it refused, as the paired door can when the bounds of its decision end first.
   */
  refuseNextRedeem(message: string, committed: boolean): void
  /** The grants the host holds, resolved ones included. */
  grants(): readonly GrantSummary[]
  /** The attempts native code keeps, as the list of them would show. */
  attempts(): readonly AttemptView[]
  /** Changes the lines on the session's screen, cut or whole. */
  setScreen(lines: readonly string[], truncated?: boolean): void
  /** The reads of the screen fail with the session's own words, until it is told otherwise. */
  failPreview(message: string | null): void
  /** The host's answer to the next action is lost: the host wrote it, the page was not told. */
  loseNextAnswer(): void
  /** The next action never reaches the host: nothing is written, the page was not told. */
  loseNextRequest(): void
  /**
   * The application's repeats are answered from the host's record: every attempt whose action the
   * host wrote closes as happened with the host's result.
   */
  recover(): void
  /**
   * The bound that keeps an absent grant from counting has passed: an attempt the host never saw
   * closes as not done, and one it wrote closes as happened, without its result.
   */
  passTheBound(): void
  /** The next revocation's barrier has a worker that has not fenced it, until told otherwise. */
  holdBarrier(held: boolean): void
  /**
   * The host's answer to the next hand-over that is sent is held until the test lets it go: the
   * hand-over is sent at once, and the page is told how it went only then.
   */
  holdNextFinish(): FinishHold
  /** An owner device answers the confirmation every waiting hand-over asks for. */
  ownerAnswers(): void
  /** The confirmation every waiting hand-over asks for runs out before an owner device answers. */
  challengeRunsOut(): void
  /** The device an invitation names accepts it: the grant becomes active. */
  deviceAccepts(grantId: string): void
  /**
   * The application is stopped and started again: nothing it was carrying on goes on, a hand-over
   * that was being asked for has no reference left, and the host's results it held in memory are
   * gone. What it kept in its records stays.
   */
  restart(): void
  /**
   * The bound that keeps an absent grant from counting has passed and no read of the host has been
   * answered: an attempt that is not over says nothing of until when it can still happen.
   */
  lapse(): void
  /** How many records native code keeps that this build does not read, which the page counts. */
  setUnreadable(count: number): void
  /** How many times the page has sent each action, by kind. */
  sent(): Readonly<Record<AttemptKind, number>>
}

/** A hand-over's answer held back, and what the test does with it. */
export interface FinishHold {
  /** The host's answer arrives. */
  give(): void
  /** The send fails with the host's own words. */
  refuse(code: string, message: string): void
}

/** The most lines a preview carries before it is cut. */
export const PREVIEW_LINES = 40

/** The screen the session shows until a test changes it. */
export const SCREEN: readonly string[] = [
  '$ cargo test -p kr-client --test session',
  '   Compiling kr-client v0.1.0',
  'running 24 tests',
  'test reconnect_000 ... ok',
  '$ '
]

/** One attempt, and what the host did with its action. */
interface Entry {
  view: AttemptView
  /** Whether it is an invitation that includes the live view of the screen. */
  live: boolean
  /** Whether the host wrote the action. */
  written: boolean
  /** What the host answered, for the repeat that is answered from its record. */
  result: unknown
}

/** One hand-over, between the confirmation being asked for and the transfer being sent. */
interface Handover {
  reference: string
  params: GrantTransferParams
  entry: Entry
  expiresAtMs: number
  state: 'waiting' | 'answered' | 'gone'
  fromName: string
  toName: string
}

type Devices = () => readonly DeviceSummary[]

export class ScriptedSharing implements FakeSharing {
  readonly #ids: SharingIds
  readonly #devices: Devices
  readonly #known: (sessionId: string) => void
  readonly #grants: GrantSummary[] = []
  readonly #entries: Entry[] = []
  readonly #handovers = new Map<string, Handover>()
  #screen: { lines: readonly string[]; truncated: boolean } = { lines: SCREEN, truncated: false }
  #previewFailure: string | null = null
  #lose: 'none' | 'answer' | 'request' = 'none'
  #barrierHeld = false
  #finishHold: { release: () => void; fail: (failure: unknown) => void; held: Promise<void> } | null = null
  #unreadable = 0
  #phone = false
  #offers: ShareOffer[] = []
  #holds: HeldShare[] = []
  #heldFailure: string | null = null
  #heldServed = true
  #heldReads = 0
  #redeemRefusal: { message: string; committed: boolean } | null = null
  #offered = 0
  #actions = 0
  #references = 0
  #sent: Record<AttemptKind, number> = { invite: 0, redeem: 0, revoke: 0, transfer: 0 }

  constructor(ids: SharingIds, devices: Devices, known: (sessionId: string) => void) {
    this.#ids = ids
    this.#devices = devices
    this.#known = known
  }

  /* ---- What a test does ----------------------------------------------------------------------- */

  grants(): readonly GrantSummary[] {
    return this.#grants
  }

  attempts(): readonly AttemptView[] {
    return this.#entries.map((entry) => entry.view)
  }

  setScreen(lines: readonly string[], truncated = false): void {
    this.#screen = { lines, truncated }
  }

  failPreview(message: string | null): void {
    this.#previewFailure = message
  }

  loseNextAnswer(): void {
    this.#lose = 'answer'
  }

  loseNextRequest(): void {
    this.#lose = 'request'
  }

  recover(): void {
    for (const entry of this.#entries) {
      if (entry.view.phase === 'closed' || entry.view.phase === 'asking' || !entry.written) continue
      this.#close(entry, 'happened', entry.result)
    }
  }

  passTheBound(): void {
    for (const entry of this.#entries) {
      if (entry.view.phase === 'closed' || entry.view.phase === 'asking') continue
      if (entry.written) this.#close(entry, 'happened', null)
      else this.#close(entry, entry.view.kind === 'redeem' ? 'not_accepted' : 'not_done', null)
    }
  }

  holdBarrier(held: boolean): void {
    this.#barrierHeld = held
  }

  holdNextFinish(): FinishHold {
    let release: () => void = () => undefined
    let fail: (failure: unknown) => void = () => undefined
    const held = new Promise<void>((resolve, reject) => {
      release = resolve
      fail = reject
    })
    this.#finishHold = { release, fail, held }
    return {
      give: () => {
        release()
      },
      refuse: (code, message) => {
        fail(new FakeHostError(code, message).toPayload())
      }
    }
  }

  ownerAnswers(): void {
    for (const handover of this.#handovers.values()) {
      if (handover.state === 'waiting') handover.state = 'answered'
    }
  }

  challengeRunsOut(): void {
    for (const handover of this.#handovers.values()) {
      if (handover.state === 'waiting') handover.state = 'gone'
    }
  }

  deviceAccepts(grantId: string): void {
    const summary = this.#grants.find((each) => each.grant.grant_id === grantId)
    if (summary === undefined || summary.state !== 'pending') return
    summary.state = 'active'
  }

  restart(): void {
    // Nothing is carried on after a restart: an attempt waits for the person, and a hand-over
    // that was being asked for has nothing the application can finish. A result held in memory
    // for the page is gone with the process; the host's record of the action still has it.
    this.#handovers.clear()
    for (const entry of this.#entries) {
      entry.view = { ...entry.view, result: null }
    }
  }

  lapse(): void {
    for (const entry of this.#entries) {
      if (entry.view.phase === 'closed') continue
      entry.view = { ...entry.view, can_happen_until_ms: null }
    }
  }

  setUnreadable(count: number): void {
    this.#unreadable = count
  }

  sent(): Readonly<Record<AttemptKind, number>> {
    return this.#sent
  }

  asPhone(): void {
    this.#phone = true
  }

  offer(spec: OfferSpec = {}): ShareOffer {
    this.#offered += 1
    const selection = {
      role: spec.role ?? 'viewer',
      include_live_screen: spec.live ?? false,
      include_question_respond: false,
      history_from_cursor_ms: null
    } as unknown as RoleSelection
    const actions = actionsOf(selection)
    const offer: ShareOffer = {
      actions,
      display_number: spec.session ?? '3',
      ends_at_ms: String(this.#ids.nowMs + (spec.lastsMs ?? 3_600_000)),
      grant_id: idOf('e7e7e7e7', 2000 + this.#offered),
      history_from_ms: String(this.#ids.nowMs - (spec.historyFromAgoMs ?? 600_000)),
      includes_live_screen: spec.live ?? false,
      invitation_id: idOf('e9e9e9e9', 2000 + this.#offered),
      issued_at_ms: String(this.#ids.nowMs + this.#offered),
      notices: noticesFor(actions),
      role: selection.role,
      session_id: this.#ids.session
    }
    this.#offers.push(offer)
    return offer
  }

  withdrawOffer(invitationId: string): void {
    this.#offers = this.#offers.filter((offer) => offer.invitation_id !== invitationId)
  }

  endShare(grantId: string): void {
    this.#holds = this.#holds.filter((share) => share.grant.grant_id !== grantId)
  }

  held(): readonly HeldShare[] {
    return this.#holds
  }

  failNextHeld(message: string): void {
    this.#heldFailure = message
  }

  doesNotServeHeld(): void {
    this.#heldServed = false
  }

  heldReads(): number {
    return this.#heldReads
  }

  refuseNextRedeem(message: string, committed: boolean): void {
    this.#redeemRefusal = { message, committed }
  }

  /* ---- The commands --------------------------------------------------------------------------- */

  sessionScreenPreview(params: unknown): SessionScreenPreviewResult {
    const read = decodeParams<{ session_id: string; selection: RoleSelection }>(
      params,
      PREVIEW_PARAMS
    )
    this.#known(read.session_id)
    if (this.#previewFailure !== null) refuse('UNKNOWN_SESSION', this.#previewFailure)
    if (!read.selection.include_live_screen) return { screen: null }
    return { screen: { lines: [...this.#screen.lines], truncated: this.#screen.truncated } }
  }

  grantList(params: unknown): GrantListResult {
    const read = decodeParams<GrantListParams>(params, GRANT_LIST_PARAMS)
    const names = (summary: GrantSummary): boolean => {
      const selector = summary.grant.session_selector
      return (
        read.session_id === null ||
        (typeof selector === 'object' && selector.these.session_ids.includes(read.session_id))
      )
    }
    return {
      grants: this.#grants.filter(
        (summary) =>
          names(summary) &&
          (read.include_resolved || summary.state === 'pending' || summary.state === 'active')
      )
    }
  }

  grantCreate(params: unknown): Attempted<GrantCreateResult> {
    const read = decodeParams<GrantCreateParams>(params, GRANT_CREATE_PARAMS)
    this.#gate(
      (entry) =>
        entry.view.kind === 'invite' &&
        entry.view.session_id === read.session_id &&
        entry.view.device_id === read.recipient_device_id,
      'An invitation of this session to this device'
    )
    const recipient = this.#recipientOf(read)
    const entry = this.#begin(
      'invite',
      `Invitation of the session to ${recipient.display_name}`,
      read.session_id,
      read.recipient_device_id
    )
    entry.live = read.selection.include_live_screen
    const lost = this.#lost(entry)
    // A request that never reached the host wrote nothing.
    if (lost && !entry.written) return this.#unfinished(entry)
    const result = this.#write(read, recipient)
    entry.view = { ...entry.view, grant_id: result.grant.grant_id }
    if (lost) {
      entry.result = result
      return this.#unfinished(entry)
    }
    return this.#answer(entry, result)
  }

  grantRevoke(params: unknown): Attempted<RevocationResult> {
    const read = decodeParams<GrantRevokeParams>(params, GRANT_REVOKE_PARAMS)
    const grant = this.#grants.find((summary) => summary.grant.grant_id === read.grant_id)
    if (grant === undefined) {
      refuse('RESOURCE_UNAVAILABLE', 'the host holds no such share, so nothing was revoked')
    }
    const entry = this.#begin(
      'revoke',
      `Taking back the access of ${this.#nameOf(grant.grant.recipient_device_id)}`,
      null,
      grant.grant.recipient_device_id,
      read.grant_id,
      'composed',
      read.grant_id
    )
    if (this.#lost(entry)) {
      if (entry.written) this.#revoke(grant)
      entry.result = this.#revocation(grant)
      return this.#unfinished(entry)
    }
    this.#revoke(grant)
    return this.#answer(entry, this.#revocation(grant))
  }

  grantRedeem(params: unknown): Attempted<GrantRedeemResult> {
    const read = decodeParams<GrantRedeemParams>(params, GRANT_REDEEM_PARAMS)
    if (!this.#phone) return this.#owner()
    const offer = this.#offers.find((each) => each.invitation_id === read.invitation_id)
    if (offer === undefined) {
      refuse('RESOURCE_UNAVAILABLE', 'that invitation is no longer offered to this device')
    }
    const entry = this.#begin(
      'redeem',
      `Accepting session ${offer.display_number}`,
      offer.session_id,
      null,
      offer.grant_id
    )
    const refusal = this.#redeemRefusal
    this.#redeemRefusal = null
    if (refusal !== null) {
      // The paired door can answer a committed redemption with a refusal, so a refusal to the first
      // send is a reason to read what the host shows and not the end of the attempt.
      entry.written = refusal.committed
      if (refusal.committed) this.#take(offer)
      entry.result = this.#redeemed(offer)
      entry.view = { ...entry.view, refusal: refusal.message }
      this.#set(entry, 'checking')
      return { attempt: entry.view, value: null }
    }
    if (this.#lost(entry)) {
      if (entry.written) this.#take(offer)
      entry.result = this.#redeemed(offer)
      return this.#unfinished(entry)
    }
    this.#take(offer)
    return this.#answer(entry, this.#redeemed(offer))
  }

  grantHeld(): Held {
    if (!this.#phone) return this.#owner()
    this.#heldReads += 1
    if (!this.#heldServed) {
      refuse('PERMISSION_DENIED', 'the effect is not listed for this actor')
    }
    const failure = this.#heldFailure
    this.#heldFailure = null
    if (failure !== null) refuse('UPSTREAM_UNAVAILABLE', failure)
    return { offers: [...this.#offers], shares: [...this.#holds] }
  }

  transferAsk(params: unknown, session: { sessionId?: string }): HandoverAsked {
    const read = decodeParams<GrantTransferParams>(params, GRANT_TRANSFER_PARAMS)
    if (session.sessionId !== read.session_id) {
      refuse('INVALID_ARGUMENT', 'the hand-over and the session it is for are not the same session')
    }
    this.#gate(
      (entry) => entry.view.kind === 'transfer' && entry.view.session_id === read.session_id,
      'A hand-over of this session'
    )
    const devices = this.#devices()
    if (!devices.some((device) => device.manages_host && !device.revoked && !device.grant_expired)) {
      refuse(
        'OWNER_CONFIRMATION_REQUIRED',
        'no owner device is paired with this host, so nobody can confirm a hand-over of control; pair one first'
      )
    }
    const receiver = devices.find((device) => device.device_id === read.to_device_id)
    if (receiver === undefined) refuse('INVALID_ARGUMENT', 'that device is not paired with this host')
    const giving = this.#grants.find((summary) => summary.grant.grant_id === read.from_grant_id)
    if (giving === undefined) {
      refuse('RESOURCE_UNAVAILABLE', 'the host holds no such share of that session')
    }
    if (giving.state !== 'active') {
      refuse(
        'PERMISSION_DENIED',
        'only a share its device has accepted, and that still stands, can be handed over'
      )
    }
    this.#references += 1
    const reference = `handover-${String(this.#references)}`
    const fromName = this.#nameOf(giving.grant.recipient_device_id)
    const entry = this.#begin(
      'transfer',
      `Handing over the session to ${receiver.display_name}`,
      read.session_id,
      read.to_device_id,
      null,
      'asking',
      read.from_grant_id
    )
    const expiresAtMs = this.#ids.nowMs + 120_000
    this.#handovers.set(reference, {
      reference,
      params: read,
      entry,
      expiresAtMs,
      state: 'waiting',
      fromName,
      toName: receiver.display_name
    })
    return {
      reference,
      expires_at_ms: String(expiresAtMs),
      attempt: entry.view,
      from_device_id: giving.grant.recipient_device_id,
      from_device_name: fromName,
      to_device_id: receiver.device_id,
      to_device_name: receiver.display_name,
      session_number: 3
    }
  }

  transferAnswered(reference: string): HandoverState {
    const handover = this.#handover(reference)
    return {
      state: handover.state,
      expires_at_ms: String(handover.expiresAtMs),
      plan: { from_device_name: handover.fromName, to_device_name: handover.toName }
    }
  }

  transferFinish(
    reference: string
  ): Attempted<GrantTransferResult> | Promise<Attempted<GrantTransferResult>> {
    const handover = this.#handover(reference)
    if (handover.state !== 'answered') {
      refuse(
        'OWNER_CONFIRMATION_REQUIRED',
        'no owner device has confirmed this hand-over, so it is not sent'
      )
    }
    // The hand-over leaves the table when it is sent, as it does in native code: a cancel that
    // comes after finds nothing to cancel.
    this.#handovers.delete(reference)
    const { entry, params } = handover
    entry.view = { ...entry.view, phase: 'composed' }
    this.#sent.transfer += 1
    const hold = this.#finishHold
    this.#finishHold = null
    const settle = (): Attempted<GrantTransferResult> => {
      const lost = this.#lost(entry)
      const giving = this.#grants.find((summary) => summary.grant.grant_id === params.from_grant_id)
      if (giving === undefined) refuse('RESOURCE_UNAVAILABLE', 'the host holds no such share')
      const apply = (): GrantTransferResult => {
        this.#revoke(giving)
        const replacement = this.#replacement(giving, params.to_device_id)
        return {
          replacement: replacement.grant,
          revoked: this.#revocation(giving, [idOf('00000000', 7)])
        }
      }
      if (lost) {
        if (entry.written) entry.result = apply()
        return this.#unfinished(entry)
      }
      return this.#answer(entry, apply())
    }
    if (hold === null) return settle()
    return hold.held.then(
      () => settle(),
      (failure: unknown) => {
        // The host refused the hand-over: nothing was written, and the page was told so.
        this.#entries.splice(this.#entries.indexOf(entry), 1)
        throw failure
      }
    )
  }

  transferCancel(reference: string): void {
    // A hand-over that has been sent is no longer one this application is asking about.
    const handover = this.#handover(reference)
    this.#handovers.delete(reference)
    this.#entries.splice(this.#entries.indexOf(handover.entry), 1)
  }

  attemptsList(): Attempts {
    return { attempts: this.#entries.map((entry) => entry.view), unreadable: this.#unreadable }
  }

  attemptAsk(actionId: string): Attempted {
    const entry = this.#entry(actionId)
    if (entry.view.phase === 'asking') refuse('INVALID_ARGUMENT', 'a hand-over still being confirmed is not asked about')
    if (entry.view.phase === 'closed' && !entry.view.follow_up) {
      refuse('INVALID_ARGUMENT', 'that attempt is over')
    }
    if (!entry.written) {
      // The host has no record of it: the repeat is refused, and the attempt reads the host.
      this.#set(entry, 'checking')
      return { attempt: entry.view, value: null }
    }
    this.#close(entry, 'happened', entry.result, true)
    this.#entries.splice(this.#entries.indexOf(entry), 1)
    return { attempt: entry.view, value: entry.result }
  }

  attemptSetHidden(actionId: string, hidden: boolean): AttemptView {
    const entry = this.#entry(actionId)
    if (hidden && entry.view.phase === 'asking') {
      refuse('INVALID_ARGUMENT', 'a hand-over still being confirmed is cancelled, not hidden')
    }
    if (hidden && entry.view.phase === 'closed') {
      refuse('INVALID_ARGUMENT', 'an attempt that is over is removed, not hidden')
    }
    entry.view = { ...entry.view, hidden }
    return entry.view
  }

  attemptRemove(actionId: string): void {
    const entry = this.#entry(actionId)
    if (entry.view.phase !== 'closed' && entry.view.phase !== 'asking') {
      refuse('PERMISSION_DENIED', 'that can still happen, so its record stays until it is over')
    }
    this.#entries.splice(this.#entries.indexOf(entry), 1)
  }

  /* ---- Inside ---------------------------------------------------------------------------------- */

  #entry(actionId: string): Entry {
    const entry = this.#entries.find((each) => each.view.action_id === actionId)
    if (entry === undefined) refuse('INVALID_ARGUMENT', 'no such attempt is kept')
    return entry
  }

  #handover(reference: string): Handover {
    const handover = this.#handovers.get(reference)
    if (handover === undefined) {
      refuse('INVALID_ARGUMENT', 'that hand-over is not one this application is asking about')
    }
    return handover
  }

  #owner(): never {
    return refuse(
      'PERMISSION_DENIED',
      'this application is the owner of the host it is connected to; it holds no share of it'
    )
  }

  /** The offer becomes a share the device holds. */
  #take(offer: ShareOffer): void {
    this.#offers = this.#offers.filter((each) => each.invitation_id !== offer.invitation_id)
    if (this.#holds.some((share) => share.grant.grant_id === offer.grant_id)) return
    const grant = this.#grantOf(offer)
    this.#holds.push({
      display_number: offer.display_number,
      ends_at_ms: offer.ends_at_ms,
      grant,
      issued_at_ms: offer.issued_at_ms
    })
  }

  #grantOf(offer: ShareOffer): GrantRedeemResult['grant'] {
    return {
      grant_id: offer.grant_id,
      parent_grant_id: null,
      issuer_device_id: this.#ids.issuer,
      recipient_device_id: idOf('d4d4d4d4', 1),
      authority_revision: '5',
      environment_selector: { these: { environment_ids: [this.#ids.environment] } },
      session_selector: { these: { session_ids: [offer.session_id] } },
      actions: offer.actions,
      history: {
        lower_bound_ms: offer.history_from_ms,
        include_live_screen: offer.includes_live_screen,
        named_questions: [],
        named_approvals: []
      },
      expiry: { at: { expires_at_ms: offer.ends_at_ms } },
      organisation: null
    }
  }

  #redeemed(offer: ShareOffer): GrantRedeemResult {
    return { grant: this.#grantOf(offer), invitation_id: offer.invitation_id }
  }

  #nameOf(deviceId: string): string {
    return this.#devices().find((device) => device.device_id === deviceId)?.display_name ?? 'a paired device'
  }

  #gate(open: (entry: Entry) => boolean, what: string): void {
    const blocker = this.#entries.find((entry) => entry.view.phase !== 'closed' && open(entry))
    if (blocker !== undefined) {
      refuse(
        'PERMISSION_DENIED',
        `${what} is still under way (${blocker.view.label}), so a second is not started until it is over`
      )
    }
  }

  #begin(
    kind: AttemptKind,
    label: string,
    sessionId: string | null,
    deviceId: string | null,
    grantId: string | null = null,
    phase: AttemptPhase = 'composed',
    revokedGrantId: string | null = null
  ): Entry {
    this.#actions += 1
    this.#sent[kind] += 1
    const entry: Entry = {
      view: {
        action_id: idOf('f1f1f1f1', this.#actions),
        kind,
        phase,
        outcome: null,
        label,
        hidden: false,
        follow_up: false,
        session_id: sessionId,
        device_id: deviceId,
        grant_id: grantId,
        revoked_grant_id: revokedGrantId,
        composed_at_ms: String(this.#ids.nowMs),
        can_happen_until_ms: String(this.#ids.nowMs + 330_000),
        repeats: 0,
        refusal: null,
        result: null
      },
      live: false,
      written: false,
      result: null
    }
    this.#entries.push(entry)
    return entry
  }

  /** Whether this action is lost, and what the host did with it. */
  #lost(entry: Entry): boolean {
    const lose = this.#lose
    this.#lose = 'none'
    if (lose === 'none') {
      entry.written = true
      return false
    }
    entry.written = lose === 'answer'
    return true
  }

  #unfinished(entry: Entry): Attempted<never> {
    this.#set(entry, 'unfinished')
    return { attempt: entry.view, value: null }
  }

  #set(entry: Entry, phase: AttemptPhase, outcome: AttemptOutcome | null = null): void {
    entry.view = {
      ...entry.view,
      phase,
      outcome,
      can_happen_until_ms: phase === 'closed' ? null : entry.view.can_happen_until_ms
    }
  }

  #close(entry: Entry, outcome: AttemptOutcome, result: unknown, asked = false): void {
    this.#set(entry, 'closed', outcome)
    // What the host's result carries is owed until the page takes it: the screen kept with a live
    // invitation, and how far the workers have got with a revocation. An attempt that is over is
    // shown whatever was done to its row.
    const owed =
      outcome === 'happened' &&
      (entry.view.kind === 'revoke' || entry.view.kind === 'transfer' || entry.live)
    entry.view = { ...entry.view, result: asked ? null : result, follow_up: owed, hidden: false }
  }

  #answer<T>(entry: Entry, value: T): Attempted<T> {
    // An answer the host gave at once leaves no record.
    this.#set(entry, 'closed', 'happened')
    this.#entries.splice(this.#entries.indexOf(entry), 1)
    entry.result = value
    return { attempt: entry.view, value }
  }

  #recipientOf(read: GrantCreateParams): DeviceSummary {
    const recipient = this.#devices().find((device) => device.device_id === read.recipient_device_id)
    if (recipient === undefined || recipient.revoked) {
      refuse('PERMISSION_DENIED', 'this host has no paired device with that identity')
    }
    return recipient
  }

  #write(read: GrantCreateParams, recipient: DeviceSummary): GrantCreateResult {
    this.#known(read.session_id)
    if (read.owner_confirmation !== null) {
      refuse(
        'INVALID_ARGUMENT',
        'an owner confirmation is completed through the owner-confirmation methods'
      )
    }
    const actions = actionsOf(read.selection)
    const notices = noticesFor(actions)
    const accepted = [...new Set(read.accepted_notices)].sort()
    if (JSON.stringify(accepted) !== JSON.stringify([...notices].sort())) {
      refuse(
        'PERMISSION_DENIED',
        'the issuer accepted a different set of consequences from the ones this grant carries'
      )
    }
    const lifetime = read.lifetime_ms === null ? 3_600_000 : Number(read.lifetime_ms)
    if (lifetime > 30 * 24 * 3_600_000) {
      refuse('INVALID_ARGUMENT', 'a session invitation lasts at most 30 days')
    }
    const endsAt = this.#ids.nowMs + lifetime
    if (recipient.grant_expires_at_ms !== null && endsAt > Number(recipient.grant_expires_at_ms)) {
      const minutes = Math.max(
        0,
        Math.floor((Number(recipient.grant_expires_at_ms) - this.#ids.nowMs) / 60_000)
      )
      refuse(
        'INVALID_ARGUMENT',
        `that device's pairing ends in ${String(minutes)} minutes, before this share would; choose a shorter lifetime or pair the device again`
      )
    }
    let live: GrantCreateResult['preview']['live_screen'] = null
    if (read.selection.include_live_screen) {
      if (this.#screen.truncated) {
        refuse(
          'INVALID_ARGUMENT',
          'the screen is larger than a preview shows, so its issuer would not be shown all of it'
        )
      }
      live = { lines: [...this.#screen.lines], truncated: false }
    }
    const history = {
      lower_bound_ms: read.selection.history_from_cursor_ms ?? String(this.#ids.nowMs),
      include_live_screen: read.selection.include_live_screen,
      named_questions: [],
      named_approvals: []
    }
    const expiresAt = String(endsAt)
    const grant: GrantSummary['grant'] = {
      grant_id: idOf('e7e7e7e7', this.#actions),
      parent_grant_id: null,
      issuer_device_id: this.#ids.issuer,
      recipient_device_id: read.recipient_device_id,
      authority_revision: '5',
      environment_selector: { these: { environment_ids: [this.#ids.environment] } },
      session_selector: { these: { session_ids: [read.session_id] } },
      actions,
      history,
      expiry: { at: { expires_at_ms: expiresAt } },
      organisation: null
    }
    const pairingEnd = recipient.grant_expires_at_ms
    this.#grants.push({
      grant,
      state: 'pending',
      revoked_at_ms: null,
      revoked_by_parent: null,
      ends_at_ms: pairingEnd !== null && Number(pairingEnd) < endsAt ? pairingEnd : expiresAt
    })
    return {
      grant,
      authority_revision: '5',
      preview: {
        invitation_id: idOf('e9e9e9e9', this.#actions),
        session_id: read.session_id,
        environment_id: this.#ids.environment,
        role: read.selection.role,
        actions,
        history,
        expires_at_ms: expiresAt,
        live_screen: live,
        named_questions: [],
        named_approvals: [],
        notices,
        historical_attachment_keys: false,
        single_use: true
      }
    }
  }

  #revoke(summary: GrantSummary): void {
    if (summary.state === 'revoked') return
    summary.state = 'revoked'
    summary.revoked_at_ms = String(this.#ids.nowMs)
  }

  /**
   * What the host says of a revocation. `alsoRevoked` names grants that went with it (a hand-over
   * revokes the giving grant's descendants): the host's list of them is sorted by identity, so the
   * grant that was named is not always the first.
   */
  #revocation(summary: GrantSummary, alsoRevoked: readonly string[] = []): RevocationResult {
    const pending = this.#barrierHeld
    this.#barrierHeld = false
    return {
      authority_revision: '6',
      revoked_grants: [...alsoRevoked, summary.grant.grant_id],
      revoked_grants_total: String(alsoRevoked.length + 1),
      barrier: {
        authority_revision: '6',
        workers: pending
          ? [
              {
                acknowledged_revision: null,
                detail: 'the session has not acknowledged the revision yet',
                names_pending: '1',
                omitted_actions: '0',
                possibly_executed: [],
                possibly_executed_total: '0',
                rejected_actions: [],
                rejected_actions_total: '0',
                session_id: sessionOf(summary),
                state: 'pending'
              }
            ]
          : [],
        workers_total: pending ? '1' : '0'
      }
    }
  }

  #replacement(giving: GrantSummary, to: string): GrantSummary {
    this.#actions += 1
    const grant = {
      ...giving.grant,
      grant_id: idOf('e7e7e7e7', 1000 + this.#actions),
      recipient_device_id: to
    }
    const summary: GrantSummary = {
      grant,
      state: 'active',
      revoked_at_ms: null,
      revoked_by_parent: null,
      ends_at_ms: giving.ends_at_ms
    }
    this.#grants.push(summary)
    return summary
  }
}

function sessionOf(summary: GrantSummary): string {
  const selector = summary.grant.session_selector
  return typeof selector === 'object' ? (selector.these.session_ids[0] ?? idOf('00000000', 0)) : idOf('00000000', 0)
}
