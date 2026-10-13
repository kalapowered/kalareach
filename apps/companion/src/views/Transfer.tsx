/**
 * Handing a session's control to another device: the person at the machine asks, an owner device
 * confirms exactly that plan, and only then is the transfer sent.
 *
 * Nothing that changes who holds the session leaves this computer until an owner device has
 * answered. The page holds a reference and nothing else: the plan, the action and the parameters
 * stay in native code behind it. The panel says what it is waiting for, how long that lasts, and
 * what happened, and never says a session was handed over on the strength of a request that was
 * only sent.
 *
 * The panel owns a reference from the moment the owner devices are asked until it is sent or let
 * go. Whenever it leaves one without sending it (the person cancels, the panel closes, the send
 * fails) it lets the reference go, so no hand-over is left holding the session's place with
 * nobody able to finish it. Once the transfer is sent, how it went is told, and what the host said
 * of the giving device's revocation is kept on the page's desk, whether or not the panel is still
 * on screen: the send does not depend on the polling that preceded it, or on the screen.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'

import type { DeviceSummary, GrantSummary } from '@kalareach/protocol'

import { Button, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import { isHostError, type HandoverAsked, type SessionSubject } from '../host/port'
import { ask } from '../mobile/model/call'
import {
  failureText,
  momentWords,
  nameWords,
  pairingEnd,
  platformWords,
  whyNot
} from '../model/sharing'
import { deskOf } from '../model/sharing-desk'
import { handedOver } from '../model/sharing-results'

/** How often the panel asks whether an owner device has answered. */
const POLL_MS = 1000

/**
 * Whether a failure of asking about a hand-over is the end of it. A host that cannot be reached
 * for a moment is not: the challenge is still the owner devices' to answer, and the next ask finds
 * out. A hand-over that is no longer one native code is asking about, or whose plan was not the
 * one asked for, is.
 */
function endsHandOver(error: unknown): boolean {
  return (
    isHostError(error) &&
    ['INVALID_ARGUMENT', 'OWNER_CONFIRMATION_REQUIRED', 'PERMISSION_DENIED'].includes(error.code)
  )
}

/** Why a device cannot receive this share, or none when it can. */
function whyNotReceiver(device: DeviceSummary, giving: GrantSummary, nowMs: number): string | null {
  if (device.device_id === giving.grant.recipient_device_id) return 'It is the device giving control up.'
  const reason = whyNot(device, nowMs)
  if (reason !== null) return reason
  const shareEnds = giving.ends_at_ms === null ? null : Number(giving.ends_at_ms)
  const pairingEnds = pairingEnd(device)
  if (pairingEnds !== null && (shareEnds === null || pairingEnds < shareEnds)) {
    return 'Its pairing ends before this share does. Pair it again first.'
  }
  return null
}

/** The hand-over of one session's control, as a panel in the sharing tab. */
export function Transfer({
  sessionId,
  subject,
  giving,
  givingName,
  devices,
  nowMs,
  onDone,
  onClose
}: {
  readonly sessionId: string
  readonly subject: SessionSubject
  /** The share being given up. */
  readonly giving: GrantSummary
  readonly givingName: string
  readonly devices: readonly DeviceSummary[]
  readonly nowMs: number
  /**
   * Called once the transfer is over while the panel is still on screen, with the receiving
   * device's name and the identity of the grant it now holds when it happened.
   */
  readonly onDone: (receiver: string | null, replacementGrantId: string | null) => void
  /** Called when the person leaves the panel. */
  readonly onClose: () => void
}): ReactNode {
  const { port, say } = useApp()
  const desk = deskOf(port)
  const [receiver, setReceiver] = useState<string | null>(null)
  const [asked, setAsked] = useState<HandoverAsked | null>(null)
  const [state, setState] = useState<'choosing' | 'asking' | 'waiting' | 'sending' | 'gone'>(
    'choosing'
  )
  const [failure, setFailure] = useState<string | null>(null)
  const heading = useRef<HTMLHeadingElement | null>(null)
  const mounted = useRef(true)
  /** The reference this panel owns: asked about, and neither sent nor let go. */
  const owned = useRef<string | null>(null)
  /**
   * Whether the transfer has been sent, or the person has cancelled: either way the polling that
   * is still on its way is not listened to, since an answer that arrives after Cancel began must
   * not send what the person took back.
   */
  const sending = useRef(false)
  /** What the send reports to, which the polling that began it does not outlive. */
  const latest = useRef({ say, onDone })

  useEffect(() => {
    latest.current = { say, onDone }
  })

  const candidates = devices.filter((device) => !device.revoked)
  const chosen = candidates.find((device) => device.device_id === receiver) ?? null

  useEffect(() => {
    heading.current?.focus()
  }, [])

  /** Lets a reference go without sending it. The host has nothing to undo: only a record to clear. */
  const release = (reference: string) => {
    if (owned.current === reference) owned.current = null
    void ask(() => port.transferCancel(reference)).catch(() => undefined)
  }

  // Leaving the panel while a hand-over is still being asked for lets it go: nothing would ever
  // send it, and its record would hold the session's place.
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      const reference = owned.current
      if (reference !== null) release(reference)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `release` reads only refs and the port
  }, [])

  const request = () => {
    if (chosen === null) return
    setState('asking')
    setFailure(null)
    ask(() =>
      port.transferAsk(
        {
          session_id: sessionId,
          from_grant_id: giving.grant.grant_id,
          to_device_id: chosen.device_id
        },
        subject
      )
    )
      .then((reply) => {
        if (!mounted.current) {
          void ask(() => port.transferCancel(reply.reference)).catch(() => undefined)
          return
        }
        owned.current = reply.reference
        setAsked(reply)
        setState('waiting')
      })
      .catch((error: unknown) => {
        if (!mounted.current) {
          // The panel is gone: the person is told here, since what failed can still have put a
          // request on an owner device.
          latest.current.say(failureText(error), 'danger')
          return
        }
        setFailure(failureText(error))
        setState('choosing')
      })
  }

  /**
   * Sends the hand-over an owner device confirmed. It is called once, from the polling, and what
   * it reports does not depend on the polling still running: moving to "sending" ends the
   * polling, and the answer to the send arrives after that.
   */
  const send = (reply: HandoverAsked) => {
    owned.current = null
    sending.current = true
    setState('sending')
    ask(() => port.transferFinish(reply.reference))
      .then((done) => {
        const unfinished = done.attempt.phase !== 'closed' || done.value === null
        const session =
          reply.session_number === null ? 'The session' : `Session ${String(reply.session_number)}`
        const to = nameWords(reply.to_device_name)
        if (unfinished || done.value === null) {
          latest.current.say(
            `The hand-over to ${to} was sent, but the host’s answer did not arrive. It is listed as unfinished.`,
            'pending'
          )
        } else if (desk.firstTime(done.attempt.action_id)) {
          // Kept on the desk, which outlives this panel: the host's account of the giving
          // device's revocation is told however soon the person leaves.
          handedOver(
            desk,
            latest.current.say,
            done.value,
            giving.grant.grant_id,
            givingName,
            `${session} is now with ${to}.`,
            Date.now()
          )
        }
        if (mounted.current) {
          latest.current.onDone(
            unfinished ? null : reply.to_device_name,
            done.value?.replacement.grant_id ?? null
          )
        }
      })
      .catch((error: unknown) => {
        // Nothing was sent, or the host refused it: either way the reference is spent or the
        // hand-over still waits. The person is told with the host's own words wherever they are.
        void ask(() => port.transferCancel(reply.reference)).catch(() => undefined)
        latest.current.say(failureText(error), 'danger')
        if (!mounted.current) return
        sending.current = false
        setFailure(failureText(error))
        setState('choosing')
      })
  }

  // While an owner device is being waited for, the panel asks once a second whether it answered.
  useEffect(() => {
    if (state !== 'waiting' || asked === null) return
    let live = true
    const reply = asked
    const handle = setInterval(() => {
      ask(() => port.transferAnswered(reply.reference))
        .then((answer) => {
          // An answer to an ask made before the send began says nothing of the send.
          if (!live || sending.current) return
          if (answer.state === 'gone') {
            owned.current = null
            setState('gone')
            return
          }
          if (answer.state === 'answered') {
            // The transfer is sent once, on the owner device's answer.
            clearInterval(handle)
            send(reply)
          }
        })
        .catch((error: unknown) => {
          if (!live || sending.current || !endsHandOver(error)) return
          release(reply.reference)
          setFailure(failureText(error))
          setState('choosing')
        })
    }, POLL_MS)
    return () => {
      live = false
      clearInterval(handle)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `send` and `release` read refs and the port
  }, [state, asked, port])

  const cancel = () => {
    const reference = owned.current
    if (reference === null) {
      onClose()
      return
    }
    // From here no answer to a poll sends anything: the person took it back.
    sending.current = true
    owned.current = null
    // The record is cleared before the list is read again, so a cancelled hand-over is not listed.
    void ask(() => port.transferCancel(reference))
      .catch(() => undefined)
      .then(onClose)
  }

  const to = asked === null ? '' : nameWords(asked.to_device_name)
  const from = asked === null ? '' : nameWords(asked.from_device_name)

  return (
    <section className="hand-over" aria-labelledby="hand-over-heading" data-testid="hand-over">
      <h3 id="hand-over-heading" ref={heading} tabIndex={-1}>
        Hand over control
      </h3>
      <p className="small muted">
        The receiving device gets the access {nameWords(givingName)} has now. {nameWords(givingName)}{' '}
        loses it. An owner device must confirm, and it is shown exactly this plan.
      </p>

      {failure !== null ? (
        <p className="small warning-text" role="alert" data-testid="hand-over-failure">
          {failure}
        </p>
      ) : null}

      {state === 'choosing' || state === 'asking' ? (
        <fieldset className="settings-group" disabled={state === 'asking'}>
          <legend>Who receives it</legend>
          {candidates.map((device) => {
            const reason = whyNotReceiver(device, giving, nowMs)
            return (
              <label className="choice-row" key={device.device_id} data-unavailable={reason !== null}>
                <input
                  type="radio"
                  name={`receiver-${sessionId}`}
                  value={device.device_id}
                  checked={receiver === device.device_id}
                  disabled={reason !== null}
                  onChange={() => {
                    setReceiver(device.device_id)
                  }}
                />
                <span>
                  {nameWords(device.display_name)}
                  <span className="small faint">
                    {' '}
                    · {platformWords(device.platform)}
                    {reason !== null ? ` · ${reason}` : ''}
                  </span>
                </span>
              </label>
            )
          })}
        </fieldset>
      ) : null}

      {state === 'waiting' && asked !== null ? (
        <div className="hand-over-waiting" role="status" data-testid="hand-over-waiting">
          <p>
            Waiting for an owner device. It shows exactly this plan: {from} gives up the access, and{' '}
            {to} gets it. Expires {momentWords(Number(asked.expires_at_ms), nowMs)}.
          </p>
        </div>
      ) : null}
      {state === 'sending' ? (
        <p role="status" data-testid="hand-over-sending">
          An owner device confirmed. Sending the hand-over.
        </p>
      ) : null}
      {state === 'gone' ? (
        <p role="status" data-testid="hand-over-gone">
          The owner devices did not answer in time. Nothing was handed over.
        </p>
      ) : null}

      <div className="hand-over-actions">
        {state === 'choosing' || state === 'asking' ? (
          <CommitButton
            data-testid="hand-over-ask"
            disabled={chosen === null || state === 'asking'}
            onCommit={request}
          >
            {chosen === null ? 'Choose a device' : `Ask an owner device to confirm`}
          </CommitButton>
        ) : null}
        {state === 'gone' ? (
          <CommitButton
            data-testid="hand-over-again"
            onCommit={() => {
              setAsked(null)
              setState('choosing')
            }}
          >
            Ask again
          </CommitButton>
        ) : null}
        {state !== 'sending' ? (
          <Button onClick={cancel} data-testid="hand-over-cancel">
            {state === 'waiting' ? 'Cancel' : 'Back'}
          </Button>
        ) : null}
      </div>
    </section>
  )
}
