/**
 * Handing a session's control to another device: the person at the machine asks, an owner device
 * confirms exactly that plan, and only then is the transfer sent.
 *
 * Nothing that changes who holds the session leaves this computer until an owner device has
 * answered. The page holds a reference and nothing else: the plan, the action and the parameters
 * stay in native code behind it. The panel says what it is waiting for, how long that lasts, and
 * what happened, and never says a session was handed over on the strength of a request that was
 * only sent.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'

import type { DeviceSummary, GrantSummary } from '@kalareach/protocol'

import { Button, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage, type HandoverAsked, type SessionSubject } from '../host/port'
import { ask } from '../mobile/model/call'
import { momentWords, pairingEnd, platformWords, whyNot } from '../model/sharing'

/** How often the panel asks whether an owner device has answered. */
const POLL_MS = 1000

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
  /** Called once the transfer is over, with the receiving device's name when it happened. */
  readonly onDone: (receiver: string | null) => void
  /** Called when the person leaves the panel. */
  readonly onClose: () => void
}): ReactNode {
  const { port, say } = useApp()
  const [receiver, setReceiver] = useState<string | null>(null)
  const [asked, setAsked] = useState<HandoverAsked | null>(null)
  const [state, setState] = useState<'choosing' | 'asking' | 'waiting' | 'sending' | 'gone'>(
    'choosing'
  )
  const [failure, setFailure] = useState<string | null>(null)
  const sent = useRef(false)
  const heading = useRef<HTMLHeadingElement | null>(null)

  const candidates = devices.filter((device) => !device.revoked)
  const chosen = candidates.find((device) => device.device_id === receiver) ?? null

  useEffect(() => {
    heading.current?.focus()
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
        sent.current = false
        setAsked(reply)
        setState('waiting')
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
        setState('choosing')
      })
  }

  // While an owner device is being waited for, the panel asks once a second whether it answered.
  useEffect(() => {
    if (state !== 'waiting' || asked === null) return
    let live = true
    const reference = asked.reference
    const handle = setInterval(() => {
      ask(() => port.transferAnswered(reference))
        .then((answer) => {
          if (!live) return
          if (answer.state === 'gone') {
            setState('gone')
            return
          }
          if (answer.state === 'answered' && !sent.current) {
            // The transfer is sent once, on the owner device's answer.
            sent.current = true
            setState('sending')
            ask(() => port.transferFinish(reference))
              .then((done) => {
                if (!live) return
                const open = done.attempt.phase !== 'closed'
                const session =
                  asked.session_number === null ? 'The session' : `Session ${String(asked.session_number)}`
                say(
                  open
                    ? `The hand-over to ${asked.to_device_name} was sent, but the host’s answer did not arrive. It is listed as unfinished.`
                    : `${session} is now with ${asked.to_device_name}.`,
                  open ? 'pending' : 'success'
                )
                onDone(open ? null : asked.to_device_name)
              })
              .catch((error: unknown) => {
                if (!live) return
                setFailure(failureMessage(error))
                setState('choosing')
              })
          }
        })
        .catch((error: unknown) => {
          if (!live) return
          setFailure(failureMessage(error))
          setState('choosing')
        })
    }, POLL_MS)
    return () => {
      live = false
      clearInterval(handle)
    }
  }, [state, asked, port, say, onDone])

  const cancel = () => {
    if (asked !== null && state === 'waiting') {
      void ask(() => port.transferCancel(asked.reference)).catch(() => undefined)
    }
    onClose()
  }

  return (
    <section className="hand-over" aria-labelledby="hand-over-heading" data-testid="hand-over">
      <h3 id="hand-over-heading" ref={heading} tabIndex={-1}>
        Hand over control
      </h3>
      <p className="small muted">
        The receiving device gets the access {givingName} has now. {givingName} loses it. An owner
        device must confirm, and it is shown exactly this plan.
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
                  {device.display_name}
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
            Waiting for an owner device. It shows exactly this plan: {asked.from_device_name} gives
            up the access, and {asked.to_device_name} gets it. Expires{' '}
            {momentWords(Number(asked.expires_at_ms), nowMs)}.
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
