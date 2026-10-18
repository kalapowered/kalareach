/**
 * Who shares the person's settings, as a card of the account panel.
 *
 * The settings follow the person to their other devices sealed under a key only those devices hold.
 * A device gets the key only when the person confirms on a computer that already has it, with the
 * platform's own ceremony, and a computer joins the settings of another only when the person
 * confirms there. This card names devices and offers; native code holds the keys, shows nothing of
 * them, and asks the person. A member no host lists any more is taken out by the next check, and
 * the person can take one out at any time, which needs no ceremony but does ask once here, because
 * putting it back asks for two.
 *
 * Each row has the device's name and, where there is something to do, one control whose name says
 * which device it is for. The words wrap and no row has a fixed width, so no text size pushes a
 * control out of the card. Nothing here moves.
 */

import { useEffect, useRef, useState } from 'react'
import type { ReactNode, RefObject } from 'react'

import type { DevicesView } from '../host/port'
import {
  DEVICES_CANNOT_CONFIRM,
  DEVICES_HELP,
  DEVICES_OFFER,
  DEVICES_WAITING,
  DEVICE_NOT_VOUCHED,
  describeDevices,
  describeHappened,
  describeOffer,
  describeTakingOut,
  uniqueKeys
} from '../model/settings'
import { Button } from './ui'

export function SettingsDevices({
  devices,
  busy,
  target,
  said,
  statusRef,
  onLook,
  onShare,
  onRemove,
  onJoin,
  onDismiss
}: {
  readonly devices: DevicesView
  readonly busy: boolean
  readonly target: number
  /** What the last step of this card said, when it said anything. */
  readonly said: string | null
  /** The status line a finished step moves focus to. */
  readonly statusRef: RefObject<HTMLDivElement | null>
  readonly onLook: () => void
  readonly onShare: (reference: string) => void
  readonly onRemove: (reference: string) => void
  readonly onJoin: (reference: string) => void
  readonly onDismiss: () => void
}): ReactNode {
  // The member the person is being asked about. Focus moves to the safe answer when the question
  // opens, and back to the control that opened it when the person keeps the device.
  const [asking, setAsking] = useState<string | null>(null)
  const triggers = useRef(new Map<string, HTMLButtonElement>())
  const keep = useRef<HTMLButtonElement | null>(null)
  const returnTo = useRef<string | null>(null)
  useEffect(() => {
    if (asking !== null) {
      keep.current?.focus()
    } else if (returnTo.current !== null) {
      triggers.current.get(returnTo.current)?.focus()
      returnTo.current = null
    }
  }, [asking])
  // A member that is gone by the next step is not asked about any more.
  const askedStillMember = devices.members.some((member) => member.reference === asking)
  const outcomes = uniqueKeys(devices.outcomes.map(describeHappened))
  return (
    <>
      <div
        className="account-status"
        aria-live="polite"
        tabIndex={-1}
        ref={statusRef}
        data-testid="settings-devices-status"
      >
        <p className="account-lead">{describeDevices(devices)}</p>
        <p className="account-note">{DEVICES_HELP}</p>
        {devices.waiting ? (
          <p className="account-note" data-testid="settings-devices-waiting">
            {DEVICES_WAITING}
          </p>
        ) : null}
        {!devices.can_confirm ? (
          <p className="account-note" data-testid="settings-devices-cannot-confirm">
            {DEVICES_CANNOT_CONFIRM}
          </p>
        ) : null}
        {said !== null ? <p className="account-note">{said}</p> : null}
      </div>
      {devices.members.length > 0 ? (
        <ul className="device-list" data-testid="settings-devices-members">
          {devices.members.map((member) => {
            const isAsked = asking === member.reference && askedStillMember
            return (
              <li className="device-row" key={member.reference}>
                <div className="device-words">
                  <p className="account-lead">{member.name}</p>
                  {!member.vouched ? <p className="account-note">{DEVICE_NOT_VOUCHED}</p> : null}
                  {isAsked ? (
                    <p className="account-note" data-testid="settings-devices-taking-out">
                      {describeTakingOut(member.name)}
                    </p>
                  ) : null}
                </div>
                {member.this_computer ? null : isAsked ? (
                  <div className="device-choice">
                    <Button
                      tone="danger"
                      data-wraps
                      disabled={busy}
                      aria-label={`Take ${member.name} out now`}
                      style={{ minBlockSize: target }}
                      onClick={() => {
                        setAsking(null)
                        onRemove(member.reference)
                      }}
                    >
                      Take out
                    </Button>
                    <Button
                      data-wraps
                      ref={keep}
                      aria-label={`Keep ${member.name} in`}
                      style={{ minBlockSize: target }}
                      onClick={() => {
                        returnTo.current = member.reference
                        setAsking(null)
                      }}
                    >
                      Keep
                    </Button>
                  </div>
                ) : (
                  <Button
                    data-wraps
                    ref={(element) => {
                      if (element !== null) {
                        triggers.current.set(member.reference, element)
                      } else {
                        triggers.current.delete(member.reference)
                      }
                    }}
                    disabled={busy}
                    aria-label={`Take ${member.name} out`}
                    style={{ minBlockSize: target }}
                    onClick={() => {
                      setAsking(member.reference)
                    }}
                  >
                    Take out
                  </Button>
                )}
              </li>
            )
          })}
        </ul>
      ) : null}
      {devices.candidates.length > 0 ? (
        <>
          <p className="account-note">Your hosts list these devices as yours.</p>
          <ul className="device-list" data-testid="settings-devices-candidates">
            {devices.candidates.map((candidate) => (
              <li className="device-row" key={candidate.reference}>
                <div className="device-words">
                  <p className="account-lead">{candidate.name}</p>
                </div>
                <Button
                  tone="primary"
                  data-wraps
                  disabled={busy || !devices.can_confirm}
                  aria-label={`Share settings with ${candidate.name}`}
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    onShare(candidate.reference)
                  }}
                >
                  Share settings
                </Button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {devices.offers.length > 0 ? (
        <>
          <p className="account-note" data-testid="settings-devices-offer">
            {DEVICES_OFFER}
          </p>
          <ul className="device-list">
            {devices.offers.map((offer) => (
              <li className="device-row" key={offer.reference}>
                <div className="device-words">
                  <p className="account-lead">{describeOffer(offer)}</p>
                </div>
                <Button
                  tone="primary"
                  data-wraps
                  disabled={busy || !devices.can_confirm}
                  aria-label={`Join the ${describeOffer(offer).toLowerCase()}`}
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    onJoin(offer.reference)
                  }}
                >
                  Join
                </Button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      {outcomes.map(({ text, key }) => (
        <p className="account-note" data-testid="settings-devices-outcome" key={key}>
          {text}
        </p>
      ))}
      <div className="account-actions">
        <Button
          data-testid="settings-devices-look"
          data-wraps
          disabled={busy}
          style={{ minBlockSize: target }}
          onClick={onLook}
        >
          Look for my devices
        </Button>
        {devices.outcomes.length > 0 ? (
          <Button
            data-testid="settings-devices-dismiss"
            data-wraps
            disabled={busy}
            style={{ minBlockSize: target }}
            onClick={onDismiss}
          >
            Dismiss
          </Button>
        ) : null}
      </div>
    </>
  )
}
