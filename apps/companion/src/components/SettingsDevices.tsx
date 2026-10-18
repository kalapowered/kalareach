/**
 * Who shares the person's settings, as a card of the account panel.
 *
 * The settings follow the person to their other devices sealed under a key only those devices hold.
 * A device gets the key only when the person confirms on a computer that already has it, with the
 * platform's own ceremony, and a computer joins the settings of another only when the person
 * confirms there. This card names devices and offers; native code holds the keys, shows nothing of
 * them, and asks the person. A member no host lists any more is taken out by the next check, unless
 * a host did not answer: the member stays, and so does the key it holds, until that host does. The
 * person can take one out at any time, which needs no ceremony but does ask once here, because
 * putting it back asks for two.
 *
 * Each row has the device's name and, where there is something to do, one control whose name says
 * which device it is for. The words wrap and no row has a fixed width, so no text size pushes a
 * control out of the card. Nothing here moves.
 */

import { useEffect, useRef, useState } from 'react'
import type { ReactNode, RefObject } from 'react'

import type { DeviceMember, DevicesView } from '../host/port'
import {
  DEVICES_CANNOT_CONFIRM,
  DEVICES_HELP,
  DEVICES_OFFER,
  DEVICES_WAITING,
  DEVICE_NOT_VOUCHED,
  describeDevices,
  describeHappened,
  describeOffer,
  offerLabel,
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
        {devices.can_confirm ? <p className="account-note">{DEVICES_HELP}</p> : null}
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
          {devices.members.map((member) => (
            <MemberRow
              key={member.reference}
              member={member}
              busy={busy}
              target={target}
              onRemove={onRemove}
            />
          ))}
        </ul>
      ) : null}
      {devices.candidates.length > 0 && devices.can_confirm ? (
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
                  disabled={busy}
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
      {devices.offers.length > 0 && devices.can_confirm ? (
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
                  disabled={busy}
                  aria-label={offerLabel(offer)}
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

/**
 * One device that holds the key. Taking it out asks once, in the row: the safe answer has focus
 * when the question opens, and focus goes back to the control that asked when the person keeps the
 * device. The row owns the question, so a device that goes (or comes back) does not leave it open.
 */
function MemberRow({
  member,
  busy,
  target,
  onRemove
}: {
  readonly member: DeviceMember
  readonly busy: boolean
  readonly target: number
  readonly onRemove: (reference: string) => void
}): ReactNode {
  const [asking, setAsking] = useState(false)
  const trigger = useRef<HTMLButtonElement | null>(null)
  const keep = useRef<HTMLButtonElement | null>(null)
  const refocus = useRef(false)
  useEffect(() => {
    if (asking) {
      keep.current?.focus()
    } else if (refocus.current) {
      refocus.current = false
      trigger.current?.focus()
    }
  }, [asking])
  const keepIt = () => {
    refocus.current = true
    setAsking(false)
  }
  return (
    <li className="device-row">
      <div className="device-words">
        <p className="account-lead">{member.name}</p>
        {!member.vouched ? <p className="account-note">{DEVICE_NOT_VOUCHED}</p> : null}
        {asking ? (
          <p className="account-note" data-testid="settings-devices-taking-out">
            {describeTakingOut(member.name)}
          </p>
        ) : null}
      </div>
      {member.this_computer ? null : asking ? (
        <div
          className="device-choice"
          role="group"
          aria-label={`Take ${member.name} out?`}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.stopPropagation()
              keepIt()
            }
          }}
        >
          <Button
            tone="danger"
            data-wraps
            disabled={busy}
            aria-label={`Take ${member.name} out now`}
            style={{ minBlockSize: target }}
            onClick={() => {
              setAsking(false)
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
            onClick={keepIt}
          >
            Keep
          </Button>
        </div>
      ) : (
        <Button
          data-wraps
          ref={trigger}
          disabled={busy}
          aria-label={`Take ${member.name} out`}
          style={{ minBlockSize: target }}
          onClick={() => {
            setAsking(true)
          }}
        >
          Take out
        </Button>
      )}
    </li>
  )
}
