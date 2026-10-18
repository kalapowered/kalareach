/**
 * Who shares the person's settings, as a card of the account panel.
 *
 * The settings follow the person to their other devices sealed under a key only those devices hold.
 * A device gets the key only when the person confirms on a computer that already has it, with the
 * platform's own ceremony, and a computer joins the settings of another only when the person
 * confirms there. This card names devices and offers; native code holds the keys, shows nothing of
 * them, and asks the person. A member no host lists any more is taken out by the next check, and
 * the person can take one out at any time, which needs no confirmation.
 *
 * Each row has the device's name and, where there is something to do, one control whose name says
 * which device it is for. The words wrap and no row has a fixed width, so no text size pushes a
 * control out of the card. Nothing here moves.
 */

import type { ReactNode, RefObject } from 'react'

import type { DevicesView } from '../host/port'
import {
  DEVICES_CANNOT_CONFIRM,
  DEVICES_HELP,
  DEVICES_OFFER,
  DEVICES_WAITING,
  DEVICE_NOT_VOUCHED,
  describeDevices,
  describeHappened
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
          {devices.members.map((member) => (
            <li className="device-row" key={member.reference}>
              <div className="device-words">
                <p className="account-lead">{member.name}</p>
                {!member.vouched ? <p className="account-note">{DEVICE_NOT_VOUCHED}</p> : null}
              </div>
              {member.this_computer ? null : (
                <Button
                  data-wraps
                  disabled={busy}
                  aria-label={`Take ${member.name} out`}
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    onRemove(member.reference)
                  }}
                >
                  Take out
                </Button>
              )}
            </li>
          ))}
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
                  <p className="account-lead">Settings shared by another of your devices</p>
                </div>
                <Button
                  tone="primary"
                  data-wraps
                  disabled={busy || !devices.can_confirm}
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
      {devices.outcomes.map((happened) => {
        const text = describeHappened(happened)
        return (
          <p className="account-note" data-testid="settings-devices-outcome" key={text}>
            {text}
          </p>
        )
      })}
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
