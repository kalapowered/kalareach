/**
 * The devices of the hosts this computer owns, and revoking one.
 *
 * One card for each host, and in it a row for each device with one thing the person can do. The
 * screen says what it knows and no more: a request the host has not acknowledged is sent, never
 * revoked, and the card says where requests are published and what the host's feed holds. A
 * revocation is done only in the row whose host has acknowledged it.
 *
 * Revoking asks the person once, with the platform's own ceremony, so the control is named for it
 * ("Revoke with Touch ID") and there is no question in the row beside the dialog's. The row's words
 * wrap and no row has a fixed width, so no text size pushes a control out of its card. A failure is
 * said in the row it is about, in words that claim nothing of the outcome, and focus returns to the
 * control that was pressed, or to the words of the row when that control is gone. A request that
 * was sent leaves its row without a control, so focus goes to the words that now say where it
 * stands; those words are one element for as long as the row lives, so a later change of standing
 * keeps the person's place. Focus moves only from where a press left it: a person who has gone
 * elsewhere is not followed. Nothing here moves: what changes is said in a polite live region.
 *
 * While a request waits for its host the screen asks again, ten seconds after the last answer: one
 * look at a time, so a slow host is waited for and its answer is shown, never dropped for the next.
 * A look asked for while another is out waits for it.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'

import { useApp } from '../app/state'
import { Badge, Banner, Button, Card } from '../components/ui'
import { failureMessage, watch, type RevocationDevice, type RevocationHost, type RevocationView, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import { minimumTarget } from '../mobile/platform'
import {
  CANNOT_CONFIRM,
  REVOCATION_HELP,
  announcements,
  anyWaiting,
  canAskAgainAfter,
  checkAgainName,
  describeContact,
  describeDevice,
  describeFeed,
  describeRoute,
  describeStanding,
  revokeLabel,
  revokeName,
  standingBadge
} from '../model/revocation'

/** How long after one look has been answered the screen waits to look again, while a request waits. */
const LOOK_AFTER_MS = 10_000

/** A revocation that did not go through, said in the row of the device it was for. */
interface Failure {
  readonly key: string
  readonly message: string
}

/** Where focus goes once the screen has settled: the words of a row, or the control of one. */
interface FocusTarget {
  readonly key: string
  readonly on: 'words' | 'control'
}

/** The screen. */
export function Devices(): ReactNode {
  const { port } = useApp()
  const target = minimumTarget('desktop')
  const [view, setView] = useState<RevocationView | null>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [looking, setLooking] = useState(false)
  // The device a revocation is being confirmed or sent for, by host and device reference.
  const [revoking, setRevoking] = useState<string | null>(null)
  const [heard, setHeard] = useState('')
  const reads = useRef<Watch | null>(null)
  const shown = useRef<RevocationView | null>(null)
  const looks = useRef(0)
  // A look was asked for while another was out, and is made once that one is answered.
  const queued = useRef(false)
  const words = useRef(new Map<string, HTMLElement>())
  const controls = useRef(new Map<string, HTMLElement>())
  const toFocus = useRef<FocusTarget | null>(null)

  /** Shows a view the host answered, and says what changed in it since the last one. */
  const show = useCallback((next: RevocationView) => {
    const said = announcements(shown.current, next)
    shown.current = next
    setView(next)
    if (said.length > 0) setHeard(said.join(' '))
  }, [])

  /** Asks every host and feed. Only the newest answer is shown, and a look in flight is waited for. */
  const look = useCallback(function look() {
    if (reads.current === null) return
    if (looks.current > 0) {
      queued.current = true
      return
    }
    const current = reads.current.read()
    if (current === null) return
    looks.current += 1
    setLooking(true)
    ask(() => port.revocationView())
      .then((next) => {
        if (!current()) return
        show(next)
        setProblem(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setProblem(failureMessage(error))
      })
      .finally(() => {
        looks.current -= 1
        if (looks.current > 0) return
        setLooking(false)
        if (queued.current) {
          queued.current = false
          look()
        }
      })
  }, [port, show])

  useEffect(() => {
    const reading = watch([], look)
    reads.current = reading
    return () => {
      reading.stop()
      if (reads.current === reading) reads.current = null
    }
  }, [look])

  // While a request waits for its host, the host's answer is looked for: once the last look has
  // been answered and ten seconds have passed. A screen no one can see asks nothing, and asks as
  // soon as it can be seen.
  const waiting = view !== null && anyWaiting(view)
  useEffect(() => {
    if (!waiting || looking) return
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return
      document.removeEventListener('visibilitychange', onVisible)
      look()
    }
    const timer = window.setTimeout(() => {
      if (document.visibilityState === 'visible') look()
      else document.addEventListener('visibilitychange', onVisible)
    }, LOOK_AFTER_MS)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [waiting, looking, look])

  // Once nothing is being asked, focus goes where the last revocation left it: to its control, or to
  // the words of its row when the answer took the control away. A person who has moved on is not
  // followed: only focus that a press left on nothing, or on a control now disabled, is moved.
  useEffect(() => {
    const next = toFocus.current
    if (next === null || revoking !== null || looking) return
    toFocus.current = null
    const control = controls.current.get(next.key)
    const row = words.current.get(next.key)
    const active = document.activeElement
    const left = active === null || active === document.body || active === control || (active as HTMLButtonElement).disabled
    if (!left) return
    // A row with no words and no control, one whose host cannot be reached, has nothing to take it.
    const target = next.on === 'words' ? (row ?? control) : (control ?? row)
    target?.focus()
  }, [view, failure, revoking, looking])

  const revoke = (host: RevocationHost, device: RevocationDevice) => {
    const key = `${host.reference}/${device.reference}`
    setRevoking(key)
    setFailure(null)
    // A later failure is said again, even in the same words.
    setHeard('')
    ask(() => port.revocationRevoke(host.reference, device.reference))
      .then((next) => {
        // This answer is newer than any look that began before it: none of them may replace it.
        if (reads.current?.read() == null) return
        toFocus.current = { key, on: 'words' }
        show(next)
        setProblem(null)
      })
      .catch((error: unknown) => {
        const message = failureMessage(error)
        toFocus.current = { key, on: 'control' }
        setFailure({ key, message })
        setHeard(`Revoking ${device.name} did not finish. ${message}`)
        // A failure after the request left says so in its own words; the screen looks, so that
        // what it shows is what the host and its feed say now.
        look()
      })
      .finally(() => {
        setRevoking(null)
      })
  }

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Devices</p>
          <h1>Devices on your hosts</h1>
          <p>{REVOCATION_HELP}</p>
        </div>
        <div className="page-actions">
          <Button data-testid="devices-refresh" disabled={looking} onClick={look}>
            Refresh
          </Button>
        </div>
      </header>

      {problem !== null ? (
        <Banner
          tone="warning"
          title="Could not read your hosts"
          detail={problem}
          action={
            <Button disabled={looking} onClick={look}>
              Try again
            </Button>
          }
        />
      ) : null}
      {view !== null && view.ceremony === 'none' ? (
        <Banner tone="accent" title="This computer cannot confirm" detail={CANNOT_CONFIRM} />
      ) : null}
      <div className="visually-hidden" aria-live="polite" data-testid="devices-heard">
        {heard}
      </div>

      {view === null && problem === null ? (
        <p className="muted small">Reading your hosts…</p>
      ) : null}
      {view !== null && view.hosts.length === 0 ? (
        <Card data-testid="devices-none">
          <div className="card-body">
            <p className="account-lead">This computer owns no host.</p>
            <p className="account-note">
              Pair with a host as its owner, or open this application on the computer a host runs
              on, and its devices are listed here.
            </p>
          </div>
        </Card>
      ) : null}
      {view !== null && view.hosts.length > 0 ? (
        <div className="devices-hosts">
          {view.hosts.map((host) => (
            <HostCard
              key={host.reference}
              host={host}
              view={view}
              target={target}
              revoking={revoking}
              failure={failure}
              words={words}
              controls={controls}
              onRevoke={revoke}
            />
          ))}
        </div>
      ) : null}
    </>
  )
}

/** One host with its devices. */
function HostCard({
  host,
  view,
  target,
  revoking,
  failure,
  words,
  controls,
  onRevoke
}: {
  readonly host: RevocationHost
  readonly view: RevocationView
  readonly target: number
  readonly revoking: string | null
  readonly failure: Failure | null
  readonly words: RefObject<Map<string, HTMLElement>>
  readonly controls: RefObject<Map<string, HTMLElement>>
  readonly onRevoke: (host: RevocationHost, device: RevocationDevice) => void
}): ReactNode {
  const contact = describeContact(host)
  const feedLines = host.feed === null ? [] : describeFeed(host.feed, host)
  // A request needs the host to be asked, and for a host reached through its feed, a feed that was
  // read and still has the host. The host on this computer that does not answer is sent nothing.
  const reachable =
    host.route === 'direct'
      ? host.contact === 'answered'
      : host.feed === null || (host.feed.read && !host.feed.removed)
  return (
    <Card data-testid="devices-host">
      <div className="card-header">
        <div className="spacer card-title">
          <h2>{host.name}</h2>
          <p className="muted small">{describeRoute(host, view.feed_origin)}</p>
        </div>
        <Badge tone={host.contact === 'answered' ? 'success' : 'neutral'}>
          {host.contact === 'answered'
            ? 'Answering'
            : host.contact === 'refused'
              ? 'Refusing'
              : 'Not answering'}
        </Badge>
      </div>
      <div className="card-body">
        {contact !== null || feedLines.length > 0 ? (
          <div className="revocation-feed">
            {contact !== null ? <p className="account-note">{contact}</p> : null}
            {feedLines.map((line) => (
              <p className="account-note" key={line} data-testid="devices-feed">
                {line}
              </p>
            ))}
          </div>
        ) : null}
        {host.devices.length > 0 ? (
          <ul className="device-list" data-testid="devices-list">
            {host.devices.map((device) => (
              <DeviceRow
                key={device.reference}
                host={host}
                device={device}
                ceremony={view.ceremony}
                target={target}
                reachable={reachable}
                revoking={revoking}
                failure={failure}
                words={words}
                controls={controls}
                onRevoke={onRevoke}
              />
            ))}
          </ul>
        ) : host.contact === 'answered' ? (
          <p className="account-note">This host lists no devices.</p>
        ) : null}
      </div>
    </Card>
  )
}

/** One device, its standing, and the one control that fits where its revocation stands. */
function DeviceRow({
  host,
  device,
  ceremony,
  target,
  reachable,
  revoking,
  failure,
  words,
  controls,
  onRevoke
}: {
  readonly host: RevocationHost
  readonly device: RevocationDevice
  readonly ceremony: RevocationView['ceremony']
  readonly target: number
  readonly reachable: boolean
  readonly revoking: string | null
  readonly failure: Failure | null
  readonly words: RefObject<Map<string, HTMLElement>>
  readonly controls: RefObject<Map<string, HTMLElement>>
  readonly onRevoke: (host: RevocationHost, device: RevocationDevice) => void
}): ReactNode {
  const key = `${host.reference}/${device.reference}`
  const standing = device.standing
  const badge = standingBadge(standing)
  const sentence = describeStanding(standing, host, device.stale_since_ms)
  const mine = revoking === key
  // Revoking is offered for a device nothing has been asked of, and again for one the host refused
  // in a way a second request can get past. The host on this computer that has not finished is
  // asked about again, which asks nothing new of the person.
  const again = canAskAgainAfter(standing)
  const askAgain = host.route === 'direct' && standing.state === 'acknowledged'
  const offered =
    !device.this_computer &&
    reachable &&
    ((standing.state === 'active' && ceremony !== 'none') ||
      (again && ceremony !== 'none') ||
      askAgain)
  const label = askAgain ? 'Check again' : revokeLabel(ceremony, again)
  const name = askAgain ? checkAgainName(device, host) : revokeName(device, host, ceremony, again)
  const failed = failure !== null && failure.key === key ? failure.message : null
  return (
    <li className="device-row" data-testid="devices-device" data-state={standing.state}>
      <div className="device-words">
        <p className="account-lead device-title">
          <span>{device.name}</span>
          {badge !== null ? <Badge tone={badge.tone}>{badge.text}</Badge> : null}
        </p>
        {sentence !== null ? (
          <p
            className="account-note revocation-state"
            tabIndex={-1}
            ref={(element) => {
              if (element === null) words.current.delete(key)
              else words.current.set(key, element)
            }}
            data-testid="devices-standing"
          >
            {sentence}
          </p>
        ) : null}
        {failed !== null ? (
          <p className="account-note revocation-failure" data-testid="devices-failure">
            Revoking {device.name} did not finish. {failed}
          </p>
        ) : null}
        <p className="account-help">{describeDevice(device)}</p>
      </div>
      {offered && label !== null && name !== null ? (
        <Button
          tone={askAgain ? 'default' : 'danger'}
          data-wraps
          disabled={revoking !== null}
          aria-label={name}
          style={{ minBlockSize: target }}
          ref={(element) => {
            if (element === null) controls.current.delete(key)
            else controls.current.set(key, element)
          }}
          onClick={() => {
            onRevoke(host, device)
          }}
        >
          {mine ? (askAgain ? 'Checking…' : 'Revoking…') : label}
        </Button>
      ) : null}
    </li>
  )
}
