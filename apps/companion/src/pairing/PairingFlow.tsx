/**
 * Pairing this computer with a host.
 *
 * One column, read top to bottom: how to pair, then the attempt, then the hosts this computer is
 * already paired with. Native code runs the attempt and tells this component where it has got to;
 * the component draws that state and nothing else. The one secret the page ever holds is the code a
 * person types, and only in its field: native code parses it and never hands it back, and an
 * invitation pasted from the clipboard is read in native code and never reaches the page.
 *
 * Each state change moves focus to the new state's heading, so a screen reader reads the state
 * rather than the person having to look for it. Nothing spins: while native code works, one status
 * line says what it is doing, and while the page waits for a person the countdown is the only thing
 * that changes.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode, type RefObject } from 'react'

import { Button, Card } from '../components/ui'
import { useApp } from '../app/state'
import {
  failureMessage,
  type AttemptState,
  type FailureKind,
  type HostRow,
  type IntakeView,
  type InvitationSummary,
  type PairingFailure,
  type PairingView
} from '../host/port'
import { VerificationValue } from './VerificationValue'
import {
  actionLabel,
  clockTime,
  codeComplete,
  codeProblem,
  failureSentence,
  failureWords,
  minutesLeft,
  readingFrom,
  timeLeft,
  triesTheCodeAgain,
  type AttemptMode,
  type NextAction,
  type Reading
} from './words'

/** Which of the column's states is showing. */
type Screen = 'entry' | 'pasted' | 'working' | 'awaiting' | 'reconnecting' | 'paired' | 'ended'

function screenOf(view: PairingView): Screen {
  switch (view.state.state) {
    case 'idle':
      return view.invitation ? 'pasted' : 'entry'
    case 'working':
      return 'working'
    case 'awaiting_approval':
      return 'awaiting'
    case 'reconnecting':
      return 'reconnecting'
    case 'paired':
      return 'paired'
    case 'ended':
      return 'ended'
  }
}

/**
 * Whether `view` shows the typed code spent. It is the one secret the page holds, and only until
 * pairing ends: once the attempt pairs, or ends in a way no second try of the same code can mend,
 * it leaves the field.
 */
function spends(view: PairingView): boolean {
  const { state } = view
  return (
    state.state === 'paired' ||
    (state.state === 'ended' &&
      !triesTheCodeAgain(
        failureWords(state.failure.kind, state.service ?? view.origin.host, state.mode).action
      ))
  )
}

/** " until 14:30", or nothing for a grant that does not end. */
function until(ms: number | null): string {
  return ms === null ? '' : ` until ${clockTime(ms)}`
}

/** The first letter of `words` as a capital, for a sentence that starts with it. */
function capitalised(words: string): string {
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/**
 * The pairing screen's column.
 *
 * `chooseHost` is given where the application's commands may go to a paired host: a phone, which has
 * none of its own. It is called with the host's reference, and the host's row then offers the
 * choice. `forgetHost` is given with it: forgetting is this computer's own action, and a host that
 * revoked it is still listed here until it is forgotten.
 */
export function PairingFlow({
  chooseHost,
  forgetHost,
  focusTheField = true,
  device = 'computer'
}: {
  readonly chooseHost?: (reference: string) => Promise<void>
  readonly forgetHost?: (reference: string) => Promise<void>
  /**
   * Whether the code field takes focus when the column is at its start. The desktop's pairing view
   * is a screen of its own and starts typing. On a phone the column is one place among four, and
   * focusing a field there would raise the keyboard over a screen the person only opened.
   */
  readonly focusTheField?: boolean
  /** What the person calls the device the application runs on, in the words that name it. */
  readonly device?: 'phone' | 'computer'
} = {}): ReactNode {
  const { port, say } = useApp()
  const [view, setView] = useState<PairingView | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [composing, setComposing] = useState(false)
  const [codeError, setCodeError] = useState<string | null>(null)
  const [pasteFailure, setPasteFailure] = useState<FailureKind | null>(null)
  const [changing, setChanging] = useState(false)
  const [draftOrigin, setDraftOrigin] = useState('')
  const [now, setNow] = useState(() => Date.now())
  const heading = useRef<HTMLHeadingElement>(null)
  const field = useRef<HTMLInputElement>(null)
  const selectOnEntry = useRef(false)

  useEffect(() => {
    let watching = true
    let stop: (() => void) | null = null
    // The state is read once the listener is registered, so no change can fall between the two.
    // An event heard before the read answers is at least as new, so the read is let go then.
    let heard = false
    const shown = (next: PairingView) => {
      setView(next)
      if (spends(next)) setCode('')
    }
    port
      .onPairing((next) => {
        heard = true
        if (!watching) return
        // The records are still not open, for a reason that has changed: the words follow it.
        if ('unavailable' in next) setFailure(next.unavailable)
        else shown(next)
      })
      .then(async (unlisten) => {
        if (!watching) {
          unlisten()
          return
        }
        stop = unlisten
        const current = await port.pairingView()
        if (watching && !heard) shown(current)
      })
      .catch((error: unknown) => {
        // The read's failure is let go as its answer is when an event was heard: the event is at
        // least as new, and its words are the ones that stand.
        if (watching && !heard) setFailure(failureMessage(error))
      })
    return () => {
      watching = false
      stop?.()
    }
  }, [port])

  const screen = view ? screenOf(view) : null

  // Focus follows the state: the new state's heading, or the field when the person is back to
  // typing a code.
  useEffect(() => {
    if (screen === null) return
    if (screen === 'entry') {
      if (!focusTheField) return
      field.current?.focus()
      if (selectOnEntry.current) {
        field.current?.select()
        selectOnEntry.current = false
      }
      return
    }
    heading.current?.focus()
  }, [screen, focusTheField])

  // A person holds this device beside the host's screen to compare the value on both, so a phone's
  // screen stays on for as long as the value shows, and may sleep again when it goes. A computer
  // has nothing to keep on, and the host says so by doing nothing.
  const showsValue =
    view?.state.state === 'awaiting_approval' ||
    (view?.state.state === 'reconnecting' && view.state.value !== null)
  const keepsAwake = showsValue && device === 'phone'
  useEffect(() => {
    if (!keepsAwake) return
    port.pairingKeepAwake(true).catch(() => undefined)
    return () => {
      port.pairingKeepAwake(false).catch(() => undefined)
    }
  }, [port, keepsAwake])

  // The countdown ticks while the person decides, and says "One minute left" once.
  const expiresAt =
    view?.state.state === 'awaiting_approval' || view?.state.state === 'reconnecting'
      ? view.state.expires_at_ms
      : null
  useEffect(() => {
    if (expiresAt === null) return
    const tick = setInterval(() => {
      setNow(Date.now())
    }, 1000)
    return () => {
      clearInterval(tick)
    }
  }, [expiresAt])
  // Announced once, when the last minute begins: the region's text changes then and not again.
  const announcement =
    expiresAt !== null && minutesLeft(expiresAt, now) <= 1 ? 'One minute left' : ''

  const service = view?.origin.host ?? 'the pairing service'
  const thisDevice = device === 'phone' ? 'this phone' : 'this computer'

  const stop = useCallback(
    (afterwards?: () => void) => {
      port
        .pairingStop()
        .then(() => {
          afterwards?.()
        })
        .catch((error: unknown) => {
          say(failureMessage(error), 'danger')
        })
    },
    [port, say]
  )

  const pair = () => {
    const problem = codeProblem(code)
    if (problem !== null || !codeComplete(code)) {
      setCodeError(problem ?? 'A code has ten characters.')
      return
    }
    setCodeError(null)
    port.pairingStartCode(code).catch((error: unknown) => {
      setCodeError(failureMessage(error))
    })
  }

  // Taking an invitation in: from the pasteboard, from the phone's scanner or from a picture. What
  // comes back says what it was, never what it says; a scanner or a picker the person closed is no
  // failure and says nothing.
  const [taking, setTaking] = useState(false)
  const takeIn = (take: () => Promise<IntakeView>) => {
    // One at a time: a second request while the scanner or the picker is up would ask the system
    // the same question twice.
    if (taking) return
    setTaking(true)
    setPasteFailure(null)
    take()
      .then((result) => {
        if (result.failure !== null) setPasteFailure(result.failure)
        if (result.cleared) say('The invitation was taken from the clipboard and cleared from it.')
        if (result.declined) say('Nothing was contacted.')
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setTaking(false)
      })
  }
  const paste = () => {
    takeIn(() => port.pairingPaste())
  }
  const scan = () => {
    takeIn(() => port.pairingScan())
  }
  const choosePhoto = () => {
    takeIn(() => port.pairingScanPhoto())
  }
  const reading: Reading = readingFrom(view?.sources)
  // The same invitation brought in again, the way this device brings one in first.
  const again = () => {
    if (reading === 'camera') scan()
    else if (reading === 'photo') choosePhoto()
    else paste()
  }
  const openSettings = () => {
    port.pairingOpenSettings().catch((error: unknown) => {
      say(failureMessage(error), 'danger')
    })
  }

  const next = (action: NextAction) => {
    switch (action) {
      case 'fix_code':
        selectOnEntry.current = true
        stop()
        return
      case 'change_service':
        stop(() => {
          setDraftOrigin(view?.origin.origin ?? '')
          setChanging(true)
        })
        return
      case 'new_invitation':
        stop(again)
        return
      case 'open_settings':
        openSettings()
        return
      case 'new_code':
      case 'try_again':
      case 'start_again':
      case 'done':
        stop()
        return
    }
  }

  if (view === null) {
    // The records could not be read, or opened at all: the words are native code's own, and say
    // what does not work, why, and what to do. They stay in place of the column, because there is
    // nothing to enter a code into.
    return failure ? (
      <div className="pairing-column">
        <section aria-labelledby="pairing-unavailable" className="pairing-section">
          <h1 id="pairing-unavailable">Cannot pair</h1>
          <p role="alert" className="pairing-unavailable" data-testid="records-failure">
            {failure}
          </p>
        </section>
      </div>
    ) : null
  }

  return (
    <div className="pairing-column">
      <p className="visually-hidden" role="status" aria-live="polite">
        {announcement}
      </p>
      {screen === 'entry' ? (
        <section aria-labelledby="pairing-entry" className="pairing-section">
          <h1 id="pairing-entry" ref={heading} tabIndex={-1}>
            Pair with a host
          </h1>
          <p className="muted">
            {view.sources.camera
              ? 'Scan the QR code your host shows, or enter its pairing code. '
              : 'Enter the pairing code your host shows. '}
            On the host, <code>kr pair invite</code> makes one.
          </p>
          {view.sources.camera ? (
            <div className="pairing-scan" aria-busy={taking}>
              <Button data-wraps tone="primary" data-testid="scan-code" disabled={taking} onClick={scan}>
                Scan code
              </Button>
            </div>
          ) : null}
          <form
            className="pairing-entry"
            onSubmit={(event) => {
              event.preventDefault()
              pair()
            }}
          >
            <div className="form-field">
              <label htmlFor="pairing-code">Pairing code</label>
              <input
                id="pairing-code"
                ref={field}
                className="mono"
                data-testid="code-input"
                value={code}
                placeholder="XXXX-XXX-XXX"
                autoCapitalize="off"
                autoCorrect="off"
                autoComplete="off"
                spellCheck={false}
                enterKeyHint="go"
                aria-invalid={codeError !== null}
                aria-describedby={codeError !== null ? 'pairing-code-problem' : undefined}
                onCompositionStart={() => {
                  setComposing(true)
                }}
                onCompositionEnd={(event) => {
                  setComposing(false)
                  setCodeError(codeProblem(event.currentTarget.value))
                }}
                onChange={(event) => {
                  setCode(event.target.value)
                  // An input method's text is checked once its composition ends, not before.
                  if (!composing) setCodeError(codeProblem(event.target.value))
                }}
              />
              {codeError !== null ? (
                <p id="pairing-code-problem" className="form-hint danger-text" role="alert">
                  {codeError}
                </p>
              ) : null}
            </div>
            <div className="row wrap">
              <Button data-wraps type="submit" tone="primary" data-testid="pair" disabled={!codeComplete(code)}>
                Pair
              </Button>
              {view.sources.photo ? (
                <Button
                  data-wraps
                  tone="quiet"
                  data-testid="choose-photo"
                  disabled={taking}
                  onClick={choosePhoto}
                >
                  Choose a photo
                </Button>
              ) : null}
              <Button
                data-wraps
                tone="quiet"
                data-testid="paste-invitation"
                disabled={taking}
                onClick={paste}
              >
                Paste invitation
              </Button>
            </div>
            {pasteFailure !== null ? (
              <p className="small danger-text" role="alert" data-testid="paste-failure">
                {failureWords(pasteFailure, service, 'code', reading).sentence}
              </p>
            ) : null}
            {pasteFailure === 'camera_denied' ? (
              <div className="row">
                <Button data-wraps tone="quiet" data-testid="open-settings" onClick={openSettings}>
                  Open Settings
                </Button>
              </div>
            ) : null}
          </form>
          <div className="pairing-settings">
            <div className="divided-row">
              <p className="small">
                Codes go through <strong data-testid="pairing-service">{view.origin.host}</strong>
              </p>
              <Button data-wraps
                tone="quiet"
                data-testid="change-service"
                aria-expanded={changing}
                onClick={() => {
                  setDraftOrigin(view.origin.origin)
                  setChanging((open) => !open)
                }}
              >
                Change
              </Button>
            </div>
            {changing ? (
              <form
                className="form-field"
                onSubmit={(event) => {
                  event.preventDefault()
                  port
                    .pairingSetOrigin(draftOrigin)
                    .then((origin) => {
                      setChanging(false)
                      say(`Codes now go through ${origin.host}.`)
                    })
                    .catch((error: unknown) => {
                      say(failureMessage(error), 'danger')
                    })
                }}
              >
                <label htmlFor="pairing-service">Pairing service</label>
                <input
                  id="pairing-service"
                  data-testid="service-input"
                  value={draftOrigin}
                  autoCapitalize="off"
                  autoCorrect="off"
                  spellCheck={false}
                  onChange={(event) => {
                    setDraftOrigin(event.target.value)
                  }}
                />
                <p className="form-hint">An https address, like https://reach.kala.to.</p>
                <div className="row">
                  <Button data-wraps type="submit" tone="primary" data-testid="save-service">
                    Use this service
                  </Button>
                </div>
              </form>
            ) : null}
            <p className="small muted" data-testid="device-name">
              {capitalised(thisDevice)} appears as “{view.device_name}”
            </p>
          </div>
        </section>
      ) : null}

      {screen === 'pasted' && view.invitation ? (
        <Pasted
          thisDevice={thisDevice}
          invitation={view.invitation}
          heading={heading}
          now={now}
          onPair={() => {
            port.pairingStartRead().catch((error: unknown) => {
              say(failureMessage(error), 'danger')
            })
          }}
          onCancel={() => {
            stop()
          }}
        />
      ) : null}

      {screen === 'working' ? (
        <section aria-labelledby="pairing-working" className="pairing-section">
          <h1 id="pairing-working" ref={heading} tabIndex={-1} className="visually-hidden">
            Pairing
          </h1>
          <p className="pairing-status" role="status" data-testid="pairing-status">
            {workingLine(view.state)}
          </p>
        </section>
      ) : null}

      {screen === 'awaiting' && view.state.state === 'awaiting_approval' ? (
        <section aria-labelledby="pairing-awaiting" className="pairing-section">
          <h1 id="pairing-awaiting" ref={heading} tabIndex={-1}>
            Check this value on the host
          </h1>
          <VerificationValue value={view.state.value} />
          <p>Approve {thisDevice} on the host only if it shows the same value.</p>
          <p className="muted" data-testid="grant-line">
            If approved, {thisDevice} can {view.state.authority}
            {until(view.state.grant_expires_at_ms)}.
          </p>
          <p className="small muted tabular" data-testid="waiting-line">
            Waiting for approval
            {view.state.expires_at_ms !== null ? `, ${timeLeft(view.state.expires_at_ms, now)}` : ''}
          </p>
          <div className="row">
            <Button data-wraps
              data-testid="stop-waiting"
              onClick={() => {
                setCode('')
                stop(() => {
                  say('Stopped. The host keeps the request until it expires or the owner declines it.')
                })
              }}
            >
              Stop waiting
            </Button>
          </div>
        </section>
      ) : null}

      {screen === 'reconnecting' && view.state.state === 'reconnecting' ? (
        <section aria-labelledby="pairing-reconnecting" className="pairing-section">
          <h1 id="pairing-reconnecting" ref={heading} tabIndex={-1}>
            {view.state.value !== null ? 'Check this value on the host' : 'Reaching the host'}
          </h1>
          {view.state.value !== null ? <VerificationValue value={view.state.value} /> : null}
          <p className="pairing-status" role="status" data-testid="pairing-status">
            Connection lost. Reconnecting.
          </p>
          <div className="row">
            <Button data-wraps
              data-testid="stop-waiting"
              onClick={() => {
                setCode('')
                stop(() => {
                  say('Stopped. The host keeps the request until it expires or the owner declines it.')
                })
              }}
            >
              Stop waiting
            </Button>
          </div>
        </section>
      ) : null}

      {screen === 'paired' && view.state.state === 'paired' ? (
        <section aria-labelledby="pairing-paired" className="pairing-section">
          <h1 id="pairing-paired" ref={heading} tabIndex={-1}>
            Paired with {view.state.host.name ?? 'your host'}
          </h1>
          <p data-testid="paired-line">
            {view.state.host.owner
              ? `${capitalised(thisDevice)} is an owner of ${view.state.host.name ?? 'your host'}. It will ask you to confirm changes there.`
              : `${capitalised(thisDevice)} can ${view.state.host.authority} on ${view.state.host.name ?? 'your host'}${until(view.state.host.grant_expires_at_ms)}.`}
          </p>
          <div className="row">
            <Button data-wraps
              tone="primary"
              data-testid="pairing-done"
              onClick={() => {
                stop()
              }}
            >
              Done
            </Button>
          </div>
        </section>
      ) : null}

      {screen === 'ended' && view.state.state === 'ended' ? (
        <Ended
          failure={view.state.failure}
          mode={view.state.mode}
          service={view.state.service ?? service}
          reading={reading}
          heading={heading}
          onAction={next}
        />
      ) : null}

      {screen === 'entry' && view.hosts.length > 0 ? (
        <PairedHosts
          hosts={view.hosts}
          chooseHost={chooseHost}
          forgetHost={
            forgetHost === undefined
              ? undefined
              : async (host) => {
                  await forgetHost(host.reference)
                  say(`${host.name} is forgotten. This phone no longer lists it.`)
                  // The row the person was on is gone: the screen's own heading is where they are.
                  heading.current?.focus()
                }
          }
        />
      ) : null}
    </div>
  )
}

/**
 * How an attempt ended, in the words for how it was made and the service it went through, with
 * the one thing the person can do next.
 */
function Ended({
  failure,
  mode,
  service,
  reading,
  heading,
  onAction
}: {
  readonly failure: PairingFailure
  readonly mode: AttemptMode
  readonly service: string
  readonly reading: Reading
  readonly heading: RefObject<HTMLHeadingElement | null>
  readonly onAction: (action: NextAction) => void
}): ReactNode {
  const { action } = failureWords(failure.kind, service, mode, reading)
  return (
    <section aria-labelledby="pairing-ended" className="pairing-section">
      <h1 id="pairing-ended" ref={heading} tabIndex={-1}>
        Pairing did not finish
      </h1>
      <p role="alert" data-testid="failure-sentence">
        {failureSentence(failure, service, mode, reading)}
      </p>
      <div className="row">
        <Button data-wraps
          tone="primary"
          data-testid="failure-action"
          onClick={() => {
            onAction(action)
          }}
        >
          {actionLabel(action, reading)}
        </Button>
      </div>
    </section>
  )
}

/** The one line a working state shows. */
function workingLine(state: AttemptState): string {
  if (state.state !== 'working') return ''
  switch (state.stage) {
    case 'reaching_service':
      return 'Reaching the pairing service'
    case 'checking_code':
      return 'Checking the code'
    case 'reaching_host':
      return 'Reaching the host'
  }
}

/** The summary of an invitation read from the clipboard, before the person uses it. */
function Pasted({
  thisDevice,
  invitation,
  heading,
  now,
  onPair,
  onCancel
}: {
  readonly thisDevice: string
  readonly invitation: InvitationSummary
  readonly heading: RefObject<HTMLHeadingElement | null>
  readonly now: number
  readonly onPair: () => void
  readonly onCancel: () => void
}): ReactNode {
  return (
    <section
      aria-labelledby="pairing-pasted"
      className="pairing-section"
      onKeyDown={(event) => {
        if (event.key === 'Escape') onCancel()
      }}
    >
      <h1 id="pairing-pasted" ref={heading} tabIndex={-1}>
        Pair with this invitation?
      </h1>
      <Card>
        <div className="card-body">
          <p data-testid="invitation-summary">
            {invitation.mode === 'direct'
              ? `Invitation from a host on this network. If approved, ${thisDevice} can ${invitation.authority ?? 'view sessions'}${until(invitation.grant_expires_at_ms)}.${
                  invitation.expires_at_ms !== null
                    ? ` It expires in ${timeLeft(invitation.expires_at_ms, now).replace(' left', '')}.`
                    : ''
                }`
              : `Code for a host that uses ${invitation.origin_host ?? 'another service'}.`}
          </p>
        </div>
        <div className="card-footer">
          <Button data-wraps onClick={onCancel} data-testid="cancel-invitation">
            Cancel
          </Button>
          <Button data-wraps tone="primary" onClick={onPair} data-testid="pair-invitation">
            Pair
          </Button>
        </div>
      </Card>
    </section>
  )
}

/** The hosts this computer is paired with, newest first. */
function PairedHosts({
  hosts,
  chooseHost,
  forgetHost
}: {
  readonly hosts: readonly HostRow[]
  readonly chooseHost: ((reference: string) => Promise<void>) | undefined
  readonly forgetHost: ((host: HostRow) => Promise<void>) | undefined
}): ReactNode {
  const [using, setUsing] = useState<string | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  // The host being asked about, and the one being forgotten. Forgetting is asked twice: this
  // computer cannot pair with the host again from here, so the first press only asks.
  const [asking, setAsking] = useState<string | null>(null)
  const [forgetting, setForgetting] = useState<string | null>(null)
  const [forgetFailure, setForgetFailure] = useState<string | null>(null)
  const keep = useRef<HTMLButtonElement>(null)
  const forgetButtons = useRef(new Map<string, HTMLButtonElement>())
  const restore = useRef<string | null>(null)

  // Focus follows the question: to the safe answer when it opens, and back to the host's own
  // control when it closes without an answer.
  useEffect(() => {
    if (asking !== null) {
      keep.current?.focus()
      return
    }
    if (restore.current !== null) {
      forgetButtons.current.get(restore.current)?.focus()
      restore.current = null
    }
  }, [asking])

  return (
    <section aria-labelledby="paired-hosts" className="pairing-section">
      <h2 id="paired-hosts">Paired hosts</h2>
      <ul className="paired-hosts" data-testid="paired-hosts">
        {hosts.map((host) => (
          <li key={host.reference} className="divided-row">
            <div className="spacer">
              <strong>{host.name}</strong>
              <p className="small muted">
                {host.owner
                  ? 'Owner'
                  : `Can ${host.authority}${until(host.grant_expires_at_ms)}`}
              </p>
            </div>
            {host.in_contact === null ? null : (
              <span className="small muted">
                <span className={`status-dot${host.in_contact ? '' : ' offline'}`} />{' '}
                {host.in_contact ? 'In contact' : 'Not in contact'}
              </span>
            )}
            {asking === host.reference && forgetHost !== undefined ? (
              <div
                className="paired-host-ask"
                role="group"
                aria-label={`Forget ${host.name}`}
                data-testid="forget-host-ask"
              >
                <p className="small">
                  Forget {host.name}? This phone stops listing it and stops reaching it. The host
                  keeps any access it still gives this phone until you remove the phone there.
                  {host.owner ? ' This phone also stops confirming requests from it.' : ''}
                </p>
                <div className="row wrap">
                  <Button data-wraps
                    ref={keep}
                    data-testid="keep-host"
                    onClick={() => {
                      restore.current = host.reference
                      setAsking(null)
                    }}
                  >
                    Keep it
                  </Button>
                  <Button data-wraps
                    tone="danger"
                    data-testid="forget-host-confirm"
                    aria-disabled={forgetting !== null}
                    onClick={() => {
                      // Not disabled while it works: a button that is disabled loses the focus
                      // the person's keyboard or screen reader is on, and keeps it nowhere after a
                      // refusal.
                      if (forgetting !== null) return
                      setForgetting(host.reference)
                      setForgetFailure(null)
                      forgetHost(host)
                        .then(() => {
                          setAsking(null)
                        })
                        .catch((error: unknown) => {
                          setForgetFailure(failureMessage(error))
                        })
                        .finally(() => {
                          setForgetting(null)
                        })
                    }}
                  >
                    {forgetting === host.reference ? 'Forgetting' : 'Forget'}
                  </Button>
                </div>
              </div>
            ) : (
              <>
                {chooseHost === undefined ? null : host.in_use ? (
                  <span className="small muted" data-testid="host-in-use">
                    In use
                  </span>
                ) : (
                  <Button data-wraps
                    disabled={using !== null}
                    data-testid="use-host"
                    onClick={() => {
                      setUsing(host.reference)
                      setFailure(null)
                      chooseHost(host.reference)
                        .catch((error: unknown) => {
                          setFailure(failureMessage(error))
                        })
                        .finally(() => {
                          setUsing(null)
                        })
                    }}
                  >
                    {using === host.reference ? 'Reaching the host' : 'Use this host'}
                  </Button>
                )}
                {forgetHost === undefined ? null : (
                  <Button data-wraps
                    ref={(button) => {
                      if (button === null) forgetButtons.current.delete(host.reference)
                      else forgetButtons.current.set(host.reference, button)
                    }}
                    tone="quiet"
                    aria-label={`Forget ${host.name}`}
                    data-testid="forget-host"
                    disabled={using !== null}
                    onClick={() => {
                      setForgetFailure(null)
                      setAsking(host.reference)
                    }}
                  >
                    Forget
                  </Button>
                )}
              </>
            )}
          </li>
        ))}
      </ul>
      {failure === null ? null : (
        <p role="alert" className="small" data-testid="use-host-failure">
          {failure}
        </p>
      )}
      {forgetFailure === null ? null : (
        <p role="alert" className="small danger-text" data-testid="forget-host-failure">
          {forgetFailure}
        </p>
      )}
    </section>
  )
}
