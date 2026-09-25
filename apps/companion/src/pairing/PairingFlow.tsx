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
  type InvitationSummary,
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
  timeLeft,
  triesTheCodeAgain,
  type NextAction
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
      !triesTheCodeAgain(failureWords(state.failure.kind, view.origin.host).action))
  )
}

/** " until 14:30", or nothing for a grant that does not end. */
function until(ms: number | null): string {
  return ms === null ? '' : ` until ${clockTime(ms)}`
}

/** The pairing screen's column. */
export function PairingFlow(): ReactNode {
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
        if (watching) shown(next)
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
        if (watching) setFailure(failureMessage(error))
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
      field.current?.focus()
      if (selectOnEntry.current) {
        field.current?.select()
        selectOnEntry.current = false
      }
      return
    }
    heading.current?.focus()
  }, [screen])

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

  const paste = () => {
    setPasteFailure(null)
    port
      .pairingPaste()
      .then((result) => {
        if (result.failure !== null) setPasteFailure(result.failure)
        if (result.cleared) say('The invitation was taken from the clipboard and cleared from it.')
        if (result.declined) say('Nothing was contacted.')
      })
      .catch((error: unknown) => {
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
      case 'paste_again':
        stop(paste)
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
    return failure ? (
      <p className="small danger-text" role="alert">
        {failure}
      </p>
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
            Enter the pairing code your host shows. On the host, <code>kr pair invite</code> makes
            one.
          </p>
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
              <Button type="submit" tone="primary" data-testid="pair" disabled={!codeComplete(code)}>
                Pair
              </Button>
              <Button tone="quiet" data-testid="paste-invitation" onClick={paste}>
                Paste invitation
              </Button>
            </div>
            {pasteFailure !== null ? (
              <p className="small danger-text" role="alert" data-testid="paste-failure">
                {failureWords(pasteFailure, service).sentence}
              </p>
            ) : null}
          </form>
          <div className="pairing-settings">
            <div className="divided-row">
              <p className="small">
                Codes go through <strong data-testid="pairing-service">{view.origin.host}</strong>
              </p>
              <Button
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
                  <Button type="submit" tone="primary" data-testid="save-service">
                    Use this service
                  </Button>
                </div>
              </form>
            ) : null}
            <p className="small muted" data-testid="device-name">
              This computer appears as “{view.device_name}”
            </p>
          </div>
        </section>
      ) : null}

      {screen === 'pasted' && view.invitation ? (
        <Pasted
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
          <p>Approve this computer on the host only if it shows the same value.</p>
          <p className="muted" data-testid="grant-line">
            If approved, this computer can {view.state.authority}
            {until(view.state.grant_expires_at_ms)}.
          </p>
          <p className="small muted tabular" data-testid="waiting-line">
            Waiting for approval
            {view.state.expires_at_ms !== null ? `, ${timeLeft(view.state.expires_at_ms, now)}` : ''}
          </p>
          <div className="row">
            <Button
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
            <Button
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
              ? `This computer is an owner of ${view.state.host.name ?? 'your host'}. It will ask you to confirm changes there.`
              : `This computer can ${view.state.host.authority} on ${view.state.host.name ?? 'your host'}${until(view.state.host.grant_expires_at_ms)}.`}
          </p>
          <div className="row">
            <Button
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
        <section aria-labelledby="pairing-ended" className="pairing-section">
          <h1 id="pairing-ended" ref={heading} tabIndex={-1}>
            Pairing did not finish
          </h1>
          <p role="alert" data-testid="failure-sentence">
            {failureSentence(view.state.failure, service)}
          </p>
          <div className="row">
            <Button
              tone="primary"
              data-testid="failure-action"
              onClick={() => {
                if (view.state.state === 'ended') {
                  next(failureWords(view.state.failure.kind, service).action)
                }
              }}
            >
              {actionLabel(failureWords(view.state.failure.kind, service).action)}
            </Button>
          </div>
        </section>
      ) : null}

      {screen === 'entry' && view.hosts.length > 0 ? <PairedHosts hosts={view.hosts} /> : null}
    </div>
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
  invitation,
  heading,
  now,
  onPair,
  onCancel
}: {
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
              ? `Invitation from a host on this network. If approved, this computer can ${invitation.authority ?? 'view sessions'}${until(invitation.grant_expires_at_ms)}.${
                  invitation.expires_at_ms !== null
                    ? ` It expires in ${timeLeft(invitation.expires_at_ms, now).replace(' left', '')}.`
                    : ''
                }`
              : `Code for a host that uses ${invitation.origin_host ?? 'another service'}.`}
          </p>
        </div>
        <div className="card-footer">
          <Button onClick={onCancel} data-testid="cancel-invitation">
            Cancel
          </Button>
          <Button tone="primary" onClick={onPair} data-testid="pair-invitation">
            Pair
          </Button>
        </div>
      </Card>
    </section>
  )
}

/** The hosts this computer is paired with, newest first. */
function PairedHosts({ hosts }: { readonly hosts: readonly HostRow[] }): ReactNode {
  return (
    <section aria-labelledby="paired-hosts" className="pairing-section">
      <h2 id="paired-hosts">Paired hosts</h2>
      <ul className="paired-hosts" data-testid="paired-hosts">
        {hosts.map((host, index) => (
          // A host has no identifier the page may hold, and the list is shown in the order kept.
          <li key={index} className="divided-row">
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
          </li>
        ))}
      </ul>
    </section>
  )
}
