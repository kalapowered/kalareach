/**
 * The invitations at the head of the inbox: what other people have shared with this phone, waiting
 * for it to say yes.
 *
 * An invitation is a decision, so it sits where the phone opens, above what the phone's own host
 * has raised. A row says who shared which session; the card it opens says what accepting lets the
 * phone do, what it will show and when it ends, all of it from what the host stated, and it holds
 * the only control that accepts. Accepting commits on a completed press, as an approval does, so a
 * pocket press decides nothing.
 *
 * An acceptance is one of the four actions this application keeps its word about. When the host's
 * answer is lost, or the host refuses in a way that does not settle it, the acceptance is listed
 * here as unfinished, in the host's words, and the person can ask the host what became of it.
 * What the host lists, and no refusal, decides whether the invitation was accepted.
 *
 * Reads happen while the inbox is shown. A new invitation arrives without moving what the person
 * is looking at: the inbox keeps the first row in view where it is (`useKeepPlace`), and when the
 * person has scrolled a pill says that something arrived above.
 */

import { useEffect, useRef, useState, type ReactNode } from 'react'

import type { ShareOffer } from '@kalareach/protocol'

import { Button, CommitButton, Sheet } from '../../components/ui'
import { useApp } from '../../app/state'
import { prefersReducedMotion } from '../../motion'
import { type AttemptView } from '../../host/port'
import { deskOf } from '../../model/sharing-desk'
import {
  STALE_WORDS,
  acceptedShareWords,
  acceptedWords,
  endsLine,
  hostWords,
  offerEnds,
  offerRole,
  offerTitle,
  sessionWords,
  showsLines,
  thisLetsYou,
  youCan
} from '../../model/shared-with-you'
import { attemptWords, failureText, nameWords, visibly } from '../../model/sharing'
import { ask } from '../model/call'
import { useHeld, useHeldBook } from '../model/held'
import { minimumTarget, type Surface } from '../platform'
import '../shared.css'

/** How far the inbox is scrolled before a new row above is something to be told of. */
const SCROLLED = 8

/** The sheet's root, which is gone once it has finished leaving. */
const SHEET = '[data-testid="sheet"]'

/**
 * Keeps focus from being lost with a row that goes.
 *
 * A row that has focus (the one that opened the card, which the sheet gives focus back to when it
 * closes) can be taken away, by an acceptance or by a read, while the card is still open or after
 * it has closed. Focus then falls to the page's body. This watches the area it is given: when the
 * element that last had focus in it has gone, it waits for the card to leave if one is open, and then
 * puts focus on what `find` returns, but only if focus is on nothing. Every observer it makes is its
 * own and ends with the area, and nothing it does depends on a press or a key, so a person who
 * moves focus themselves, or a screen reader's cursor, is never taken from where they put it.
 */
function useKeepFocus(area: React.RefObject<HTMLElement | null>, find: () => HTMLElement | null): void {
  const where = useRef(find)
  useEffect(() => {
    where.current = find
  })
  useEffect(() => {
    const within = area.current
    if (within === null) return
    let last: Element | null = null
    let waiting: MutationObserver | null = null
    const stopWaiting = () => {
      waiting?.disconnect()
      waiting = null
    }
    const settle = () => {
      if (last === null || last.isConnected) {
        stopWaiting()
        return
      }
      // A card that is open holds focus; what it was opened from is dealt with once it has left.
      if (document.querySelector(SHEET) !== null) return
      const active = document.activeElement
      last = null
      stopWaiting()
      // Focus put on a row is noted by the listener above, so it is the row that is watched next.
      if (active === null || active === document.body || !active.isConnected) where.current()?.focus()
    }
    const noted = (event: FocusEvent) => {
      last = event.target instanceof Element ? event.target : null
    }
    within.addEventListener('focusin', noted)
    const removal = new MutationObserver(() => {
      if (last === null || last.isConnected) return
      settle()
      if (last !== null && waiting === null) {
        waiting = new MutationObserver(settle)
        waiting.observe(document.body, { childList: true, subtree: true })
      }
    })
    removal.observe(within, { childList: true, subtree: true })
    return () => {
      within.removeEventListener('focusin', noted)
      removal.disconnect()
      stopWaiting()
    }
  }, [area])
}

/** The invitations, and the acceptances not seen to the end. */
export function Offers({ surface }: { readonly surface: Surface }): ReactNode {
  const { port, say } = useApp()
  const book = useHeldBook()
  const view = useHeld()
  const target = minimumTarget(surface)
  const head = useRef<HTMLDivElement | null>(null)
  const [open, setOpen] = useState<string | null>(null)
  const [accepting, setAccepting] = useState<string | null>(null)
  const [unseen, setUnseen] = useState(0)
  const [said, setSaid] = useState('')

  // A new invitation is told once, when it arrives: to a screen reader at once, and to the eye as a
  // pill when the person has scrolled past the head. The callback is the book telling this screen.
  useEffect(() => {
    let seq = book.snapshot().arrived.seq
    return book.subscribe(() => {
      const now = book.snapshot()
      if (now.arrived.seq === seq) return
      seq = now.arrived.seq
      const fresh = now.offers.filter(
        (offer) => now.arrived.invitationIds.includes(offer.invitation_id)
      )
      if (fresh.length === 0) return
      setSaid(
        fresh.length === 1 && fresh[0] !== undefined
          ? `New invitation. ${offerTitle(now.hostName, fresh[0])}`
          : `${String(fresh.length)} new invitations.`
      )
      const scroller = head.current?.closest<HTMLElement>('.m-main')
      if (scroller && scroller.scrollTop > SCROLLED) setUnseen((count) => count + fresh.length)
    })
  }, [book])

  // Back at the top, the pill has nothing left to say.
  useEffect(() => {
    const scroller = head.current?.closest<HTMLElement>('.m-main')
    if (!scroller) return
    const onScroll = () => {
      if (scroller.scrollTop <= SCROLLED) setUnseen(0)
    }
    scroller.addEventListener('scroll', onScroll, { passive: true })
    return () => {
      scroller.removeEventListener('scroll', onScroll)
    }
  }, [])

  const shown = view.status === 'ready'
  const offers = view.offers.filter((offer) => !view.hidden.includes(offer.invitation_id))
  const attempts = view.attempts.filter((attempt) => !attempt.hidden && !isDone(attempt))
  const putOff = view.attempts.filter((attempt) => attempt.hidden && attempt.phase !== 'closed')
  const host = view.hostName
  const desk = deskOf(port)

  // An acceptance that ended as accepted without the page being told, because it was carried on in
  // the background or found by a read, is told once and its record removed.
  useEffect(() => {
    for (const attempt of view.attempts) {
      if (attempt.phase !== 'closed' || attempt.outcome !== 'happened') continue
      if (!desk.firstTime(attempt.action_id)) continue
      say(
        acceptedShareWords(
          view.shares.find((each) => each.grant.grant_id === attempt.grant_id),
          view.readAtMs
        )
      )
      void ask(() => port.attemptRemove(attempt.action_id)).then(
        () => {
          book.refresh()
        },
        (failure: unknown) => {
          say(failureText(failure), 'danger')
        }
      )
    }
  }, [view, desk, port, book, say])

  useKeepFocus(
    head,
    () =>
      head.current?.querySelector<HTMLElement>('[data-offer]') ??
      head.current?.querySelector<HTMLElement>('[data-attempt]') ??
      document.getElementById('main')
  )

  /** Closes the card of `offer` and no other: another may have been opened while this was sent. */
  const closeCardOf = (offer: ShareOffer) => {
    setOpen((current) => (current === offer.invitation_id ? null : current))
  }

  const accept = (offer: ShareOffer) => {
    setAccepting(offer.invitation_id)
    ask(() => port.grantRedeem({ invitation_id: offer.invitation_id }))
      .then((done) => {
        if (done.attempt.phase === 'closed' && done.attempt.outcome === 'happened') {
          // The host answered with its result, so the invitation is no longer offered: it is out of
          // sight at once, and the next read says the same.
          book.taken(offer.invitation_id)
          if (desk.firstTime(done.attempt.action_id)) say(acceptedWords(offer, Date.now()))
        } else {
          // The host's answer was lost or did not settle it. The row for the acceptance says where
          // it stands, in the host's words, and what the host lists decides how it ended.
          book.keep(done.attempt)
          say(`Waiting to hear from the host about ${sessionWords(offer.display_number)}.`, 'pending')
        }
        closeCardOf(offer)
      })
      .catch((failure: unknown) => {
        closeCardOf(offer)
        say(failureText(failure), 'danger')
      })
      .finally(() => {
        setAccepting(null)
        book.refresh()
      })
  }

  const notNow = (offer: ShareOffer) => {
    setOpen(null)
    book.putOff(offer.invitation_id)
  }

  const askHost = (attempt: AttemptView) => {
    ask(() => port.attemptAsk(attempt.action_id))
      .then((done) => {
        if (done.value === null) {
          say('The host did not say what became of it. Ask again in a moment.', 'pending')
        } else if (desk.firstTime(done.attempt.action_id)) {
          say('Accepted.')
        }
      })
      .catch((failure: unknown) => {
        say(failureText(failure), 'danger')
      })
      .finally(() => {
        book.refresh()
      })
  }

  const setHidden = (attempt: AttemptView, hidden: boolean) => {
    void ask(() => port.attemptSetHidden(attempt.action_id, hidden)).then(
      () => {
        book.refresh()
      },
      (failure: unknown) => {
        say(failureText(failure), 'danger')
      }
    )
  }

  const remove = (attempt: AttemptView) => {
    void ask(() => port.attemptRemove(attempt.action_id)).then(
      () => {
        book.refresh()
      },
      (failure: unknown) => {
        say(failureText(failure), 'danger')
      }
    )
  }

  const jump = () => {
    const scroller = head.current?.closest<HTMLElement>('.m-main')
    scroller?.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' })
    setUnseen(0)
    head.current?.querySelector<HTMLElement>('[data-offer]')?.focus({ preventScroll: true })
  }

  const opened = offers.find((offer) => offer.invitation_id === open) ?? null
  const unsettled =
    opened === null
      ? null
      : (view.attempts.find(
          (attempt) => attempt.grant_id === opened.grant_id && attempt.phase !== 'closed'
        ) ?? null)

  return (
    <>
      {unseen > 0 ? (
        <div className="sw-new">
          <button type="button" className="sw-new-button" style={{ minBlockSize: target }} onClick={jump}>
            {unseen === 1 ? '1 new invitation' : `${String(unseen)} new invitations`}
          </button>
        </div>
      ) : null}

      <div role="status" aria-live="polite" className="visually-hidden" data-testid="offers-said">
        {said}
      </div>

      <div ref={head} data-testid="offers-head">
        {shown && (offers.length > 0 || attempts.length > 0 || view.hidden.length > 0 || putOff.length > 0) ? (
          <section className="sw-group" aria-labelledby="offers-heading" data-testid="offers">
            <h2 className="sw-heading" id="offers-heading">
              Invitations
            </h2>
            {view.stale ? <p className="sw-stale">{STALE_WORDS}</p> : null}

            {offers.length > 0 ? (
              <ul className="m-list">
                {offers.map((offer) => (
                  <li key={offer.invitation_id}>
                    <button
                      type="button"
                      className="m-row"
                      data-tone="warning"
                      data-offer={offer.invitation_id}
                      style={{ minBlockSize: target }}
                      onClick={() => {
                        setOpen(offer.invitation_id)
                      }}
                    >
                      <span className="m-row-head">
                        <span className="m-row-kind">Invitation</span>
                        <span className="m-row-where">{hostWords(host)}</span>
                      </span>
                      <span className="m-row-title">{offerTitle(host, offer)}</span>
                      <span className="m-row-detail">
                        {offerRole(offer)} · {offerEnds(offer, view.readAtMs)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}

            {view.hidden.length > 0 ? (
              <button
                type="button"
                className="m-row sw-quiet"
                data-tone="muted"
                data-testid="hidden-offers"
                style={{ minBlockSize: target }}
                onClick={() => {
                  book.showPutOff()
                }}
              >
                <span className="m-row-title">
                  {view.hidden.length === 1
                    ? '1 hidden invitation'
                    : `${String(view.hidden.length)} hidden invitations`}
                </span>
                <span className="sw-quiet-action">Show</span>
              </button>
            ) : null}

            {attempts.map((attempt) => (
              <div
                key={attempt.action_id}
                className="sw-attempt"
                role="status"
                tabIndex={-1}
                data-testid="accept-attempt"
                data-attempt={attempt.action_id}
                data-phase={attempt.phase}
                data-outcome={attempt.outcome ?? undefined}
              >
                <p>{attemptWords(attempt, view.readAtMs)}</p>
                {attempt.refusal !== null ? <p>The host said: {visibly(attempt.refusal)}</p> : null}
                <div className="sw-actions">
                  {attempt.phase !== 'closed' ? (
                    <>
                      <Button
                        data-testid="attempt-ask"
                        onClick={() => {
                          askHost(attempt)
                        }}
                      >
                        Ask the host
                      </Button>
                      <Button
                        data-testid="attempt-hide"
                        onClick={() => {
                          setHidden(attempt, true)
                        }}
                      >
                        Hide
                      </Button>
                    </>
                  ) : (
                    <Button
                      data-testid="attempt-remove"
                      onClick={() => {
                        remove(attempt)
                      }}
                    >
                      Remove
                    </Button>
                  )}
                </div>
              </div>
            ))}

            {putOff.length > 0 ? (
              <div className="m-row sw-quiet" data-tone="muted" data-testid="hidden-attempts">
                <span className="m-row-title">
                  {putOff.length === 1
                    ? '1 hidden attempt can still happen'
                    : `${String(putOff.length)} hidden attempts can still happen`}
                </span>
                {putOff.map((attempt) => (
                  <Button
                    key={attempt.action_id}
                    data-testid="attempt-show"
                    onClick={() => {
                      setHidden(attempt, false)
                    }}
                  >
                    Show {nameWords(attempt.label)}
                  </Button>
                ))}
              </div>
            ) : null}
          </section>
        ) : null}
      </div>

      <Sheet
        open={opened !== null}
        title={opened === null ? '' : offerTitle(host, opened)}
        onClose={() => {
        closeLabel="Close invitation"
          setOpen(null)
        }}
        footer={
          opened === null ? null : (
            <div className="sw-footer">
              <CommitButton
                tone="primary"
                data-testid="accept-offer"
                disabled={accepting !== null || unsettled !== null}
                onCommit={() => {
                  accept(opened)
                }}
              >
                {accepting === opened.invitation_id ? 'Accepting…' : 'Accept'}
              </CommitButton>
              <Button
                data-testid="not-now"
                disabled={accepting !== null}
                onClick={() => {
                  notNow(opened)
                }}
              >
                Not now
              </Button>
            </div>
          )
        }
      >
        {opened === null ? null : (
          <div className="sw-card" data-testid="offer-card">
            <div>
              <h3>You can</h3>
              <ul>
                {youCan(opened.actions, opened.includes_live_screen).map((words) => (
                  <li key={words}>{words}</li>
                ))}
              </ul>
            </div>
            {opened.notices.length > 0 ? (
              <div>
                <h3>This lets you</h3>
                <ul>
                  {thisLetsYou(host, opened.notices).map((words) => (
                    <li key={words}>{words}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <div>
              <h3>Shows</h3>
              <ul>
                {showsLines(opened, view.readAtMs).map((words) => (
                  <li key={words}>{words}</li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Ends</h3>
              <ul>
                <li>{endsLine(opened, view.readAtMs)}</li>
              </ul>
            </div>
            {unsettled !== null ? (
              <p data-testid="offer-unsettled">
                An earlier try at accepting this is not settled yet. Ask the host about it in the list
                behind this card.
              </p>
            ) : null}
          </div>
        )}
      </Sheet>
    </>
  )
}

/** Whether an acceptance is over and was told: it was accepted, and its record is about to go. */
function isDone(attempt: AttemptView): boolean {
  return attempt.phase === 'closed' && attempt.outcome === 'happened'
}
