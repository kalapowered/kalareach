/**
 * The shares this phone holds, at the head of the sessions list.
 *
 * Each row is a session someone else shared, and opens it under that share. The list is what
 * `grant.held` says and nothing else: a share is here while the host lists it, and a row for one
 * the host stopped listing stays for the rest of the run, as ended, drawn as what it was and not as
 * anything the host has said about why. A list that could not be read in full changes no row.
 */

import type { ReactNode } from 'react'

import type { HeldView } from '../../model/held-shares'
import {
  STALE_WORDS,
  hostWords,
  sentenceCase,
  sessionOfShare,
  sessionWords,
  shareEnds,
  shareRole
} from '../../model/shared-with-you'
import { minimumTarget, type Surface } from '../platform'
import '../shared.css'

/** Whether there is anything to draw under the heading. */
export function hasShares(view: HeldView): boolean {
  return view.status === 'ready' && (view.shares.length > 0 || view.ended.length > 0)
}

/** The shares held, and the ones that ended, under "Shared with you". */
export function SharedWithYou({
  view,
  surface,
  onOpen
}: {
  readonly view: HeldView
  readonly surface: Surface
  readonly onOpen: (sessionId: string, grantId: string) => void
}): ReactNode {
  const target = minimumTarget(surface)
  if (!hasShares(view)) return null
  const host = hostWords(view.hostName)
  const title = (displayNumber: string): string => `${sentenceCase(sessionWords(displayNumber))} · ${host}`
  return (
    <section className="sw-group" aria-labelledby="shared-heading" data-testid="shared-with-you">
      <h2 className="sw-heading" id="shared-heading">
        Shared with you
      </h2>
      {view.stale ? <p className="sw-stale">{STALE_WORDS}</p> : null}
      <ul className="m-list">
        {view.shares.map((share) => {
          const sessionId = sessionOfShare(share)
          const rows = (
            <>
              <span className="m-row-head">
                <span className="m-row-kind">{shareRole(share)}</span>
              </span>
              <span className="m-row-title">{title(share.display_number)}</span>
              <span className="m-row-detail">{shareEnds(share, view.readAtMs)}</span>
            </>
          )
          return (
            <li key={share.grant.grant_id}>
              {sessionId === null ? (
                <div className="m-row" data-tone="success" style={{ minBlockSize: target }}>
                  {rows}
                </div>
              ) : (
                <button
                  type="button"
                  className="m-row"
                  data-tone="success"
                  data-share={share.grant.grant_id}
                  style={{ minBlockSize: target }}
                  onClick={() => {
                    onOpen(sessionId, share.grant.grant_id)
                  }}
                >
                  {rows}
                </button>
              )}
            </li>
          )
        })}
        {view.ended.map((ended) => (
          <li key={ended.grantId}>
            <div
              className="m-row sw-ended"
              data-tone="muted"
              data-testid="ended-share"
              data-ended={ended.grantId}
              style={{ minBlockSize: target }}
            >
              <span className="m-row-head">
                <span className="m-row-kind">Ended</span>
              </span>
              <span className="m-row-title">{title(ended.displayNumber)}</span>
              <span className="m-row-detail">The host no longer lists this share.</span>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}
