/**
 * The control strip of the test harness.
 *
 * A test driving the application on a device cannot reach into the page, so the few things a
 * browser test does through the scripted host's controls are buttons here: contact with the host
 * lost and regained, sends held and released, and what the page keeps of drafts and sends cleared.
 * The harness bundle is built only for tests, so this never ships in a desktop or phone build.
 *
 * It is one small control in the corner until it is opened, and it closes after each choice, so it
 * is out of the way of the screen being tested and out of its measurements.
 */

import { useState, type ReactNode } from 'react'

import type { FakeHostControls, HeldMutations } from './host/fake'
import { DRAFTS_KEY, SUBMISSIONS_KEY } from './mobile/model/store'

/** What tells the next page that a reset was asked for. */
const RESET_KEY = 'kr.harness.reset'

/**
 * Clears what the page keeps of drafts and sends, if the strip asked for it, before the page shows
 * anything.
 *
 * The page writes what it holds as it is unloaded, so clearing at the moment of the reset is undone
 * by the unload that follows it. The reset is asked for there and done here, by the page that
 * starts after, and once: a draft written later is kept.
 */
export function applyPendingReset(storage: Storage, session: Storage): void {
  if (session.getItem(RESET_KEY) === null) return
  session.removeItem(RESET_KEY)
  storage.removeItem(DRAFTS_KEY)
  storage.removeItem(SUBMISSIONS_KEY)
}

/** The strip, for the scripted host `controls` drives. */
export function HarnessStrip({
  controls,
  storage = window.localStorage,
  session = window.sessionStorage,
  reload = () => {
    window.location.reload()
  }
}: {
  readonly controls: FakeHostControls
  readonly storage?: Storage
  readonly session?: Storage
  readonly reload?: () => void
}): ReactNode {
  const [open, setOpen] = useState(false)
  const [held, setHeld] = useState<HeldMutations | null>(null)
  const [submissions, setSubmissions] = useState(controls.submissions)

  const choose = (action: () => void) => () => {
    action()
    setSubmissions(controls.submissions)
    setOpen(false)
  }

  return (
    <div id="kr-strip" style={{ position: 'fixed', insetBlockStart: 0, insetInlineStart: 0, zIndex: 2147483647, opacity: 0.45 }}>
      <button
        type="button"
        aria-label="Controls"
        id="kr-strip-toggle"
        style={{ inlineSize: 22, blockSize: 22, padding: 0 }}
        onClick={() => {
          setSubmissions(controls.submissions)
          setOpen((now) => !now)
        }}
      >
        ·
      </button>
      {open ? (
        <div style={{ display: 'flex', gap: 2, background: 'Canvas', color: 'CanvasText' }}>
          <button type="button" id="kr-strip-lose" onClick={choose(() => { controls.setConnected(false) })}>
            Lose contact
          </button>
          <button type="button" id="kr-strip-restore" onClick={choose(() => { controls.setConnected(true) })}>
            Restore contact
          </button>
          <button
            type="button"
            id="kr-strip-hold"
            disabled={held !== null}
            onClick={choose(() => {
              setHeld(controls.holdMutation())
            })}
          >
            Hold sends
          </button>
          <button
            type="button"
            id="kr-strip-release"
            onClick={choose(() => {
              held?.release()
              setHeld(null)
            })}
          >
            Release sends
          </button>
          <button
            type="button"
            id="kr-strip-reset"
            onClick={choose(() => {
              // Cleared now, so that nothing reads it meanwhile, and again by the next page.
              storage.removeItem(DRAFTS_KEY)
              storage.removeItem(SUBMISSIONS_KEY)
              session.setItem(RESET_KEY, '1')
              reload()
            })}
          >
            Reset
          </button>
          <span id="kr-strip-submissions" data-testid="strip-submissions" aria-label="Sends received">
            {submissions}
          </span>
        </div>
      ) : null}
    </div>
  )
}
