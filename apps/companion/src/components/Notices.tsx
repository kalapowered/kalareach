import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

// The text the installers carry as THIRD-PARTY-NOTICES.txt. The build emits it as a file of the
// interface's own bundle, which every installer and store bundle embeds, and it is read only when a
// person opens it.
import noticeUrl from '../../../../docs/releases/companion-third-party-notices.txt?url'

import {
  NOTICES_FAILED,
  NOTICES_HIDE,
  NOTICES_NOTE,
  NOTICES_READING,
  NOTICES_SHOW,
  NOTICES_TITLE
} from '../model/notices'
import { Button, Card } from './ui'

type Reading =
  | { readonly state: 'unread' }
  | { readonly state: 'reading' }
  | { readonly state: 'read'; readonly text: string }
  | { readonly state: 'failed' }

/**
 * The third-party notices row: a button that shows the text in a region that scrolls and takes
 * focus, so the keyboard reaches it. Nothing moves when it opens, so reduced motion changes nothing
 * here. A text that was read stays, and one that could not be read is asked for again the next time
 * the row is opened.
 */
export function Notices({ target }: { readonly target: number }): ReactNode {
  const [open, setOpen] = useState(false)
  const [reading, setReading] = useState<Reading>({ state: 'unread' })
  const regionId = useId()
  const here = useRef(true)

  useEffect(() => {
    here.current = true
    return () => {
      here.current = false
    }
  }, [])

  const toggle = (): void => {
    if (open) {
      setOpen(false)
      return
    }
    setOpen(true)
    if (reading.state === 'read' || reading.state === 'reading') return
    setReading({ state: 'reading' })
    fetch(noticeUrl)
      .then((response) => {
        if (!response.ok) throw new Error(`the notices answered ${response.status}`)
        return response.text()
      })
      .then((text) => {
        if (here.current) setReading({ state: 'read', text })
      })
      .catch(() => {
        if (here.current) setReading({ state: 'failed' })
      })
  }

  const message =
    open && reading.state === 'reading'
      ? NOTICES_READING
      : open && reading.state === 'failed'
        ? NOTICES_FAILED
        : ''

  return (
    <>
      <p className="account-section-title">{NOTICES_TITLE}</p>
      <Card data-testid="third-party-notices">
        <div className="account-actions">
          <p className="account-note">{NOTICES_NOTE}</p>
          <Button
            aria-expanded={open}
            aria-controls={regionId}
            style={{ minBlockSize: target }}
            onClick={toggle}
          >
            {open ? NOTICES_HIDE : NOTICES_SHOW}
          </Button>
        </div>
        <div id={regionId} hidden={!open}>
          <p className="account-note" role="status">
            {message}
          </p>
          {open && reading.state === 'read' ? (
            <pre className="account-notices" role="region" aria-label={NOTICES_TITLE} tabIndex={0}>
              {reading.text}
            </pre>
          ) : null}
        </div>
      </Card>
    </>
  )
}
