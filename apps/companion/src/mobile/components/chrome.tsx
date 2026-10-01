/**
 * The two bars, and the glyphs on them.
 *
 * The bars are the only chrome on a phone, so they carry the whole answer to "where am I, where
 * can I go, and how do I get out". The tab bar names its destinations for what is in them rather
 * than for a category, and the title bar says what this screen is and what the host connection is
 * doing.
 */

import { useLayoutEffect, useRef, useState, type ReactNode } from 'react'

import { minimumTarget, showsBackControl, type Surface } from '../platform'

/**
 * The forms the bar takes, from the one that asks the most room to the one that asks the least. In
 * the first the tabs sit side by side, each glyph over its label. With text or letters too wide for
 * that they sit two to a row, each glyph beside its label, and where even that cuts a label, each
 * has a row of its own. The tab order is the same in all three.
 */
const FORMS = ['row', 'pairs', 'column'] as const
type Form = (typeof FORMS)[number]

/** Lays the bar out in `form`: the first is the bar's own, and the others are named on it. */
function layOut(bar: HTMLElement, form: Form): void {
  if (form === 'row') bar.removeAttribute('data-form')
  else bar.setAttribute('data-form', form)
}

/**
 * Whether the bar, as it is laid out now, holds its tabs within its width and every label shows its
 * whole word. A label that is a fraction of a pixel short ends in an ellipsis as one that is far
 * short does, so the word as typeset is held to its box to the fraction. Each label keeps the room
 * of its bold form whether or not its tab is the current one, so which tab that is changes nothing
 * measured here.
 */
function showsEveryLabel(bar: HTMLElement): boolean {
  if (bar.scrollWidth > bar.clientWidth) return false
  for (const label of bar.querySelectorAll<HTMLElement>('.m-tab-label')) {
    if (label.scrollWidth > label.clientWidth) return false
    const word = document.createRange()
    word.selectNodeContents(label)
    // A width in layout units is 1/64 of a pixel: anything over that is a cut. A range has no
    // measure in a test environment that lays nothing out.
    const typeset = typeof word.getBoundingClientRect === 'function' ? word.getBoundingClientRect().width : 0
    if (typeset > label.getBoundingClientRect().width + 0.02) return false
  }
  return true
}

/**
 * The first form in which the bar shows every label as the text is set, or the last, where a label
 * can only end in an ellipsis. Each form is tried in turn and the bar is left as it was found, so
 * the answer never depends on the form the bar is in, and nothing is drawn in between.
 */
function formThatFits(bar: HTMLElement): Form {
  const found = bar.getAttribute('data-form')
  try {
    for (const form of FORMS) {
      layOut(bar, form)
      if (showsEveryLabel(bar)) return form
    }
    return 'column'
  } finally {
    if (found === null) bar.removeAttribute('data-form')
    else bar.setAttribute('data-form', found)
  }
}

/** One destination in the tab bar. */
export interface Destination {
  readonly id: string
  readonly label: string
  readonly glyph: ReactNode
  /** How many things there are to act on, which the badge shows. Zero shows nothing. */
  readonly badge?: number
}

/** The bar along the bottom. */
export function TabBar({
  destinations,
  current,
  onChoose,
  surface
}: {
  readonly destinations: readonly Destination[]
  readonly current: string
  readonly onChoose: (id: string) => void
  readonly surface: Surface
}): ReactNode {
  const target = minimumTarget(surface)
  const bar = useRef<HTMLElement | null>(null)
  // The form the labels need as the text and the screen are now. A label's width does not depend on
  // the form, but what fits does, so each measure starts from the first form.
  const [form, setForm] = useState<Form>('row')
  useLayoutEffect(() => {
    const element = bar.current
    if (element === null) return
    const measure = () => {
      setForm(formThatFits(element))
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    // The bar changes size with the screen and with the text, and each label with the text.
    const observer = new ResizeObserver(measure)
    observer.observe(element)
    for (const label of element.querySelectorAll('.m-tab-label')) observer.observe(label)
    return () => {
      observer.disconnect()
    }
  }, [destinations])
  return (
    <nav className="m-tabbar" aria-label="Sections" ref={bar} data-form={form === 'row' ? undefined : form}>
      {destinations.map((destination) => (
        <button
          key={destination.id}
          type="button"
          className="m-tab"
          style={{ minInlineSize: target, minBlockSize: target }}
          aria-current={destination.id === current ? 'page' : undefined}
          onClick={() => {
            onChoose(destination.id)
          }}
        >
          <span className="m-tab-glyph" aria-hidden="true">
            {destination.glyph}
            {destination.badge && destination.badge > 0 ? (
              <span className="m-tab-badge">{destination.badge > 99 ? '99+' : destination.badge}</span>
            ) : null}
          </span>
          <span className="m-tab-label" data-label={destination.label}>{destination.label}</span>
          {destination.badge && destination.badge > 0 ? (
            <span className="visually-hidden">{`, ${destination.badge} waiting for you`}</span>
          ) : null}
        </button>
      ))}
    </nav>
  )
}

/**
 * The control in the top bar that opens the settings over a session. It is the size a target is on
 * this platform in both dimensions, like the back control beside it.
 */
export function SettingsButton({
  onPress,
  surface
}: {
  readonly onPress: () => void
  readonly surface: Surface
}): ReactNode {
  const target = minimumTarget(surface)
  return (
    <button
      type="button"
      className="icon-btn"
      style={{ minInlineSize: target, minBlockSize: target }}
      aria-label="Settings"
      aria-haspopup="dialog"
      onClick={onPress}
    >
      <SettingsGlyph />
    </button>
  )
}

/** The bar along the top. */
export function TopBar({
  title,
  onBack,
  backLabel,
  action,
  connection,
  surface
}: {
  readonly title: string
  readonly onBack?: () => void
  readonly backLabel?: string
  readonly action?: ReactNode
  /** Where the connection stands, or null before anything has answered which. */
  readonly connection: { readonly connected: boolean; readonly reason: string | null } | null
  readonly surface: Surface
}): ReactNode {
  const target = minimumTarget(surface)
  // Android has a system back gesture and a system affordance; a second one in the bar would be a
  // second way to do the same thing in a place the platform does not put it.
  const back = onBack && showsBackControl(surface)
  return (
    <header className="m-topbar">
      <span className="m-topbar-side">
        {back ? (
          <button
            type="button"
            className="icon-btn"
            style={{ minInlineSize: target, minBlockSize: target }}
            aria-label={backLabel ?? 'Back'}
            onClick={onBack}
          >
            <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">
              <path
                d="M15 5 8 12l7 7"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        ) : null}
      </span>
      <h1>{title}</h1>
      <span className="m-topbar-side">{action}</span>
      <p className="m-connection" title={connection?.reason ?? undefined}>
        {connection === null ? (
          // Before the first answer there is no state to show, so there is no dot to colour.
          <span>Checking the connection…</span>
        ) : (
          <>
            <span
              className={`status-dot${connection.connected ? '' : ' offline'}`}
              aria-hidden="true"
            />
            <span>
              {connection.connected
                ? 'In contact with this host'
                : (connection.reason ?? 'Not in contact')}
            </span>
          </>
        )}
      </p>
    </header>
  )
}

/* ---- Glyphs ---------------------------------------------------------------------------------- */

/** A bell: what is waiting for you. */
export function AttentionGlyph(): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <path
        d="M12 4a5 5 0 0 0-5 5v3.5L5.5 16h13L17 12.5V9a5 5 0 0 0-5-5Zm0 16a2.2 2.2 0 0 0 2.1-1.6H9.9A2.2 2.2 0 0 0 12 20Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/** A terminal prompt: the sessions. */
export function SessionsGlyph(): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <rect
        x="3.5"
        y="5"
        width="17"
        height="14"
        rx="2.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
      />
      <path
        d="m7.5 10 2.5 2-2.5 2M13 14h3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  )
}

/** A machine: the hosts. */
export function HostsGlyph(): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <rect
        x="3.5"
        y="4.5"
        width="17"
        height="6"
        rx="1.8"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
      />
      <rect
        x="3.5"
        y="13.5"
        width="17"
        height="6"
        rx="1.8"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
      />
      <path d="M7 7.5h.01M7 16.5h.01" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
    </svg>
  )
}

/** Two sliders: the settings. */
export function SettingsGlyph(): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">
      <path
        d="M4 8h8.5M17.5 8H20M4 16h2.5M11.5 16H20"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
      <circle cx="15" cy="8" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <circle cx="9" cy="16" r="2.5" fill="none" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  )
}

/** A person: the account. */
export function AccountGlyph(): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" focusable="false">
      <circle cx="12" cy="9" r="3.4" fill="none" stroke="currentColor" strokeWidth="1.6" />
      <path
        d="M5.5 19.5a6.5 6.5 0 0 1 13 0"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  )
}
