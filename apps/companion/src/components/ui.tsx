/**
 * The components every screen is built from.
 *
 * Two rules run through them. A pressable element gives feedback on press and commits on a
 * completed action: pointer-down highlights, pointer-up over the control commits, and a press that
 * slides away is cancelled. And nothing here decides its own colour: the tokens do, so light, dark
 * and high contrast are one implementation.
 */

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type HTMLAttributes,
  type ReactNode
} from 'react'

import markLight from '../assets/kala-mark.svg'
import markDark from '../assets/kala-mark-dark.svg'
import { applyMode, storedMode, THEME_KEY, type ColourMode } from '../theme-init'
import {
  animateSpring,
  DRAG_THRESHOLD,
  prefersReducedMotion,
  rubberband,
  shouldDismiss,
  VelocityTracker,
  type Animation
} from '../motion'

/* ---- Brand ----------------------------------------------------------------------------------- */

/** The product mark and wordmark. */
export function Brand(): ReactNode {
  return (
    <div className="brand">
      <img className="mark-light" src={markLight} alt="" width={31} height={31} />
      <img className="mark-dark" src={markDark} alt="" width={31} height={31} />
      <span className="brand-divider" aria-hidden="true" />
      <span className="brand-word">
        Kala<span>Reach</span>
      </span>
    </div>
  )
}

/* ---- Buttons --------------------------------------------------------------------------------- */

type ButtonTone = 'default' | 'primary' | 'sage' | 'danger' | 'quiet'

interface ButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> {
  readonly tone?: ButtonTone
  readonly children: ReactNode
}

/** A button. */
export function Button({ tone = 'default', children, ...rest }: ButtonProps): ReactNode {
  const toneClass = tone === 'default' ? '' : ` btn-${tone}`
  return (
    <button type="button" className={`btn${toneClass}`} {...rest}>
      {children}
    </button>
  )
}

/** A button that is only an icon, and therefore needs a label. */
export function IconButton({
  label,
  children,
  ...rest
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className'> & {
  readonly label: string
  readonly children: ReactNode
}): ReactNode {
  return (
    <button type="button" className="icon-btn" aria-label={label} title={label} {...rest}>
      {children}
    </button>
  )
}

/**
 * A control that commits only on a deliberate, completed action.
 *
 * Approving a command is the one place in this product where a mistaken press has a consequence
 * the person cannot take back, so this is not an ordinary button. It highlights on pointer-down,
 * which is the feedback; it commits on pointer-up while the same pointer is still inside it, which
 * is the decision. Dragging off it cancels, and so does losing focus or losing the pointer.
 *
 * Only the primary button arms it: a right-click is a request for a menu, not a decision. From the
 * keyboard it commits on the key-up of a key it saw go down, so a held key repeats nothing and a
 * key-up that arrives from somewhere else decides nothing.
 *
 * A `click` that arrives without any of that is an activation from assistive technology, which
 * synthesises no pointer or key events. That is a deliberate action by a person, so it commits,
 * once, and the pointer path suppresses its own click so nothing commits twice.
 */
export function CommitButton({
  onCommit,
  tone = 'default',
  children,
  disabled,
  ...rest
}: Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'className' | 'onClick'> & {
  readonly onCommit: () => void
  readonly tone?: ButtonTone
  readonly children: ReactNode
}): ReactNode {
  const [pressed, setPressed] = useState(false)
  const pointer = useRef<number | null>(null)
  const key = useRef<string | null>(null)
  const committedHere = useRef(false)

  const cancel = useCallback(() => {
    pointer.current = null
    key.current = null
    setPressed(false)
  }, [])

  const inside = (event: { clientX: number; clientY: number }, element: HTMLElement) => {
    const box = element.getBoundingClientRect()
    return (
      event.clientX >= box.left &&
      event.clientX <= box.right &&
      event.clientY >= box.top &&
      event.clientY <= box.bottom
    )
  }

  return (
    <button
      type="button"
      className={`btn${tone === 'default' ? '' : ` btn-${tone}`}`}
      data-pressed={pressed ? 'true' : undefined}
      disabled={disabled}
      onPointerDown={(event) => {
        // The primary button only. `button` is 0 for the primary one on every pointer type.
        if (disabled || event.button !== 0 || pointer.current !== null) return
        event.currentTarget.setPointerCapture(event.pointerId)
        pointer.current = event.pointerId
        setPressed(true)
      }}
      onPointerMove={(event) => {
        if (pointer.current !== event.pointerId) return
        setPressed(inside(event, event.currentTarget))
      }}
      onPointerUp={(event) => {
        if (pointer.current !== event.pointerId) return
        const within = inside(event, event.currentTarget)
        cancel()
        if (within && !disabled) {
          committedHere.current = true
          onCommit()
        }
      }}
      onPointerCancel={cancel}
      onLostPointerCapture={cancel}
      onBlur={cancel}
      onKeyDown={(event) => {
        if (disabled) return
        if (event.key === ' ' || event.key === 'Enter') {
          event.preventDefault()
          if (event.repeat) return
          key.current = event.key
          setPressed(true)
        }
      }}
      onKeyUp={(event) => {
        if (event.key !== ' ' && event.key !== 'Enter') return
        event.preventDefault()
        const armed = key.current === event.key
        cancel()
        if (armed && !disabled) {
          committedHere.current = true
          onCommit()
        }
      }}
      onClick={() => {
        // The pointer and keyboard paths have already decided by the time their click arrives.
        if (committedHere.current) {
          committedHere.current = false
          return
        }
        if (!disabled) onCommit()
      }}
      {...rest}
    >
      {children}
    </button>
  )
}

/* ---- Small pieces ---------------------------------------------------------------------------- */

/** A status chip. */
export function Badge({
  tone = 'neutral',
  children,
  ...rest
}: {
  readonly tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
  readonly children: ReactNode
} & Omit<HTMLAttributes<HTMLSpanElement>, 'className'>): ReactNode {
  return (
    <span className={`badge ${tone}`} {...rest}>
      {children}
    </span>
  )
}

/** A card. */
export function Card({
  children,
  ...rest
}: { readonly children: ReactNode } & Record<string, unknown>): ReactNode {
  return (
    <section className="card" {...rest}>
      {children}
    </section>
  )
}

/** A two-state switch. */
export function Switch({
  checked,
  label,
  onChange
}: {
  readonly checked: boolean
  readonly label: string
  readonly onChange: (next: boolean) => void
}): ReactNode {
  return (
    <button
      type="button"
      role="switch"
      className="switch-control"
      aria-checked={checked}
      aria-label={label}
      onClick={() => {
        onChange(!checked)
      }}
    >
      <span className="switch-thumb" />
    </button>
  )
}

/** A set of mutually exclusive choices. */
export function Segmented<T extends string>({
  value,
  options,
  label,
  onChange
}: {
  readonly value: T
  readonly options: readonly { readonly value: T; readonly label: string }[]
  readonly label: string
  readonly onChange: (next: T) => void
}): ReactNode {
  return (
    <div className="segmented" role="tablist" aria-label={label}>
      {options.map((option, index) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={option.value === value}
          tabIndex={option.value === value ? 0 : -1}
          onKeyDown={(event) => {
            const wrapped = (position: number) =>
              (position + options.length) % options.length
            const target =
              event.key === 'ArrowRight' || event.key === 'ArrowDown'
                ? wrapped(index + 1)
                : event.key === 'ArrowLeft' || event.key === 'ArrowUp'
                  ? wrapped(index - 1)
                  : event.key === 'Home'
                    ? 0
                    : event.key === 'End'
                      ? options.length - 1
                      : -1
            if (target < 0) return
            event.preventDefault()
            const next = options[target]
            if (!next) return
            onChange(next.value)
            // Focus follows the selection, or a second arrow press would start from the tab that
            // is no longer selected and the control could not be traversed.
            const list = event.currentTarget.parentElement
            const buttons = list?.querySelectorAll<HTMLButtonElement>('[role="tab"]')
            buttons?.[target]?.focus()
          }}
          onClick={() => {
            onChange(option.value)
          }}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

/** A banner that says what is happening, without claiming more than it knows. */
export function Banner({
  tone,
  title,
  detail,
  action
}: {
  readonly tone: 'warning' | 'accent' | 'danger'
  readonly title: string
  readonly detail: string
  readonly action?: ReactNode
}): ReactNode {
  return (
    <div className={`banner ${tone}`} role="status">
      <div className="spacer">
        <strong>{title}</strong>
        {detail}
      </div>
      {action}
    </div>
  )
}

/* ---- The toast ------------------------------------------------------------------------------- */

/** One passing message. */
export interface ToastMessage {
  readonly id: number
  readonly text: string
  readonly tone: 'success' | 'danger' | 'pending'
}

/** Shows the newest message, and takes it away. */
export function Toast({
  message,
  onDismiss
}: {
  readonly message: ToastMessage | null
  readonly onDismiss: () => void
}): ReactNode {
  useEffect(() => {
    if (!message) return
    const handle = setTimeout(onDismiss, 4200)
    return () => {
      clearTimeout(handle)
    }
  }, [message, onDismiss])

  if (!message) return null
  return (
    <div className="toast" role="status" aria-live="polite" key={message.id}>
      <span
        className={
          message.tone === 'danger'
            ? 'danger-text'
            : message.tone === 'pending'
              ? 'faint'
              : 'success-text'
        }
        aria-hidden="true"
      >
        {message.tone === 'danger' ? '!' : message.tone === 'pending' ? '…' : '✓'}
      </span>
      <span>{message.text}</span>
      <IconButton label="Dismiss" onClick={onDismiss}>
        ×
      </IconButton>
    </div>
  )
}

/* ---- The sheet ------------------------------------------------------------------------------- */

/** How long the reduced-motion cross-fade lasts. */
const REDUCED_MOTION_FADE_MS = 120

/**
 * Where a sheet's own motion has got to, published as `data-presentation`.
 *
 * `arriving` while the surface is coming in or on its way back to where it sits, `here` once it has
 * come to rest over the screen, and `leaving` from the moment it is dismissed until it is taken
 * away. This is what the surface is doing, not what was asked of it: `data-open` says whether it
 * has been dismissed, and the two differ for as long as the motion lasts. A drag takes the surface
 * off its rest, so it reads `arriving` again from the moment a finger lands on it until it has
 * settled back.
 *
 * It is here because the surface arrives and leaves over a number of animation frames, and how
 * long a frame lasts is the machine's answer rather than this application's. Anything that has to
 * know whether the surface has settled — a screen reader announcement, a measurement, a browser
 * test taking a picture of what a person sees — would otherwise have to read the transform back
 * and guess.
 */
export type SheetPresentation = 'arriving' | 'here' | 'leaving'

/**
 * A surface that opens over the screen it belongs to, and can be dragged away.
 *
 * It arrives from the bottom and leaves to the bottom, so the gesture that dismisses it is the
 * reverse of the motion that brought it. While a finger is on it the transform is set directly from
 * the pointer; on release a critically damped spring takes over with the velocity the finger had,
 * and it can be caught again mid-flight.
 *
 * With reduced motion it does not travel at all: it cross-fades, and the drag still dismisses it.
 */
export function Sheet({
  open,
  title,
  description,
  onClose,
  children,
  footer
}: {
  readonly open: boolean
  readonly title: string
  readonly description?: string
  readonly onClose: () => void
  readonly children: ReactNode
  readonly footer?: ReactNode
}): ReactNode {
  const sheetRef = useRef<HTMLDivElement | null>(null)
  const scrimRef = useRef<HTMLDivElement | null>(null)
  const animation = useRef<Animation | null>(null)
  const tracker = useRef(new VelocityTracker())
  const dragStart = useRef<{ pointer: number; offset: number } | null>(null)
  // Where the surface is now, and how fast it is moving. Every animation starts from these, so a
  // gesture caught mid-flight continues from what is on the screen rather than from where the last
  // animation thought it was.
  const presented = useRef({ offset: 0, velocity: 0 })
  const restoreFocus = useRef<HTMLElement | null>(null)
  const titleId = useId()
  const [mounted, setMounted] = useState(open)
  // Whether the motion this surface is in the middle of has finished. Each run of the effect below
  // is one piece of motion and clears it; whatever ends that motion sets it again.
  const [atRest, setAtRest] = useState(false)
  const reduced = prefersReducedMotion()

  // Opening is a render-phase adjustment rather than an effect: the surface has to exist in the
  // same commit that starts its motion, or its first frame is missing.
  if (open && !mounted) setMounted(true)

  const place = useCallback((offset: number) => {
    const sheet = sheetRef.current
    if (!sheet) return
    const height = sheet.offsetHeight || 1
    presented.current.offset = offset
    sheet.style.transform = `translate3d(0, ${offset}px, 0)`
    if (scrimRef.current) {
      scrimRef.current.style.setProperty(
        '--scrim-opacity',
        String(Math.max(0, 1 - offset / height))
      )
    }
  }, [])

  const close = useCallback(() => {
    onClose()
  }, [onClose])

  useEffect(() => {
    if (!mounted) {
      // No surface, so no grab: a finger that was on one when it was taken away never gets its
      // release, and a grab that outlived its surface must not decide anything about the next one.
      dragStart.current = null
      return
    }
    const sheet = sheetRef.current
    if (!sheet) return
    const height = sheet.offsetHeight || 1
    setAtRest(false)

    if (reduced) {
      // No travel: the surface cross-fades where it is, and is taken away once the fade is over.
      place(0)
      sheet.style.opacity = open ? '1' : '0'
      const handle = setTimeout(() => {
        // A finger that landed during the fade owns the surface now, and the release will say
        // when it is at rest again. This timer is not what stops a drag.
        if (open) {
          if (dragStart.current === null) setAtRest(true)
        } else setMounted(false)
      }, REDUCED_MOTION_FADE_MS)
      return () => {
        clearTimeout(handle)
      }
    }

    // Always from the value on screen, with the velocity it already has: a sheet caught while
    // closing reverses from where it is rather than jumping back to where it started.
    animation.current?.stop()
    const from = animation.current ? presented.current.offset : open ? height : 0
    const velocity = animation.current ? presented.current.velocity : 0
    presented.current.offset = from
    animation.current = animateSpring({
      from,
      velocity,
      to: open ? 0 : height,
      onFrame: (value) => {
        presented.current.velocity = (value - presented.current.offset) * 60
        place(value)
      },
      onDone: () => {
        presented.current.velocity = 0
        if (open) setAtRest(true)
        else setMounted(false)
      }
    })
    return () => {
      animation.current?.stop()
    }
  }, [open, mounted, place, reduced])

  // A modal surface takes the focus and keeps it. Without this a keyboard is still operating the
  // session behind a consequence the person has not answered.
  useEffect(() => {
    if (!mounted) return
    const sheet = sheetRef.current
    if (!sheet) return
    restoreFocus.current = document.activeElement as HTMLElement | null
    const focusable = () =>
      Array.from(
        sheet.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
      )
    focusable()[0]?.focus()

    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return
      const targets = focusable()
      if (targets.length === 0) return
      const first = targets[0]
      const last = targets[targets.length - 1]
      if (!first || !last) return
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      restoreFocus.current?.focus()
    }
  }, [mounted])

  useEffect(() => {
    if (!mounted) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close()
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
    }
  }, [mounted, close])

  if (!mounted) return null

  const presentation: SheetPresentation = !open ? 'leaving' : atRest ? 'here' : 'arriving'

  return (
    <>
      <div
        ref={scrimRef}
        className="scrim"
        onClick={close}
        role="presentation"
        data-testid="sheet-scrim"
      />
      <div
        ref={sheetRef}
        className="sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="sheet"
        data-open={open ? 'true' : 'false'}
        data-presentation={presentation}
      >
        <div
          className="sheet-grip"
          data-testid="sheet-grip"
          role="presentation"
          onPointerDown={(event) => {
            const sheet = sheetRef.current
            if (!sheet || event.button !== 0) return
            event.currentTarget.setPointerCapture(event.pointerId)
            animation.current?.stop()
            // The surface is under a finger, so it is not where it was left and is not at rest.
            // Stopping the animation above also takes away whatever would have said so later.
            setAtRest(false)
            const currentOffset = animation.current?.value ?? 0
            // The grab offset is respected: the surface does not jump to centre under the finger.
            dragStart.current = { pointer: event.clientY, offset: currentOffset }
            tracker.current.reset()
            tracker.current.add(event.clientY, event.timeStamp)
          }}
          onPointerMove={(event) => {
            const start = dragStart.current
            const sheet = sheetRef.current
            if (!start || !sheet) return
            tracker.current.add(event.clientY, event.timeStamp)
            const height = sheet.offsetHeight || 1
            const raw = start.offset + (event.clientY - start.pointer)
            // Upward is past the boundary: it resists rather than stopping. With reduced motion
            // the surface does not travel at all, and the gesture still decides.
            if (!reduced) place(raw < 0 ? -rubberband(-raw, height) : raw)
          }}
          onPointerUp={(event) => {
            const start = dragStart.current
            const sheet = sheetRef.current
            dragStart.current = null
            if (!start || !sheet) return
            tracker.current.add(event.clientY, event.timeStamp)
            const height = sheet.offsetHeight || 1
            const offset = Math.max(0, start.offset + (event.clientY - start.pointer))
            const velocity = tracker.current.velocity()
            // Recorded before either branch: a dismissal that discarded the release velocity would
            // stop dead where the finger left, which is the one thing a thrown surface must not do.
            presented.current.offset = offset
            presented.current.velocity = velocity
            if (Math.abs(offset - start.offset) < DRAG_THRESHOLD && velocity === 0) {
              place(start.offset)
              setAtRest(start.offset === 0)
              return
            }
            if (shouldDismiss(offset, velocity, height)) {
              close()
              return
            }
            if (reduced) {
              place(0)
              setAtRest(true)
              return
            }
            animation.current?.stop()
            presented.current.offset = offset
            presented.current.velocity = velocity
            animation.current = animateSpring({
              from: offset,
              velocity,
              to: 0,
              onFrame: (value) => {
                presented.current.velocity = (value - presented.current.offset) * 60
                place(value)
              },
              onDone: () => {
                presented.current.velocity = 0
                setAtRest(true)
              }
            })
          }}
        />
        <header className="dialog-header">
          <div>
            <h2 id={titleId}>{title}</h2>
            {description ? <p className="muted">{description}</p> : null}
          </div>
          <IconButton label="Close settings" onClick={close}>
            ×
          </IconButton>
        </header>
        <div className="dialog-body">{children}</div>
        {footer ? <footer className="dialog-footer">{footer}</footer> : null}
      </div>
    </>
  )
}

/* ---- Appearance ------------------------------------------------------------------------------ */

/** Light, dark or the device's own setting. */
export function ThemeChooser(): ReactNode {
  const [mode, setMode] = useState<ColourMode>(() => storedMode())

  const choose = (next: ColourMode) => {
    setMode(next)
    applyMode(next)
    try {
      localStorage.setItem(THEME_KEY, next)
    } catch {
      // A private window keeps the choice for this page and no longer. The controls still work.
    }
  }

  return (
    <fieldset className="theme-options">
      <legend className="visually-hidden">Appearance</legend>
      {(['light', 'dark', 'system'] as const).map((option) => (
        <label key={option} className="theme-option">
          <input
            type="radio"
            name="appearance"
            value={option}
            checked={mode === option}
            onChange={() => {
              choose(option)
            }}
          />
          <span className={`theme-preview ${option}`} aria-hidden="true">
            <span className="mini-sidebar">
              <i />
              <i />
            </span>
            <span className="mini-content">
              <i />
              <b />
            </span>
          </span>
          <span className="theme-caption">
            {option === 'light' ? 'Light' : option === 'dark' ? 'Dark' : 'System'}
            <span className="theme-check" aria-hidden="true" />
          </span>
        </label>
      ))}
    </fieldset>
  )
}
