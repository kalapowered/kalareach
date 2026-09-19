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
 * which is the feedback; it commits on pointer-up while the pointer is still inside it, which is
 * the decision. Dragging off it cancels. From the keyboard it commits on key-up, for the same
 * reason: a held key must not repeat a decision.
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
  const armed = useRef(false)

  const cancel = useCallback(() => {
    armed.current = false
    setPressed(false)
  }, [])

  return (
    <button
      type="button"
      className={`btn${tone === 'default' ? '' : ` btn-${tone}`}`}
      data-pressed={pressed ? 'true' : undefined}
      disabled={disabled}
      onPointerDown={(event) => {
        if (disabled) return
        event.currentTarget.setPointerCapture(event.pointerId)
        armed.current = true
        setPressed(true)
      }}
      onPointerMove={(event) => {
        if (!armed.current) return
        const box = event.currentTarget.getBoundingClientRect()
        const inside =
          event.clientX >= box.left &&
          event.clientX <= box.right &&
          event.clientY >= box.top &&
          event.clientY <= box.bottom
        setPressed(inside)
      }}
      onPointerUp={(event) => {
        if (!armed.current) return
        const box = event.currentTarget.getBoundingClientRect()
        const inside =
          event.clientX >= box.left &&
          event.clientX <= box.right &&
          event.clientY >= box.top &&
          event.clientY <= box.bottom
        cancel()
        if (inside && !disabled) onCommit()
      }}
      onPointerCancel={cancel}
      onPointerLeave={() => {
        setPressed(false)
      }}
      onKeyDown={(event) => {
        if (event.key === ' ' || event.key === 'Enter') {
          event.preventDefault()
          if (!event.repeat) setPressed(true)
        }
      }}
      onKeyUp={(event) => {
        if (event.key === ' ' || event.key === 'Enter') {
          event.preventDefault()
          setPressed(false)
          if (!disabled) onCommit()
        }
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
  children
}: {
  readonly tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'accent'
  readonly children: ReactNode
}): ReactNode {
  return <span className={`badge ${tone}`}>{children}</span>
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
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="tab"
          aria-selected={option.value === value}
          tabIndex={option.value === value ? 0 : -1}
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
  readonly tone: 'success' | 'danger'
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
      <span className={message.tone === 'danger' ? 'danger-text' : 'success-text'} aria-hidden="true">
        {message.tone === 'danger' ? '!' : '✓'}
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
  const titleId = useId()
  const [mounted, setMounted] = useState(open)
  const reduced = prefersReducedMotion()

  // Opening is a render-phase adjustment rather than an effect: the surface has to exist in the
  // same commit that starts its motion, or its first frame is missing.
  if (open && !mounted) setMounted(true)

  const place = useCallback((offset: number) => {
    const sheet = sheetRef.current
    if (!sheet) return
    const height = sheet.offsetHeight || 1
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
    if (!mounted) return
    const sheet = sheetRef.current
    if (!sheet) return
    const height = sheet.offsetHeight || 1

    if (reduced) {
      // No travel: the surface cross-fades where it is, and is taken away once the fade is over.
      place(0)
      sheet.style.opacity = open ? '1' : '0'
      if (open) return
      const handle = setTimeout(() => {
        setMounted(false)
      }, REDUCED_MOTION_FADE_MS)
      return () => {
        clearTimeout(handle)
      }
    }

    // Always from the value on screen: a sheet caught while closing reverses from where it is.
    const current = animation.current?.value ?? (open ? height : 0)
    animation.current?.stop()
    animation.current = animateSpring({
      from: current,
      velocity: 0,
      to: open ? 0 : height,
      onFrame: place,
      onDone: () => {
        if (!open) setMounted(false)
      }
    })
    return () => {
      animation.current?.stop()
    }
  }, [open, mounted, place, reduced])

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
      >
        <div
          className="sheet-grip"
          data-testid="sheet-grip"
          role="presentation"
          onPointerDown={(event) => {
            const sheet = sheetRef.current
            if (!sheet) return
            event.currentTarget.setPointerCapture(event.pointerId)
            animation.current?.stop()
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
            // Upward is past the boundary: it resists rather than stopping.
            place(raw < 0 ? -rubberband(-raw, height) : raw)
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
            if (Math.abs(offset - start.offset) < DRAG_THRESHOLD && velocity === 0) {
              place(start.offset)
              return
            }
            if (shouldDismiss(offset, velocity, height)) {
              close()
              return
            }
            animation.current?.stop()
            animation.current = animateSpring({
              from: offset,
              velocity,
              to: 0,
              onFrame: place
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
