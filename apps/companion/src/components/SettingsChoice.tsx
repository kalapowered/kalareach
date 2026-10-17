/**
 * The choice between two versions of the settings, when two devices changed the same setting.
 *
 * Nothing is replaced until the person has chosen, and nothing is chosen for them: no version is
 * selected to begin with, none is placed first for being later, and the times shown are shown for
 * recognition and decide nothing. This device's own comes first only because it is the one the
 * person is holding. The colour mode is the one setting there is, so each version is drawn as the
 * appearance it holds, the way the chooser draws it, and a person recognises one by looking.
 *
 * The control is the card's own: it opens in place under the card's status line and closes where it
 * opened, so the person is never taken anywhere and can go back to what they were doing. A choice
 * is a press of the version and a press of the button; the first is undone by pressing another and
 * the second is what is sent. Nothing moves of its own: the options appear with the card.
 */

import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

import type { SettingsChoice, SettingsKeep } from '../host/port'
import { colourModeName, keepables, SETTINGS_CHOICE_HELP, type Keepable } from '../model/settings'
import { Button } from './ui'

/** The versions to choose between, and the control that records the choice. */
export function SettingsChoiceForm({
  choice,
  busy,
  target,
  onKeep,
  onCancel
}: {
  readonly choice: SettingsChoice
  readonly busy: boolean
  /** The least size of a control on this surface. */
  readonly target: number
  readonly onKeep: (keep: SettingsKeep) => void
  readonly onCancel: () => void
}): ReactNode {
  const headingId = useId()
  const group = useId()
  const heading = useRef<HTMLHeadingElement | null>(null)
  // The control opens where the person pressed to open it, and focus goes to what it says first.
  useEffect(() => {
    heading.current?.focus()
  }, [])
  const [picked, setPicked] = useState<string | null>(null)
  const versions = keepables(choice)
  const kept = versions.find((version) => version.id === picked) ?? null

  return (
    <section className="choice" aria-labelledby={headingId} data-testid="settings-choice">
      <h3 id={headingId} className="choice-title" tabIndex={-1} ref={heading}>
        Which appearance do you want to keep?
      </h3>
      <p className="muted">{SETTINGS_CHOICE_HELP}</p>
      <fieldset className="choice-options">
        <legend className="visually-hidden">Appearance to keep</legend>
        {versions.map((version) => (
          <Version
            key={version.id}
            version={version}
            group={group}
            checked={picked === version.id}
            onPick={() => {
              setPicked(version.id)
            }}
          />
        ))}
      </fieldset>
      <div className="row choice-actions">
        <Button
          tone="primary"
          data-testid="settings-choice-keep"
          data-wraps
          disabled={busy || kept === null || kept.mode === null}
          style={{ minBlockSize: target }}
          onClick={() => {
            if (kept !== null) onKeep(kept.keep)
          }}
        >
          {kept?.mode == null ? 'Keep this one' : `Keep ${colourModeName(kept.mode)}`}
        </Button>
        <Button
          data-testid="settings-choice-cancel"
          data-wraps
          disabled={busy}
          style={{ minBlockSize: target }}
          onClick={onCancel}
        >
          Not now
        </Button>
      </div>
    </section>
  )
}

function Version({
  version,
  group,
  checked,
  onPick
}: {
  readonly version: Keepable
  readonly group: string
  readonly checked: boolean
  readonly onPick: () => void
}): ReactNode {
  const readable = version.mode !== null
  return (
    <label className="theme-option choice-option" data-readable={readable ? 'true' : 'false'}>
      <input
        type="radio"
        name={group}
        value={version.id}
        checked={checked}
        disabled={!readable}
        onChange={onPick}
      />
      <span className={`theme-preview ${version.mode ?? 'system'}`} aria-hidden="true">
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
        <span className="choice-words">
          <strong>{version.mode === null ? 'A setting this version cannot show' : colourModeName(version.mode)}</strong>
          <small>
            {version.whose}
            {version.recorded === '' ? '' : `, ${version.recorded}`}
          </small>
        </span>
        <span className="theme-check" aria-hidden="true" />
      </span>
    </label>
  )
}
