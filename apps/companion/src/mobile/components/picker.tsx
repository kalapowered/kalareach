/**
 * Camera, photo library and files, through the platform's own pickers.
 *
 * Each button is a label over a file input with the attributes that open one of them. That is not
 * a shortcut: the file input is exactly how a WebView reaches the camera and the photo library on
 * both platforms, so the person gets the platform's picker and the platform's permission prompt
 * rather than a second set built here.
 *
 * The input is hidden from sight and not from assistive technology: the label is the control, and
 * the input carries the accessible name.
 */

import { useId, useRef, type ReactNode } from 'react'

import { attributesFor, describeSource, type PickSource, type Picked } from '../model/media'
import { minimumTarget, type Surface } from '../platform'

/** The three sources, in the order a phone offers them. */
const SOURCES: readonly PickSource[] = ['camera', 'library', 'files']

/** The picker row. */
export function AttachmentPicker({
  onPicked,
  surface,
  disabled
}: {
  readonly onPicked: (files: readonly { readonly picked: Picked; readonly file: File }[]) => void
  readonly surface: Surface
  readonly disabled?: boolean
}): ReactNode {
  const target = minimumTarget(surface)
  return (
    <div className="m-composer-actions" role="group" aria-label="Add an attachment">
      {SOURCES.map((source) => (
        <PickerButton
          key={source}
          source={source}
          target={target}
          disabled={disabled}
          onPicked={onPicked}
        />
      ))}
    </div>
  )
}

function PickerButton({
  source,
  target,
  disabled,
  onPicked
}: {
  readonly source: PickSource
  readonly target: number
  readonly disabled?: boolean
  readonly onPicked: (files: readonly { readonly picked: Picked; readonly file: File }[]) => void
}): ReactNode {
  const id = useId()
  const input = useRef<HTMLInputElement | null>(null)
  const attributes = attributesFor(source)
  return (
    <>
      <label
        className="btn"
        htmlFor={id}
        style={{ minInlineSize: target, minBlockSize: target, display: 'inline-flex', alignItems: 'center' }}
        data-source={source}
      >
        {describeSource(source)}
      </label>
      <input
        ref={input}
        id={id}
        className="visually-hidden"
        type="file"
        accept={attributes.accept}
        capture={attributes.capture}
        multiple={attributes.multiple}
        disabled={disabled}
        onChange={(event) => {
          const chosen = Array.from(event.target.files ?? []).map((file) => ({
            file,
            picked: {
              name: file.name,
              mediaType: file.type || 'application/octet-stream',
              byteLen: file.size,
              source
            }
          }))
          // The same file picked twice in a row must still raise a change, so the input is cleared.
          event.target.value = ''
          if (chosen.length > 0) onPicked(chosen)
        }}
      />
    </>
  )
}
