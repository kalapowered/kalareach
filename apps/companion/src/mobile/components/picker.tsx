/**
 * Camera, photo library and files, through the platform's own pickers.
 *
 * Each button opens a file input with the attributes that open one of them. That is not a
 * shortcut: the file input is exactly how a WebView reaches the camera and the photo library on
 * both platforms, so the person gets the platform's picker and the platform's permission prompt
 * rather than a second set built here.
 *
 * The button is the control: it carries the name and the role, and a touch, Enter and Space each
 * open the picker. The input is the platform's way in and not a second control, so `hidden` takes it
 * out of the accessibility tree and the focus order: a one-point input that carried the name would
 * be a control too small to touch, found by a person who goes by what assistive technology lists.
 *
 * The camera is the one source that can be refused by the system, and a WebView says nothing when
 * it is: its picker closes with no picture. The screen reads the camera's permission (`camera`), so
 * the button is offered only where it would do something, and a refusal is told with the way to
 * allow the camera.
 */

import { useEffect, useRef, type ReactNode } from 'react'

import { attributesFor, describeSource, type PickSource, type Picked } from '../model/media'
import type { CameraControl } from '../model/camera'
import { minimumTarget, type Surface } from '../platform'

/** The three sources, in the order a phone offers them. */
const SOURCES: readonly PickSource[] = ['camera', 'library', 'files']

/** The picker row. */
export function AttachmentPicker({
  onPicked,
  surface,
  disabled,
  camera
}: {
  readonly onPicked: (files: readonly { readonly picked: Picked; readonly file: File }[]) => void
  readonly surface: Surface
  readonly disabled?: boolean
  /** What the system says of the camera. Without it the camera is offered and the system asks. */
  readonly camera?: CameraControl
}): ReactNode {
  const target = minimumTarget(surface)
  const offered = camera?.offer.offered ?? true
  const notice = camera?.offer.notice ?? null
  // The button that was pressed may have just gone, since it would do nothing now: the next thing
  // to do is its replacement, so the focus goes there rather than to the page.
  const settings = useRef<HTMLButtonElement | null>(null)
  const refusedJustNow = camera?.refusedJustNow === true
  useEffect(() => {
    if (refusedJustNow) settings.current?.focus()
  }, [refusedJustNow])
  return (
    <>
      <div className="m-composer-actions" role="group" aria-label="Add an attachment">
        {SOURCES.filter((source) => source !== 'camera' || offered).map((source) => (
          <PickerButton
            key={source}
            source={source}
            target={target}
            disabled={disabled}
            camera={source === 'camera' ? camera : undefined}
            onPicked={onPicked}
          />
        ))}
      </div>
      {/* Always drawn, so a screen reader that watches it hears the words when they arrive. */}
      <div className="m-camera-notice" role="status" data-testid="camera-notice">
        {notice === null ? null : (
          <>
            <p className="small">{notice}</p>
            <button
              ref={settings}
              type="button"
              className="btn"
              style={{ minInlineSize: target, minBlockSize: target }}
              data-testid="camera-open-settings"
              onClick={camera?.openSettings}
            >
              Open Settings
            </button>
          </>
        )}
      </div>
    </>
  )
}

function PickerButton({
  source,
  target,
  disabled,
  camera,
  onPicked
}: {
  readonly source: PickSource
  readonly target: number
  readonly disabled?: boolean
  readonly camera?: CameraControl
  readonly onPicked: (files: readonly { readonly picked: Picked; readonly file: File }[]) => void
}): ReactNode {
  const input = useRef<HTMLInputElement | null>(null)
  const attributes = attributesFor(source)
  // A picker closed with no choice is a `cancel` on the input. React does not wire that event for a
  // file input, so it is listened for here.
  const closedEmpty = camera?.closedEmpty
  useEffect(() => {
    const field = input.current
    if (closedEmpty === undefined || field === null) return undefined
    field.addEventListener('cancel', closedEmpty)
    return () => {
      field.removeEventListener('cancel', closedEmpty)
    }
  }, [closedEmpty])
  return (
    <>
      <button
        type="button"
        className="btn"
        style={{ minInlineSize: target, minBlockSize: target, display: 'inline-flex', alignItems: 'center' }}
        data-source={source}
        disabled={disabled}
        onClick={() => {
          input.current?.click()
        }}
      >
        {describeSource(source)}
      </button>
      <input
        ref={input}
        hidden
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
          if (chosen.length > 0) {
            camera?.pictured()
            onPicked(chosen)
          }
        }}
      />
    </>
  )
}
