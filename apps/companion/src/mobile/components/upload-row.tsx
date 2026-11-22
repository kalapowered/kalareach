/**
 * One file sent to a host this phone is paired with: its name and size, where it stands in words,
 * how far it is, and the one thing the person can do about it.
 *
 * The status is words first. The bar says how far, and the border says the tone, but neither is
 * the only place the state is: a person who cannot see colour or motion reads the same sentence.
 * The progress bar is a `progressbar` with its value, for a screen reader that asks; the sentence is
 * not a live region, because it changes with every chunk, and what a person must be told (sent,
 * not sent, cancelled) is said once through the screen's own announcement.
 *
 * The control the person presses keeps its place while the file moves on: Cancel is still there,
 * unavailable, while the host answers, and it is Remove once the file has ended, so a press never
 * lands on something that moved, and focus never has to be put back.
 */

import type { ReactNode } from 'react'

import { Button } from '../../components/ui'
import { canCancel, lineOf, type UploadRow } from '../../model/paired-uploads'
import { describeBytes } from '../model/media'
import type { DraftAttachment } from '../../model/drafts'
import { AttachmentThumb } from '../../components/AttachmentThumb'

/** What the person can do to a row. */
export interface UploadActions {
  readonly cancel: () => void
  readonly remove: () => void
  /** Adds a file that was sent in full to the draft. */
  readonly add: () => void
}

/** The label of Remove for a file on the draft: it names the files that go with it. */
export function removeLabel(name: string, others: number): string {
  return others > 0
    ? `Remove ${name} and the other files kept with this draft`
    : `Remove ${name} from this draft`
}

export function UploadRowView({
  row,
  attachment,
  actions,
  target,
  others
}: {
  readonly row: UploadRow
  /** The file on the composer, when the row is one; the ones a restart found have none. */
  readonly attachment: DraftAttachment | null
  readonly actions: UploadActions
  readonly target: number
  /** How many other files are bound to the same draft. */
  readonly others: number
}): ReactNode {
  const line = lineOf(row.phase)
  const phase = row.phase.kind
  const percent = line.progress === null ? null : Math.round(line.progress * 100)
  const cancelling = phase === 'cancelling'
  // A card that was sent before and has no row yet is only being checked: there is no upload of this
  // window's to cancel, and the person may take the card off the composer.
  const stored = phase === 'checking' && attachment?.upload === 'uploaded'
  const cancels = !stored && (canCancel(row.phase) || cancelling)
  const adds = phase === 'kept'
  const settled =
    phase === 'cancelled' || phase === 'refused' || phase === 'bound' || phase === 'adding' || adds || stored
  const sizing = { minBlockSize: target, minInlineSize: target }
  return (
    <div className="m-upload" data-testid="m-upload" data-phase={phase} data-tone={line.tone}>
      <div className="m-upload-head">
        {attachment === null ? null : <AttachmentThumb attachment={attachment} />}
        <span className="m-attachment-name">{row.name}</span>
        <span className="m-row-detail">{describeBytes(row.byteLen)}</span>
      </div>
      <p className="m-upload-line" data-testid="upload-line">
        {line.text}
      </p>
      {row.note === null ? null : (
        <p className="m-upload-line" data-testid="upload-note">
          {row.note}
        </p>
      )}
      {percent === null ? null : (
        <div
          className="m-progress"
          role="progressbar"
          aria-label={`Sending ${row.name}`}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent}
        >
          <span className="m-progress-fill" style={{ transform: `scaleX(${String(line.progress)})` }} />
        </div>
      )}
      <div className="m-upload-actions">
        {cancels ? (
          <Button
            tone="quiet"
            style={sizing}
            aria-label={`Cancel sending ${row.name}`}
            aria-disabled={cancelling ? true : undefined}
            onClick={() => {
              if (!cancelling) actions.cancel()
            }}
          >
            Cancel
          </Button>
        ) : null}
        {adds ? (
          <Button style={sizing} onClick={actions.add}>
            {row.phase.kind === 'kept' && row.phase.words === null ? 'Add to draft' : 'Add again'}
          </Button>
        ) : null}
        {settled && phase !== 'adding' ? (
          <Button
            tone="quiet"
            style={sizing}
            aria-label={phase === 'bound' ? removeLabel(row.name, others) : `Remove ${row.name}`}
            onClick={actions.remove}
          >
            Remove
          </Button>
        ) : null}
      </div>
    </div>
  )
}
