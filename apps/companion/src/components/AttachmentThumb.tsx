/**
 * The small picture of an attached image, when the host made one.
 *
 * A completed upload of an image carries a bounded PNG thumbnail in its handle. It is shown beside
 * the file's name as the picture itself and says nothing the name does not, so it is decorative to
 * a screen reader. A handle kept on the device carries none (a record is too small to hold one), and
 * a file that is not an image has none: the chip is then the name alone.
 */

import type { ReactNode } from 'react'

import type { DraftAttachment } from '../model/drafts'

/** The thumbnail as a `data:` address, or null when the handle carries none. */
function thumbnailAddress(attachment: DraftAttachment): string | null {
  const thumbnail = attachment.handle?.preview?.thumbnail
  if (thumbnail === undefined || thumbnail === '') return null
  // The protocol writes bytes as unpadded base64url; an address wants base64.
  const standard = thumbnail.replaceAll('-', '+').replaceAll('_', '/')
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4)
  return `data:image/png;base64,${padded}`
}

/** The picture, or nothing. */
export function AttachmentThumb({ attachment }: { readonly attachment: DraftAttachment }): ReactNode {
  const address = thumbnailAddress(attachment)
  if (address === null) return null
  return <img className="attachment-thumb" data-testid="attachment-thumb" alt="" src={address} />
}
