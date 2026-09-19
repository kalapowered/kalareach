/**
 * What the person picked, and whether this device can send it.
 *
 * Camera, photo library and files are all the platform's own pickers, reached through the file
 * input each WebView already maps to them: `capture` opens the camera, an image filter opens the
 * photo library, and no filter opens the file browser. That is the platform's picker, with the
 * platform's permission prompt, rather than a second one built here.
 *
 * What is picked then has to reach the host, and that is where the size rule is. A chunk rides the
 * control connection, whose complete frame is bounded at one mebibyte including its own length
 * prefix, and a chunk carries encoded metadata beside the bytes. So the largest content this lane
 * can carry is a mebibyte less the metadata allowance, and something larger is refused by name
 * here rather than failing on the wire.
 */

/** Maximum size of a complete control frame, from the protocol's limits. */
export const MAX_CONTROL_FRAME_LEN = 1024 * 1024

/** Maximum encoded metadata and framing around one chunk, from the protocol's limits. */
export const MAX_ATTACHMENT_METADATA_LEN = 4 * 1024

/**
 * The largest content this lane can carry.
 *
 * The protocol's chunk length is a mebibyte and the layout is the host's to choose, so a client on
 * this lane cannot ask for smaller chunks. Until an attachment-chunk stream exists, one chunk plus
 * its metadata has to fit one control frame, which bounds the whole transfer at one chunk.
 */
export const MAX_CONTROL_LANE_UPLOAD_LEN = MAX_CONTROL_FRAME_LEN - MAX_ATTACHMENT_METADATA_LEN

/** Where a picked file came from. */
export type PickSource = 'camera' | 'library' | 'files'

/** What the file input is told for each source. */
export interface PickerAttributes {
  readonly accept: string
  /** The rear camera, where the source is the camera. */
  readonly capture?: 'environment'
  /** More than one file at a time, where the source allows it. */
  readonly multiple: boolean
}

/** The attributes that open one of the platform's pickers. */
export function attributesFor(source: PickSource): PickerAttributes {
  switch (source) {
    case 'camera':
      return { accept: 'image/*', capture: 'environment', multiple: false }
    case 'library':
      return { accept: 'image/*,video/*', multiple: true }
    case 'files':
      return { accept: '*/*', multiple: true }
  }
}

/** One thing the person picked. */
export interface Picked {
  readonly name: string
  readonly mediaType: string
  readonly byteLen: number
  readonly source: PickSource
}

/** Whether a picked file can be sent, and why not when it cannot. */
export type Admission =
  | { readonly admitted: true; readonly chunks: 1 }
  | { readonly admitted: false; readonly reason: string; readonly code: 'TOO_LARGE_FOR_LANE' }

/**
 * Decides whether one picked file can go.
 *
 * The refusal names the bound and the size, because "it did not work" leaves a person guessing and
 * "22 MB is more than this connection can carry in one chunk" tells them what to do instead.
 */
export function admit(picked: Picked): Admission {
  if (picked.byteLen <= MAX_CONTROL_LANE_UPLOAD_LEN) return { admitted: true, chunks: 1 }
  return {
    admitted: false,
    code: 'TOO_LARGE_FOR_LANE',
    reason: `${picked.name} is ${describeBytes(picked.byteLen)}. This connection carries an attachment in one chunk of at most ${describeBytes(MAX_CONTROL_LANE_UPLOAD_LEN)}. Send it from a desktop, or send a smaller one.`
  }
}

/** A size a person reads, rather than a number of bytes. */
export function describeBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** What the picker button says it will open, so the person knows before the permission prompt. */
export function describeSource(source: PickSource): string {
  switch (source) {
    case 'camera':
      return 'Take a photo'
    case 'library':
      return 'Photo library'
    case 'files':
      return 'Files'
  }
}
