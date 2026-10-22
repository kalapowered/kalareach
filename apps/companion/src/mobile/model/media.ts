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

import type { CameraAccess } from '../../host/port'

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

/** What the picker says when the camera is not allowed, and how to allow it. */
export const CAMERA_NOT_ALLOWED =
  'KalaReach cannot use the camera. Allow it in Settings to take a photo.'

/** What the picker does about the camera, and says. */
export interface CameraOffer {
  /** Whether "Take a photo" is there to press. */
  readonly offered: boolean
  /** What the person is told, or null when there is nothing to tell. */
  readonly notice: string | null
}

/**
 * What the picker offers and says about the camera, from what the system says of it.
 *
 * The WebView asks the system for the camera when the person opens it. Once the system asks no
 * more (the person refused for good, or a policy refuses), that request is refused without a word:
 * the picker closes with no picture and no error, and the person is left with a button that does
 * nothing. So the permission is read before the button is offered, and again when the camera
 * closes with no picture.
 *
 * - Not read yet, or allowed, or the system will ask: the button is offered, and the system asks
 *   when it is pressed.
 * - Refused for good: the button is not offered, since it would do nothing, and the person is told
 *   how to allow it.
 * - The camera closed with no picture while it is not allowed: the person refused it just now, so
 *   they are told the same, and the button stays so that a system that asks again can.
 *
 * `closedEmpty` is true when the camera closed with no picture, and `access` is what the system
 * said after that.
 */
export function cameraOffer(access: CameraAccess | null, closedEmpty: boolean): CameraOffer {
  const refused = access === 'denied' || (closedEmpty && access !== null && access !== 'granted')
  return { offered: access !== 'denied', notice: refused ? CAMERA_NOT_ALLOWED : null }
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
