/**
 * What the person picked, and whether this device can send it.
 *
 * Camera, photo library and files are all the platform's own pickers, reached through the file
 * input each WebView already maps to them: `capture` opens the camera, an image filter opens the
 * photo library, and no filter opens the file browser. That is the platform's picker, with the
 * platform's permission prompt, rather than a second one built here.
 *
 * What is picked then has to reach the host, and that is where the size rule is. The platform gives
 * the page the file, so the page hands its bytes to native code in one piece, and native code takes
 * at most 64 MiB that way (`MAX_HANDED_BYTES` in the application's `transfers.rs`). Past that the
 * file is refused here by name and size, rather than failing at the boundary. A host takes a file of
 * up to 2 GiB, so the phone's hand-over is the smaller bound and the one a person meets. Nothing here
 * limits what a connection carries: the file goes to the host in chunks, over the connection's own
 * transfer lane, and a connection that ends does not end the upload.
 */

import { MAX_HANDED_BYTES, type CameraAccess } from '../../host/port'

/** The largest file the page hands to native code: 64 MiB, the application's own bound. */
export const HANDED_FILE_LIMIT = MAX_HANDED_BYTES

/** The largest file a host takes: 2 GiB. */
export const HOST_FILE_LIMIT = 2 * 1024 * 1024 * 1024

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
  | { readonly admitted: true }
  | { readonly admitted: false; readonly reason: string }

/**
 * Decides whether one picked file can go.
 *
 * The refusal names the file, its size and the bound, because "it did not work" leaves a person
 * guessing and "this phone sends a file of at most 64 MB" tells them what to choose instead.
 */
export function admit(picked: Picked): Admission {
  if (picked.byteLen <= HANDED_FILE_LIMIT) return { admitted: true }
  return {
    admitted: false,
    reason: `${picked.name} is ${describeBytes(picked.byteLen)}. This phone sends a picked file of at most ${describeBytes(HANDED_FILE_LIMIT).replace('.0 ', ' ')} (a host takes up to ${describeBytes(HOST_FILE_LIMIT).replace('.0 ', ' ')}). Choose a smaller file.`
  }
}

/** A size a person reads, rather than a number of bytes. */
export function describeBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

/** What the picker says when the camera is not allowed, and how to allow it. */
export const CAMERA_NOT_ALLOWED =
  'KalaReach cannot use the camera. Allow it in Settings, if this phone lets you, to take a photo.'

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
