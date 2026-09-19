/**
 * The one surface the interface talks to.
 *
 * Every screen in this application reads protocol values and writes protocol parameters. It does
 * not hold a connection, a socket or a path: it calls a named command and receives what the host
 * returned. That is what lets the same screens run on the desktop, where the commands reach a
 * native backend, and under test, where they reach a scripted host.
 *
 * The types here are the generated protocol types wherever one exists. Where a shape belongs to
 * this application rather than to the wire, it is declared here and nowhere else.
 */

import type {
  ClosureRecord,
  Dimensions4,
  EnvironmentListResult,
  HostInfoResult,
  Receipt,
  SessionListResult,
  SessionReadResult,
  ShellLaunchResult
} from '@kalareach/protocol'
import type { DocumentNode } from '@kalareach/plugin-sdk'

import type { AttentionInbox, LaunchSurface } from '../model/pending'

/** A failure a command answered with. */
export interface HostError {
  /** The protocol error code. */
  readonly code: string
  /** Plain text for a person. */
  readonly message: string
  /** What the person can do about it, where the client knows. */
  readonly user_action: string
}

/** The rendezvous origin this device is configured with. */
export interface RendezvousOrigin {
  readonly origin: string
  readonly host: string
  readonly is_default: boolean
}

/** What a scanned QR payload turned out to be. */
export type ScannedCode =
  | {
      readonly mode: 'code'
      readonly origin: RendezvousOrigin
      readonly code: string
      /** True when the QR names an origin other than the configured one. */
      readonly needs_origin_confirmation: boolean
    }
  | {
      readonly mode: 'direct'
      readonly invitation_id: string
      readonly endpoint_id: string
      readonly expires_at_ms: string
    }

/** What the platform's user-verification ceremony reported. */
export interface OwnerPresence {
  readonly verified: boolean
  readonly mechanism: string
  readonly reason: string
}

/** A link the backend is willing to open. */
export interface ApprovedLink {
  readonly scheme: string
  readonly url: string
  readonly host: string | null
}

/** One image the person explicitly imported. */
export interface ImportedImage {
  readonly url: string
  readonly media_type: string
  readonly bytes: number[]
}

/** One thing an export deliberately does not carry. */
export interface Omission {
  readonly kind: string
  readonly detail: string
  readonly count: number
}

/** What an export wrote. */
export interface Written {
  readonly path: string
  readonly byte_len: number
  readonly omissions: readonly Omission[]
}

/** The terminal size an export records. */
export interface ExportDimensions {
  readonly columns: number
  readonly rows: number
}

/** One node as an archive carries it. */
export interface ArchivedNode {
  readonly id: string
  readonly revision: string
  readonly body: unknown
  readonly at_ms: number
}

/** One recorded slice of terminal output. */
export interface RecordedFrame {
  readonly at_ms: number
  readonly text: string
}

/**
 * The answer of a mutation: the receipt, and the method's own result when the host returned one.
 *
 * The receipt is what makes an input state "applied", so it travels beside the value rather than
 * being folded into it.
 */
export interface Settled<T = unknown> {
  readonly receipt: Receipt | null
  readonly value: T | null
}

/** One event the host pushed. */
export interface HostEvent {
  /** The stream it belongs to. */
  readonly stream_id: string
  /** Its sequence within that stream. */
  readonly sequence: string
  /** The event body. */
  readonly body: unknown
}

/** A file the person dropped, pasted or picked. */
export interface DroppedFile {
  readonly name: string
  readonly media_type: string
  readonly byte_len: number
  /** The bytes, where the platform gave them to the page rather than to the backend. */
  readonly bytes?: Uint8Array
  /** The path, where the platform gave the backend a path instead. */
  readonly path?: string
}

/**
 * The commands the interface may call.
 *
 * One method per command, named for what the person is doing rather than for the wire. Nothing
 * here takes a method name: a screen cannot reach an operation this list does not carry.
 */
export interface HostPort {
  /** Whether a host connection is live. */
  connectionState(): Promise<boolean>

  hostInfo(environmentId: string): Promise<HostInfoResult>
  environmentList(environmentId: string): Promise<EnvironmentListResult>
  environmentCapabilities(environmentId: string, params: unknown): Promise<unknown>

  sessionList(environmentId: string, params: unknown): Promise<SessionListResult>
  sessionRead(environmentId: string, params: unknown): Promise<SessionReadResult>
  sessionClose(environmentId: string, params: unknown): Promise<Settled<ClosureRecord>>

  /**
   * What the launch surface may draw right now.
   *
   * The prompt generation in the answer is the one a launch must name. A button drawn at an older
   * generation is disabled rather than launched against a prompt the person has not seen.
   */
  launchSurface(environmentId: string, params: unknown): Promise<LaunchSurface>
  shellLaunch(environmentId: string, params: unknown): Promise<Settled<ShellLaunchResult>>

  agentSnapshot(environmentId: string, params: unknown): Promise<{ nodes: DocumentNode[] }>
  agentCommands(environmentId: string, params: unknown): Promise<unknown>
  composerSubmit(environmentId: string, params: unknown): Promise<Settled>
  composerQueue(environmentId: string, params: unknown): Promise<Settled>
  composerSteer(environmentId: string, params: unknown): Promise<Settled>
  composerInterrupt(environmentId: string, params: unknown): Promise<Settled>
  approvalRespond(environmentId: string, params: unknown): Promise<Settled>
  pluginActionInvoke(environmentId: string, params: unknown): Promise<Settled>

  draftCreate(environmentId: string, params: unknown): Promise<Settled>
  draftUpdate(environmentId: string, params: unknown): Promise<Settled>
  draftAddAttachment(environmentId: string, params: unknown): Promise<Settled>
  /** Reads the bytes behind one validated attachment handle. */
  attachmentImage(environmentId: string, params: unknown): Promise<{ bytes: number[]; media_type: string }>

  historyPage(environmentId: string, params: unknown): Promise<unknown>
  attentionRead(environmentId: string, params: unknown): Promise<AttentionInbox>
  attentionAcknowledge(environmentId: string, params: unknown): Promise<Settled>
  questionRead(environmentId: string, params: unknown): Promise<unknown>
  questionAnswer(environmentId: string, params: unknown): Promise<Settled>
  grantList(environmentId: string, params: unknown): Promise<unknown>
  grantCreate(environmentId: string, params: unknown): Promise<Settled>

  pluginList(environmentId: string, params: unknown): Promise<unknown>
  catalogueList(environmentId: string, params: unknown): Promise<unknown>

  changesetRead(environmentId: string, params: unknown): Promise<unknown>

  storageStatus(environmentId: string, params: unknown): Promise<unknown>
  storageObjectDelete(environmentId: string, params: unknown): Promise<Settled>

  terminalProjection(environmentId: string, params: unknown): Promise<ProjectedScreen>
  terminalInput(environmentId: string, params: unknown): Promise<unknown>
  attachmentViewport(environmentId: string, params: unknown): Promise<Settled>

  pairingOrigin(): Promise<RendezvousOrigin>
  pairingSetOrigin(origin: string): Promise<RendezvousOrigin>
  pairingScan(payload: string): Promise<ScannedCode>
  pairingVerifyOwner(reason: string): Promise<OwnerPresence>

  openExternal(url: string): Promise<ApprovedLink>
  importRemoteImage(url: string): Promise<ImportedImage>
  exportSemanticJson(request: {
    path: string
    sessionId: string
    exportedAtMs: number
    dimensions: ExportDimensions
    nodes: readonly ArchivedNode[]
    omissions: readonly Omission[]
  }): Promise<Written>
  exportAsciicast(request: {
    path: string
    title: string
    startedAtUnixSeconds: number
    dimensions: ExportDimensions
    frames: readonly RecordedFrame[]
    omissions: readonly Omission[]
  }): Promise<Written>

  /** Asks the platform where to write an export. `null` means the person cancelled. */
  chooseExportPath(suggestedName: string): Promise<string | null>

  /** Subscribes to the host's events. The returned function unsubscribes. */
  subscribe(listener: (event: HostEvent) => void): () => void

  /** The files the platform handed this window, as they are dropped. */
  onFilesDropped(listener: (files: readonly DroppedFile[]) => void): () => void
}

/** One row of the projected screen, as the raw view draws it. */
export interface ProjectedRow {
  /** The row's stable identity above the live screen. */
  readonly row: number
  /** The cells, already resolved to text and attributes. */
  readonly cells: readonly ProjectedCell[]
}

/** One cell of the projected screen. */
export interface ProjectedCell {
  /** The cluster this cell holds. Empty for a continuation cell of a wide cluster. */
  readonly text: string
  /** How many columns the cluster occupies. */
  readonly width: number
  /** The foreground colour, as a palette index or a hex string. */
  readonly fg?: string
  /** The background colour. */
  readonly bg?: string
  /** True when the cell is bold. */
  readonly bold?: boolean
  /** True when the cell is underlined. */
  readonly underline?: boolean
  /** True when the cell is inverted. */
  readonly inverse?: boolean
  /** The hyperlink this cell carries, where the host reported one. */
  readonly link?: string
}

/** Where the palette a projection is drawn with came from. */
export type PaletteProvenance =
  | 'host_default'
  | 'client_probe'
  | 'client_preset'
  | 'session_create'
  | 'unknown'

/** The projected screen a raw terminal view draws. */
export interface ProjectedScreen {
  /** Columns and rows. */
  readonly dimensions: Dimensions4
  /** The rows the host published. */
  readonly rows: readonly ProjectedRow[]
  /** The cursor's column and row. */
  readonly cursor: { readonly column: number; readonly row: number; readonly visible: boolean }
  /** The first row above the live screen this view is showing, or null while it is at the end. */
  readonly viewport_top_row: number | null
  /** The oldest row the host still retains. */
  readonly oldest_retained_row: number
  /** Where the palette came from. */
  readonly palette_provenance: PaletteProvenance
  /** The sixteen palette entries, as hex strings. */
  readonly palette: readonly string[]
}

/** Whether a value is a host failure rather than an unexpected one. */
export function isHostError(value: unknown): value is HostError {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as HostError).code === 'string' &&
    typeof (value as HostError).message === 'string'
  )
}

/** The message to show for a failure, whatever shape it arrived in. */
export function failureMessage(value: unknown): string {
  if (isHostError(value)) return value.message
  if (value instanceof Error) return value.message
  return 'Something went wrong.'
}

/** The protocol code of a failure, or null when it did not carry one. */
export function failureCode(value: unknown): string | null {
  return isHostError(value) ? value.code : null
}
