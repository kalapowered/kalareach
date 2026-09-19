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

/**
 * What a mutation is about.
 *
 * Section 23 makes every mutation state its exact subject. The interface supplies it because the
 * interface is what read it: it saw the session in a list the host sent, with the epoch beside the
 * identifier. The environment is not the page's to choose and comes from the connection itself.
 */
export interface SessionSubject {
  readonly sessionId?: string
  readonly sessionEpoch?: string
  readonly applicationInstanceId?: string
  readonly agentBindingRevision?: string
}

/** What the backend says about the host connection. */
export interface ConnectionState {
  /** True while a session is live. */
  readonly connected: boolean
  /** The environment the connection belongs to, when there is one. */
  readonly environment_id: string | null
  /** Why there is no connection, in plain words, when there is none. */
  readonly reason: string | null
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

/** A completed, verified attachment, as `upload.finish` published it. */
export interface AttachmentHandle {
  readonly transfer_id: string
  readonly environment_id: string
  readonly byte_len: string
  readonly content_digest: string
  readonly declared_media_type: string
  readonly original_file_name: string
  readonly presented_as_image: boolean
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
  /**
   * The action's durable identity.
   *
   * It exists from the moment the request is submitted, before any receipt, so a submission whose
   * outcome is unknown is still one the interface can ask about rather than resubmit.
   */
  readonly action_id: string | null
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
  /** Whether a host connection is live, and why not when it is not. */
  connectionState(): Promise<ConnectionState>

  hostInfo(): Promise<HostInfoResult>
  environmentList(): Promise<EnvironmentListResult>

  sessionList(params: unknown): Promise<SessionListResult>
  sessionRead(params: unknown): Promise<SessionReadResult>
  sessionClose(params: unknown, subject: SessionSubject): Promise<Settled<ClosureRecord>>

  /**
   * What the launch surface may draw right now.
   *
   * The prompt generation in the answer is the one a launch must name. A button drawn at an older
   * generation is disabled rather than launched against a prompt the person has not seen.
   */
  launchSurface(params: unknown): Promise<LaunchSurface>
  shellLaunch(params: unknown, subject: SessionSubject): Promise<Settled<ShellLaunchResult>>

  agentSnapshot(params: unknown): Promise<{ nodes: DocumentNode[] }>
  agentCommands(params: unknown): Promise<unknown>
  composerSubmit(params: unknown, subject: SessionSubject): Promise<Settled>
  composerQueue(params: unknown, subject: SessionSubject): Promise<Settled>
  composerSteer(params: unknown, subject: SessionSubject): Promise<Settled>
  composerInterrupt(params: unknown, subject: SessionSubject): Promise<Settled>
  approvalRespond(params: unknown, subject: SessionSubject): Promise<Settled>
  pluginActionInvoke(params: unknown, subject: SessionSubject): Promise<Settled>

  draftCreate(params: unknown, subject: SessionSubject): Promise<Settled>
  draftUpdate(params: unknown, subject: SessionSubject): Promise<Settled>
  /**
   * Sends one dropped file to the host and answers with the verified handle.
   *
   * The page never holds the bytes. The platform gave the backend a path when the person dropped
   * the file on the window; this names that path back, and the backend refuses any other.
   */
  attachmentUpload(path: string, subject: SessionSubject): Promise<AttachmentHandle>
  draftAddAttachment(params: unknown, subject: SessionSubject): Promise<Settled>
  /** Reads the bytes behind one validated attachment handle. */
  attachmentImage(params: unknown): Promise<{ bytes: number[]; media_type: string }>

  historyPage(params: unknown): Promise<unknown>
  attentionRead(params: unknown): Promise<AttentionInbox>
  attentionAcknowledge(params: unknown, subject: SessionSubject): Promise<Settled>
  questionRead(params: unknown): Promise<unknown>
  questionAnswer(params: unknown, subject: SessionSubject): Promise<Settled>
  grantList(params: unknown): Promise<unknown>
  grantCreate(params: unknown, subject: SessionSubject): Promise<Settled>

  pluginList(params: unknown): Promise<unknown>
  catalogueList(params: unknown): Promise<unknown>

  changesetRead(params: unknown): Promise<unknown>

  storageStatus(params: unknown): Promise<unknown>
  storageObjectDelete(params: unknown, subject: SessionSubject): Promise<Settled>

  terminalProjection(params: unknown): Promise<ProjectedScreen>
  terminalInput(params: unknown): Promise<unknown>
  attachmentViewport(params: unknown, subject: SessionSubject): Promise<Settled>

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
