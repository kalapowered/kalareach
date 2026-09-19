/**
 * The port the desktop application runs on.
 *
 * Every method here is one `invoke` of one named command. Nothing builds a command name from a
 * value, so the set of commands this file can reach is the set written in it, and the set the
 * backend registers is the set it will answer.
 *
 * Some of the operations the interface knows how to display have no command yet, because their
 * parameters and results are not part of the published contract on this build. Those refuse here,
 * with the protocol's own word for it, rather than sending a request whose shape nobody agrees on.
 */

import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWebview } from '@tauri-apps/api/webview'

import type {
  ApprovedLink,
  ConnectionState,
  DroppedFile,
  HostEvent,
  HostPort,
  ImportedImage,
  OwnerPresence,
  ProjectedScreen,
  RendezvousOrigin,
  ScannedCode,
  SessionSubject,
  Settled,
  Written
} from './port'

/** The event the backend publishes each host notification on. */
export const HOST_EVENT = 'kr://event'

/** The event the backend publishes a change of connection state on. */
export const CONNECTION_EVENT = 'kr://connection'

/**
 * The refusal for an operation this build has no agreed shape for.
 *
 * `UNSUPPORTED_SCHEMA` is the protocol's own word for two builds that do not share a contract, and
 * that is exactly the situation: the interface can draw the screen, and this build cannot state
 * the request. Refusing here keeps a half-formed request off the wire.
 */
class NoAgreedShape extends Error {
  readonly code = 'UNSUPPORTED_SCHEMA'
  readonly user_action = 'update'

  constructor(operation: string) {
    super(`this host and this application do not share a contract for ${operation}`)
    this.name = 'NoAgreedShape'
  }
}

function noAgreedShape(operation: string): Promise<never> {
  return Promise.reject(new NoAgreedShape(operation))
}

/** What the backend publishes for one host event. */
interface PublishedEvent {
  readonly stream_id: string
  readonly sequence: string
  readonly event_type: string
  readonly payload: unknown
}

/** Builds the desktop port. */
export function tauriPort(): HostPort {
  const call = <T,>(command: string, args: Record<string, unknown>): Promise<T> =>
    invoke<T>(command, args)

  const read = <T,>(command: string, params: unknown): Promise<T> => call<T>(command, { params })

  const mutate = <T,>(command: string, params: unknown, subject: SessionSubject): Promise<T> =>
    call<T>(command, { params, subject })

  return {
    connectionState: () => call<ConnectionState>('connection_state', {}),

    hostInfo: () => call('host_info', {}),
    environmentList: () => call('environment_list', {}),

    sessionList: (params) => read('session_list', params),
    sessionRead: (params) => read('session_read', params),
    sessionClose: (params, subject) => mutate('session_close', params, subject),

    launchSurface: () => noAgreedShape('the launch surface'),
    shellLaunch: (params, subject) => mutate('shell_launch', params, subject),

    agentSnapshot: () => noAgreedShape("an agent's semantic snapshot"),
    agentCommands: () => noAgreedShape("an agent's commands"),
    composerSubmit: () => noAgreedShape('submitting a prompt'),
    composerQueue: () => noAgreedShape('queueing a prompt'),
    composerSteer: () => noAgreedShape('steering a turn'),
    composerInterrupt: () => noAgreedShape('interrupting a turn'),
    approvalRespond: () => noAgreedShape('answering an approval'),
    pluginActionInvoke: () => noAgreedShape("invoking a package's action"),

    draftCreate: (params, subject) => mutate<Settled>('draft_create', params, subject),
    draftUpdate: (params, subject) => mutate<Settled>('draft_update', params, subject),
    draftAddAttachment: (params, subject) =>
      mutate<Settled>('draft_add_attachment', params, subject),
    attachmentImage: (params) =>
      mutate<{ bytes: number[]; media_type: string }>('attachment_image', params, {}),

    historyPage: (params) => read('history_page', params),
    attentionRead: () => noAgreedShape('the attention inbox'),
    attentionAcknowledge: () => noAgreedShape('acknowledging an attention entry'),
    questionRead: (params) => read('question_read', params),
    questionAnswer: (params, subject) => mutate<Settled>('question_answer', params, subject),
    grantList: () => noAgreedShape('the grants a session has issued'),
    grantCreate: () => noAgreedShape('issuing a grant'),

    pluginList: () => noAgreedShape('the installed packages'),
    catalogueList: () => noAgreedShape('the package catalogue'),

    changesetRead: () => noAgreedShape('a change set'),

    storageStatus: () => noAgreedShape('what this host retains'),
    storageObjectDelete: () => noAgreedShape('deleting a retained artefact'),

    terminalProjection: (params) => read<ProjectedScreen>('events_snapshot', params),
    terminalInput: (params) => read('input_write', params),
    attachmentViewport: (params, subject) =>
      mutate<Settled>('attachment_viewport', params, subject),

    pairingOrigin: () => call<RendezvousOrigin>('pairing_origin', {}),
    pairingSetOrigin: (origin) => call<RendezvousOrigin>('pairing_set_origin', { origin }),
    pairingScan: (payload) => call<ScannedCode>('pairing_scan', { payload }),
    pairingVerifyOwner: (reason) => call<OwnerPresence>('pairing_verify_owner', { reason }),

    openExternal: (url) => call<ApprovedLink>('open_external', { url }),
    importRemoteImage: (url) => call<ImportedImage>('import_remote_image', { url }),
    exportSemanticJson: (request) =>
      call<Written>('export_semantic_json', {
        path: request.path,
        sessionId: request.sessionId,
        exportedAtMs: request.exportedAtMs,
        dimensions: request.dimensions,
        nodes: request.nodes,
        omissions: request.omissions
      }),
    exportAsciicast: (request) =>
      call<Written>('export_asciicast', {
        path: request.path,
        title: request.title,
        startedAtUnixSeconds: request.startedAtUnixSeconds,
        dimensions: request.dimensions,
        frames: request.frames,
        omissions: request.omissions
      }),

    // The platform's own dialog answers, and the backend remembers its answer for exactly one
    // write. The page never names a path of its own.
    chooseExportPath: (suggestedName) =>
      call<string | null>('choose_export_destination', { suggestedName }),

    subscribe(listener: (event: HostEvent) => void) {
      const stops: (() => void)[] = []
      let cancelled = false
      const keep = (unlisten: () => void) => {
        if (cancelled) unlisten()
        else stops.push(unlisten)
      }

      void listen<PublishedEvent>(HOST_EVENT, (event) => {
        listener({
          stream_id: event.payload.stream_id,
          sequence: event.payload.sequence,
          body: { kind: event.payload.event_type, payload: event.payload.payload }
        })
      }).then(keep)

      void listen<ConnectionState>(CONNECTION_EVENT, (event) => {
        listener({
          stream_id: '',
          sequence: '',
          body: { kind: 'connection', connected: event.payload.connected }
        })
      }).then(keep)

      return () => {
        cancelled = true
        for (const stop of stops) stop()
      }
    },

    onFilesDropped(listener: (files: readonly DroppedFile[]) => void) {
      let stop: (() => void) | null = null
      let cancelled = false
      void getCurrentWebview()
        .onDragDropEvent((event) => {
          if (event.payload.type !== 'drop') return
          // The platform hands the native backend paths, never the bytes: the page is told what
          // was dropped and the backend is what reads it.
          listener(
            event.payload.paths.map((path) => ({
              name: path.split(/[\\/]/).pop() ?? path,
              media_type: 'application/octet-stream',
              byte_len: 0,
              path
            }))
          )
        })
        .then((unlisten) => {
          if (cancelled) unlisten()
          else stop = unlisten
        })
      return () => {
        cancelled = true
        stop?.()
      }
    }
  }
}

/** Whether this page is running inside the desktop shell. */
export function insideDesktopShell(): boolean {
  return '__TAURI_INTERNALS__' in window
}
