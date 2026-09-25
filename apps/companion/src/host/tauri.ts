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

import type { AccountView, UsageView } from '../model/account'

import type {
  ApprovedLink,
  AttachmentHandle,
  ConnectionState,
  DroppedFile,
  HostEvent,
  HostPort,
  ImportedImage,
  OwnerView,
  PairingOrigin,
  PairingView,
  PasteView,
  ProjectedScreen,
  ReviewOutcome,
  SessionSubject,
  Settled,
  SettingsPane,
  SetupIdentity,
  VoiceCallState,
  VoiceClosure,
  Written
} from './port'

/** The event the backend publishes each host notification on. */
export const HOST_EVENT = 'kr://event'

/** The event the backend publishes a change of connection state on. */
export const CONNECTION_EVENT = 'kr://connection'

/** The event the backend publishes the paths of dropped files on. */
export const DROPPED_EVENT = 'kr://dropped'

/** The event the backend publishes the account's view on when it changes by itself. */
export const ACCOUNT_EVENT = 'kr://account'

/** The event the backend publishes the pairing screen's state on. */
export const PAIRING_EVENT = 'kr://pairing'

/** The event the backend publishes the owner confirmations on. */
export const CONFIRMATIONS_EVENT = 'kr://confirmations'

/**
 * Listens for one backend event. Resolves, with the function that stops listening, once the
 * listener is registered: the shell registers it asynchronously, and drops what it publishes
 * before then.
 */
function listening<T>(event: string, listener: (payload: T) => void): Promise<() => void> {
  return listen<T>(event, (published) => {
    listener(published.payload)
  })
}

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
    onConnection: (listener) => listening<ConnectionState>(CONNECTION_EVENT, listener),

    hostInfo: () => call('host_info', {}),
    environmentList: () => call('environment_list', {}),

    environmentCapabilities: (params) => read('environment_capabilities', params),
    setupIdentity: () => call<SetupIdentity>('setup_identity', {}),
    openSettingsPane: (pane) => call<SettingsPane>('setup_open_settings', { pane }),

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
    // The upload belongs to the same session the subject names; sending the subject without it
    // would reserve the transfer against no session while the action targeted one.
    attachmentUpload: (path, subject) =>
      call<AttachmentHandle>('attachment_upload', {
        path,
        subject,
        sessionId: subject.sessionId ?? null
      }),
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

    // Voice. The first three each reach one method; the last two reach the call this device is
    // holding and no service at all, which is what keeps mute and closure working when the broker
    // is the thing that has stopped answering.
    voicePrepare: (params) => read('voice_prepare', params),
    voiceStart: (request, subject) =>
      call('voice_start', {
        sessionIds: request.sessionIds,
        durationSeconds: request.durationSeconds,
        reasoningBudgetMinor: request.reasoningBudgetMinor,
        prepared: request.prepared,
        expectedRateVersion: request.expectedRateVersion,
        subject
      }),
    voiceStop: (voiceSessionId, subject) =>
      call<VoiceClosure>('voice_stop', { voiceSessionId, subject }),
    voiceDelegate: (params, subject) => mutate('voice_delegate', params, subject),
    voiceContext: (params) => read('voice_context', params),
    voiceSetMuted: (what, muted) => call<VoiceCallState>('voice_set_muted', { what, muted }),
    voiceCallState: () => call<VoiceCallState>('voice_call_state', {}),

    pairingView: () => call<PairingView>('pairing_view', {}),
    pairingSetOrigin: (origin) => call<PairingOrigin>('pairing_set_origin', { origin }),
    pairingStartCode: (code) => call<undefined>('pairing_start_code', { code }),
    pairingPaste: () => call<PasteView>('pairing_paste', {}),
    pairingStartRead: () => call<undefined>('pairing_start_read', {}),
    pairingStop: () => call<undefined>('pairing_stop', {}),
    onPairing: (listener) => listening<PairingView>(PAIRING_EVENT, listener),

    ownerConfirmations: () => call<OwnerView>('owner_confirmations', {}),
    ownerConfirmationReview: (reference) =>
      call<ReviewOutcome>('owner_confirmation_review', { request: { reference } }),
    onConfirmations: (listener) => listening<OwnerView>(CONFIRMATIONS_EVENT, listener),

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

    accountStatus: () => call<AccountView>('account_status', {}),
    accountSignIn: () => call<AccountView>('account_sign_in', {}),
    accountSignInCancel: () => call<undefined>('account_sign_in_cancel', {}),
    accountSignOut: () => call<AccountView>('account_sign_out', {}),
    accountUsage: () => call<UsageView>('account_usage', {}),
    onAccount(listener: (view: AccountView) => void) {
      let stop: (() => void) | null = null
      let cancelled = false
      void listen<AccountView>(ACCOUNT_EVENT, (event) => {
        listener(event.payload)
      }).then((unlisten) => {
        if (cancelled) unlisten()
        else stop = unlisten
      })
      return () => {
        cancelled = true
        stop?.()
      }
    },

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
      // The backend records the paths first and then publishes them, so a path the page sees here
      // is one the backend will accept for exactly one upload.
      void listen<string[]>(DROPPED_EVENT, (event) => {
        listener(
          event.payload.map((path) => ({
            name: path.split(/[\\/]/).pop() ?? path,
            media_type: 'application/octet-stream',
            byte_len: 0,
            path
          }))
        )
      }).then((unlisten) => {
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
