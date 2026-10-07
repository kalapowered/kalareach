/**
 * The port the desktop application runs on.
 *
 * Every method here is one `invoke` of one named command. Nothing builds a command name from a
 * value, so the set of commands this file can reach is the set written in it, and the set the
 * backend registers is the set it will answer.
 *
 * An operation the interface knows how to display whose parameters or result are not part of the
 * published contract has no command. It refuses here, with the protocol's own word for it, rather
 * than sending a request whose shape nobody agrees on.
 */

import { Channel, invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

import type { AccountView, UsageView } from '../model/account'

import type {
  ApprovedLink,
  AttachmentHandle,
  ConnectionState,
  DroppedFile,
  GrantNotices,
  HostEvent,
  HostPort,
  ImportedImage,
  OwnerView,
  PairingOrigin,
  PairingView,
  PasteView,
  ReviewOutcome,
  SessionAgents,
  SessionSubject,
  Settled,
  SettingsPane,
  SetupIdentity,
  TerminalView,
  TerminalViewState,
  VoiceCallState,
  VoiceClosure,
  Written
} from './port'
import { receivedConnection, viewMoveArguments, viewSizeArguments } from './port'

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
    // Native code's reason can arrive blank; it is taken in as none, from a read and a change alike.
    connectionState: () =>
      call<ConnectionState>('connection_state', {}).then(receivedConnection),
    onConnection: (listener) =>
      listening<ConnectionState>(CONNECTION_EVENT, (state) => {
        listener(receivedConnection(state))
      }),

    hostInfo: () => call('host_info', {}),
    environmentList: () => call('environment_list', {}),

    environmentCapabilities: (params) => read('environment_capabilities', params),
    setupIdentity: () => call<SetupIdentity>('setup_identity', {}),
    openSettingsPane: (pane) => call<SettingsPane>('setup_open_settings', { pane }),

    sessionList: (params) => read('session_list', params),
    sessionRead: (params) => read('session_read', params),
    sessionCreate: (params, subject) => mutate('session_create', params, subject),
    sessionClose: (params, subject) => mutate('session_close', params, subject),
    sessionDescribe: (params) => read('session_describe', params),
    // Both writes are about the host and name no session: the subject is empty.
    descriptionSetup: () => call('description_setup', {}),
    descriptionConfigure: (params) => mutate('description_configure', params, {}),
    descriptionDownload: (params) => mutate('description_download', params, {}),

    launchSurface: () => noAgreedShape('the launch surface'),
    shellLaunch: (params, subject) => mutate('shell_launch', params, subject),

    // The agent's calls go to the session's own worker, which native code reaches and which checks
    // this device's rights itself. A mutation names its session, instance and binding revision in
    // its own parameters, and native code builds its envelope from exactly those.
    sessionAgents: (sessionId) => call<SessionAgents>('session_agents', { sessionId }),
    agentCapabilities: (params) => read('agent_capabilities', params),
    agentSnapshot: (params) => read('agent_snapshot', params),
    agentCommands: (params) => read('agent_commands', params),
    approvalInspect: (params) => read('agent_approval_inspect', params),
    composerSubmit: (params) => call('agent_prompt_submit', { params }),
    composerQueue: (params) => call('agent_prompt_queue', { params }),
    composerSteer: (params) => call('agent_turn_steer', { params }),
    composerInterrupt: (params) => call('agent_turn_cancel', { params }),
    approvalRespond: (params) => call('agent_approval_respond', { params }),
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
    // The bytes are the call's raw body; the name and the subject travel as its two headers.
    attachmentUploadBytes: (file, subject) =>
      invoke<AttachmentHandle>('attachment_upload_bytes', file.bytes, {
        headers: {
          'kr-file-name': encodeURIComponent(file.name),
          'kr-subject': JSON.stringify(subject)
        }
      }),
    draftAddAttachment: (params, subject) =>
      mutate<Settled>('draft_add_attachment', params, subject),
    attachmentImage: (params) =>
      mutate<{ bytes: number[]; media_type: string }>('attachment_image', params, {}),

    historyPage: (params) => read('history_page', params),
    // Attention and review belong to the environment, so an acknowledgement names no session.
    attentionRead: (params) => read('attention_read', params),
    attentionAcknowledge: (params) => mutate('attention_acknowledge', params, {}),
    reviewRead: (params) => read('review_read', params),
    reviewAcknowledge: (params) => mutate('review_acknowledge', params, {}),
    questionRead: (params) => read('question_read', params),
    questionAnswer: (params, subject) => mutate<Settled>('question_answer', params, subject),
    deviceList: (params) => read('device_list', params),
    grantNotices: (selection) => call<GrantNotices>('grant_notices', { selection }),
    grantCreate: (params, subject) => mutate('grant_create', params, subject),
    grantList: (params) => read('grant_list', params),

    pluginList: (params) => read('plugin_list', params),
    catalogueList: (params) => read('catalogue_list', params),

    changesetRead: (params) => read('changeset_read', params),

    storageStatus: () => noAgreedShape('what this host retains'),
    storageObjectDelete: () => noAgreedShape('deleting a retained artefact'),

    // Each view has a channel of its own, which native code publishes that view's states on and
    // nothing else: no protocol event and no other view's state ever reaches its listener.
    openTerminalView: async (sessionId, grid, listener): Promise<TerminalView> => {
      const states = new Channel<TerminalViewState>()
      states.onmessage = listener
      const view = await call<string>('terminal_view_open', {
        sessionId,
        ...viewSizeArguments(grid),
        onState: states
      })
      return {
        resize: (next) => call<undefined>('terminal_view_resize', { view, ...viewSizeArguments(next) }),
        move: (next) => call<undefined>('terminal_view_move', { view, ...viewMoveArguments(next) }),
        // The person's input goes in the shape native code reads, and nothing else is sent.
        input: (next) => call<undefined>('terminal_view_input', { view, input: next }),
        close: () => call<undefined>('terminal_view_close', { view })
      }
    },

    // Voice. The reads, the stop and the delegation each reach one method. Native code refuses the
    // start, because it opens no call. The last two reach no service at all, which is what keeps
    // mute and closure working when the broker is the thing that has stopped answering.
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
    onAccount: (listener) => listening<AccountView>(ACCOUNT_EVENT, listener),

    subscribe: (listener: (event: HostEvent) => void) =>
      listening<PublishedEvent>(HOST_EVENT, (published) => {
        listener({
          stream_id: published.stream_id,
          sequence: published.sequence,
          body: { kind: published.event_type, payload: published.payload }
        })
      }),

    // The backend records the paths first and then publishes them, so a path the page sees here is
    // one the backend will accept for exactly one upload.
    onFilesDropped: (listener: (files: readonly DroppedFile[]) => void) =>
      listening<string[]>(DROPPED_EVENT, (paths) => {
        listener(
          paths.map((path) => ({
            name: path.split(/[\\/]/).pop() ?? path,
            media_type: 'application/octet-stream',
            byte_len: 0,
            path
          }))
        )
      })
  }
}

/** Whether this page is running inside the desktop shell. */
export function insideDesktopShell(): boolean {
  return '__TAURI_INTERNALS__' in window
}
