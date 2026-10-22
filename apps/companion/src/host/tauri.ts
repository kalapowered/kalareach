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
  CameraAccess,
  ConnectionState,
  DroppedFile,
  GrantNotices,
  HostEvent,
  HostPort,
  ImportedImage,
  KitSaved,
  OpenRequest,
  OwnerView,
  PairingOrigin,
  PairingUnavailable,
  PairingView,
  PushView,
  IntakeView,
  RecoveryView,
  RevocationView,
  ReviewOutcome,
  SessionAgents,
  SessionSubject,
  Settled,
  SettingsChoice,
  SettingsPane,
  SettingsView,
  SessionStanding,
  SetupIdentity,
  StandingEvent,
  SyncServiceView,
  TerminalView,
  TerminalViewState,
  VoiceCallState,
  VoiceClosure,
  VoiceScope,
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

/** The event the backend publishes the person's settings on when they change by themselves. */
export const SETTINGS_EVENT = 'kr://settings'

/** The event the backend publishes a change of an opened session's standing on. */
export const STANDING_EVENT = 'kr://standing'

/** The event the backend publishes the pairing screen's state on. */
export const PAIRING_EVENT = 'kr://pairing'

/** The event native code publishes where notifications stand on. */
export const PUSH_EVENT = 'kr://push'

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
  /** The environment of the host it came from. */
  readonly host?: string
  readonly stream_id: string
  readonly sequence: string
  readonly event_type: string
  readonly payload: unknown
}

/** Builds the desktop port. */
export function tauriPort(): HostPort {
  // The environment of the host the connection last said it was to: undefined before it has said
  // anything, null while there is no host, as when one is being chosen. An event that names another
  // host, or one that comes while there is none, was on its way when the host changed, and is not the
  // new host's.
  let host: string | null | undefined
  // How many times the connection has said something. An answer to a read made before that does not
  // overwrite what the connection said since.
  let said = 0
  const heard = (state: ConnectionState): ConnectionState => {
    said += 1
    host = state.environment_id
    return state
  }
  const learned = (at: number) => (state: ConnectionState): ConnectionState => {
    if (said === at) host = state.environment_id
    return state
  }
  const ofThisHost = (published: { readonly host?: string }): boolean =>
    published.host === undefined || host === undefined || published.host === host
  /** The host is being chosen: nothing the old one sent is the new one's. */
  const choosing = (): number => {
    said += 1
    host = null
    return said
  }

  const call = <T,>(command: string, args: Record<string, unknown>): Promise<T> =>
    invoke<T>(command, args)

  /**
   * Asks native code to use or forget a host. While it is asked, nothing of the old host is the new
   * one's. A refusal changes nothing there: the connection it kept is asked what it is, so the host
   * still in use is heard again, unless the connection has said something since.
   */
  const choose = (command: string, reference: string): Promise<ConnectionState> => {
    const at = choosing()
    return call<ConnectionState>(command, { reference })
      .then(receivedConnection)
      .then(learned(at))
      .catch(async (failure: unknown) => {
        await call<ConnectionState>('connection_state', {})
          .then(receivedConnection)
          .then(learned(at))
          .catch(() => {
            // Nothing can say which host is in use: events are taken as they come, as before any
            // host was known.
            if (said === at) host = undefined
          })
        throw failure
      })
  }

  const read = <T,>(command: string, params: unknown): Promise<T> => call<T>(command, { params })

  const mutate = <T,>(command: string, params: unknown, subject: SessionSubject): Promise<T> =>
    call<T>(command, { params, subject })

  // A command about a session also names the opening of the screen making it. An opening that is
  // left out is no opening: native code serves the call over a link kept for calls made outside
  // any screen.
  const readIn = <T,>(command: string, params: unknown, opening: string | undefined): Promise<T> =>
    call<T>(command, { params, opening })

  const mutateIn = <T,>(
    command: string,
    params: unknown,
    subject: SessionSubject,
    opening: string | undefined
  ): Promise<T> => call<T>(command, { params, subject, opening })

  return {
    // Native code's reason can arrive blank; it is taken in as none, from a read and a change alike.
    connectionState: () => {
      const at = said
      return call<ConnectionState>('connection_state', {})
        .then(receivedConnection)
        .then(learned(at))
    },
    onConnection: (listener) =>
      listening<ConnectionState>(CONNECTION_EVENT, (state) => {
        listener(heard(receivedConnection(state)))
      }),

    openSession: (request: OpenRequest) =>
      call<SessionStanding>('session_open', {
        sessionId: request.sessionId,
        grantId: request.grantId,
        opening: request.opening
      }),
    leaveSession: (sessionId, opening) =>
      call<undefined>('session_leave', { sessionId, opening }),
    onStanding: (listener: (event: StandingEvent) => void) =>
      listening<StandingEvent>(STANDING_EVENT, listener),

    hostInfo: () => call('host_info', {}),
    environmentList: () => call('environment_list', {}),

    environmentCapabilities: (params) => read('environment_capabilities', params),
    setupIdentity: () => call<SetupIdentity>('setup_identity', {}),
    openSettingsPane: (pane) => call<SettingsPane>('setup_open_settings', { pane }),

    sessionList: (params) => read('session_list', params),
    sessionRead: (params) => read('session_read', params),
    sessionCreate: (params, subject) => mutate('session_create', params, subject),
    sessionClose: (params, subject, opening) =>
      mutateIn('session_close', params, subject, opening),
    sessionDescribe: (params) => read('session_describe', params),
    // Both writes are about the host and name no session: the subject is empty.
    descriptionSetup: () => call('description_setup', {}),
    descriptionConfigure: (params) => mutate('description_configure', params, {}),
    descriptionDownload: (params) => mutate('description_download', params, {}),
    environmentCapabilitiesCheck: (params) =>
      mutate('environment_capabilities_check', params, {}),

    launchSurface: () => noAgreedShape('the launch surface'),
    shellLaunch: (params, subject) => mutate('shell_launch', params, subject),

    // The agent's calls go to the session's own worker, which native code reaches and which checks
    // this device's rights itself. A mutation names its session, instance and binding revision in
    // its own parameters, and native code builds its envelope from exactly those.
    sessionAgents: (sessionId, opening) =>
      call<SessionAgents>('session_agents', { sessionId, opening }),
    agentCapabilities: (params, opening) => readIn('agent_capabilities', params, opening),
    agentSnapshot: (params, opening) => readIn('agent_snapshot', params, opening),
    agentCommands: (params, opening) => readIn('agent_commands', params, opening),
    approvalInspect: (params, opening) => readIn('agent_approval_inspect', params, opening),
    composerSubmit: (params, opening) => call('agent_prompt_submit', { params, opening }),
    composerQueue: (params, opening) => call('agent_prompt_queue', { params, opening }),
    composerSteer: (params, opening) => call('agent_turn_steer', { params, opening }),
    composerInterrupt: (params, opening) => call('agent_turn_cancel', { params, opening }),
    approvalRespond: (params, opening) => call('agent_approval_respond', { params, opening }),
    pluginActionInvoke: () => noAgreedShape("invoking a package's action"),

    deviceDrafts: () => call('device_drafts', {}),
    deviceDraftSave: (request) => read('device_draft_save', request),
    deviceDraftRetarget: (request) => read('device_draft_retarget', request),
    deviceDraftDiscard: (request) => read('device_draft_discard', request),
    deviceDraftMarkRemoval: (request) => read('device_draft_mark_removal', request),
    draftCreate: (params, subject) => mutate<Settled>('draft_create', params, subject),
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

    historyPage: (params) => read('history_page', params),
    actionRead: (params, opening) => readIn('action_read', params, opening),
    // Attention and review belong to the environment, so an acknowledgement names no session.
    attentionRead: (params) => read('attention_read', params),
    attentionAcknowledge: (params) => mutate('attention_acknowledge', params, {}),
    reviewRead: (params) => read('review_read', params),
    reviewAcknowledge: (params) => mutate('review_acknowledge', params, {}),
    questionRead: (params, opening) => readIn('question_read', params, opening),
    questionAnswer: (params, opening) => readIn('question_answer', params, opening),
    questionKept: () => call('question_kept', {}),
    questionSettle: (sessionId, opening) => readIn('question_settle', { sessionId }, opening),
    questionSendKept: (which, opening) => readIn('question_send_kept', which, opening),
    questionDismissKept: (which) => read('question_dismiss_kept', which),
    deviceList: (params) => read('device_list', params),
    grantNotices: (selection) => call<GrantNotices>('grant_notices', { selection }),
    sessionScreenPreview: (params) => read('session_screen_preview', params),
    grantCreate: (params, subject) => mutate('grant_create', params, subject),
    grantList: (params) => read('grant_list', params),
    grantRevoke: (params) => call('grant_revoke', { params }),
    grantRedeem: (params) => call('grant_redeem', { params }),
    grantHeld: () => call('grant_held', {}),
    transferAsk: (params, subject) => call('transfer_ask', { params, subject }),
    transferAnswered: (reference) => call('transfer_answered', { reference }),
    transferFinish: (reference) => call('transfer_finish', { reference }),
    transferCancel: (reference) => call<undefined>('transfer_cancel', { reference }),
    attemptsList: () => call('attempts_list', {}),
    attemptAsk: (actionId) => call('attempt_ask', { actionId }),
    attemptSetHidden: (actionId, hidden) => call('attempt_set_hidden', { actionId, hidden }),
    attemptRemove: (actionId) => call<undefined>('attempt_remove', { actionId }),

    pluginList: (params) => read('plugin_list', params),
    catalogueList: (params) => read('catalogue_list', params),

    changesetRead: (params) => read('changeset_read', params),

    storageStatus: () => noAgreedShape('what this host retains'),
    storageObjectDelete: () => noAgreedShape('deleting a retained artefact'),

    // Each view has a channel of its own, which native code publishes that view's states on and
    // nothing else: no protocol event and no other view's state ever reaches its listener.
    openTerminalView: async (sessionId, grid, listener, opening): Promise<TerminalView> => {
      const states = new Channel<TerminalViewState>()
      states.onmessage = listener
      const view = await call<string>('terminal_view_open', {
        sessionId,
        ...viewSizeArguments(grid),
        opening,
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

    // Voice. The reads and the stop each reach one method. A start is the application's own call:
    // it opens the call on the device and asks the host for it. The silence and the state are read
    // from the call the application holds, and reach no service.
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
    voiceScope: () => call<VoiceScope>('voice_scope', {}),
    voiceAllow: (request, subject) =>
      mutate(
        'voice_allow',
        { session_ids: request.sessionIds, actions: request.actions },
        subject
      ),
    voiceStop: (voiceSessionId, subject) =>
      call<VoiceClosure>('voice_stop', { voiceSessionId, subject }),
    voiceContext: (params) => read('voice_context', params),
    voiceSetMuted: (what, muted) => call<VoiceCallState>('voice_set_muted', { what, muted }),
    voiceCallState: () => call<VoiceCallState>('voice_call_state', {}),

    hostsUse: (reference) => choose('hosts_use', reference),
    hostsForget: (reference) => choose('hosts_forget', reference),
    pushView: () => call<PushView>('push_view', {}),
    pushEnable: (reference) => call<PushView>('push_enable', { reference }),
    pushRefresh: () => call<PushView>('push_refresh', {}),
    notificationRoute: () => call<string | null>('notification_route', {}),
    onPush: (listener) => listening<PushView>(PUSH_EVENT, listener),
    pairingView: () => call<PairingView>('pairing_view', {}),
    pairingSetOrigin: (origin) => call<PairingOrigin>('pairing_set_origin', { origin }),
    pairingStartCode: (code) => call<undefined>('pairing_start_code', { code }),
    pairingPaste: () => call<IntakeView>('pairing_paste', {}),
    pairingScan: () => call<IntakeView>('pairing_scan', {}),
    pairingScanPhoto: () => call<IntakeView>('pairing_scan_photo', {}),
    pairingKeepAwake: (on) => call<undefined>('pairing_keep_awake', { on }),
    cameraAccess: () => call<CameraAccess>('camera_access', {}),
    openAppSettings: () => call<undefined>('app_open_settings', {}),
    pairingStartRead: () => call<undefined>('pairing_start_read', {}),
    pairingStop: () => call<undefined>('pairing_stop', {}),
    onPairing: (listener) => listening<PairingView | PairingUnavailable>(PAIRING_EVENT, listener),

    ownerConfirmations: () => call<OwnerView>('owner_confirmations', {}),
    ownerConfirmationReview: (reference) =>
      call<ReviewOutcome>('owner_confirmation_review', { request: { reference } }),
    onConfirmations: (listener) => listening<OwnerView>(CONFIRMATIONS_EVENT, listener),
    revocationView: () => call<RevocationView>('revocation_view', {}),
    revocationRevoke: (host, device) =>
      call<RevocationView>('revocation_revoke', { host, device }),

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
    accountSignInForRecovery: () => call<AccountView>('account_sign_in_for_recovery', {}),
    accountSignInCancel: () => call<undefined>('account_sign_in_cancel', {}),
    accountSignOut: () => call<AccountView>('account_sign_out', {}),
    accountUsage: () => call<UsageView>('account_usage', {}),
    onAccount: (listener) => listening<AccountView>(ACCOUNT_EVENT, listener),

    syncServiceView: () => call<SyncServiceView>('sync_service_view', {}),
    syncServiceSet: (origin) => call<SyncServiceView>('sync_service_set', { origin }),
    settingsView: () => call<SettingsView>('settings_view', {}),
    settingsSetColourMode: (mode) => call<SettingsView>('settings_colour_mode_set', { mode }),
    settingsSyncTurnOn: () => call<SettingsView>('settings_sync_turn_on', {}),
    settingsSyncNow: () => call<SettingsView>('settings_sync_now', {}),
    settingsDraftsSet: (enabled) => call<SettingsView>('settings_drafts_set', { enabled }),
    settingsDevicesRefresh: () => call<SettingsView>('settings_devices_refresh', {}),
    settingsDeviceShare: (reference) => call<SettingsView>('settings_device_share', { reference }),
    settingsDeviceRemove: (reference) => call<SettingsView>('settings_device_remove', { reference }),
    settingsJoin: (reference) => call<SettingsView>('settings_join', { reference }),
    settingsDevicesDismiss: () => call<SettingsView>('settings_devices_dismiss', {}),
    settingsConflicts: () => call<SettingsChoice | null>('settings_conflicts', {}),
    settingsConflictResolve: (keep) =>
      call<SettingsView>('settings_conflict_resolve', { keep }),
    onSettings: (listener) => listening<SettingsView>(SETTINGS_EVENT, listener),
    recoveryView: () => call<RecoveryView>('recovery_view', {}),
    recoveryTurnOn: () => call<RecoveryView>('recovery_turn_on', {}),
    recoverySettle: () => call<RecoveryView>('recovery_settle', {}),
    recoverySaveKit: (path) => call<KitSaved>('recovery_save_kit', { path }),

    subscribe: (listener: (event: HostEvent) => void) =>
      listening<PublishedEvent>(HOST_EVENT, (published) => {
        if (!ofThisHost(published)) return
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
