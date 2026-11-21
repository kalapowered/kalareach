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

import { Channel, invoke, type InvokeArgs, type InvokeOptions } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

import type { AccountView, ServiceLine, UsageView } from '../model/account'
import type {
  DeletionConfirmAnswer,
  DeletionSendAnswer,
  DeletionStatusAnswer,
  DeletionViewAnswer
} from '../model/deletion'

import type {
  ApprovedLink,
  AttachmentHandle,
  CameraAccess,
  ConnectionSince,
  ConnectionState,
  DroppedFile,
  GrantNotices,
  Keyed,
  ReadKey,
  HostEvent,
  HostPort,
  ImportedImage,
  ExportSaved,
  HostCoverView,
  KitSaved,
  LaunchCommandsReading,
  RecoveryArchive,
  OpenRequest,
  OtherHost,
  OwnerView,
  PairingOrigin,
  PairingUnavailable,
  PairingView,
  PushView,
  HostContact,
  HostError,
  InboxHosts,
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
import {
  failureWords,
  receivedConnection,
  supersededRead,
  viewMoveArguments,
  viewSizeArguments
} from './port'
import { createConnectionFeed } from './connection-feed'

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
 * What a person can do about a failure, in words, for each key native code names an action by.
 *
 * Section 23 has the interface translate a code into a direct action rather than show the code.
 * Native code attaches the key of the action a code maps to (`UserAction::as_str` in the client
 * library) to every failure it answers with, and these are the words for each key, the library's own
 * (`UserAction::message`). `nothing` has none: the host's words are all there is to say.
 *
 * Only `receivedFailure` reads this table.
 */
const ACTION_WORDS: Readonly<Record<string, string>> = {
  pair_again: 'Pair this device with the host again.',
  sign_in: 'Sign in to your account.',
  update: 'Update this app or the host: their versions do not agree.',
  wait: 'Wait a moment and try again.',
  resync: 'Refresh: this view has fallen behind.',
  check_the_outcome: 'Check whether this went through before trying it again.',
  fix_configuration: 'Change a setting on this device or on the host.'
}

/**
 * THE BOUNDARY. This file is the one place that takes in what native code answers with, and it turns
 * a failure into what the page shows the moment it arrives: the host's words and, after them, what
 * the person can do about it. The line it makes is the page's failure (`HostError`), which has no
 * member for the action, so nothing past this file can read the action, or add it a second time.
 *
 * The shape native code sends a failure in (`CommandError` in the backend) is the parameter's type,
 * written out here and named nowhere else. The function is exported for the stand-ins of native
 * code (`fake*.ts`), which build that shape and hand it through the conversion that the real
 * commands go through.
 *
 * The client library says a host's refusal as its code, a colon and the host's words. The words are
 * for the person and the code is not, so the line leaves the code out. A failure that came with no
 * words of its own is still a failure, and says so in `failureWords`' own. The line ends the words
 * with a full stop where they do not end a sentence before it adds the action.
 */
export function receivedFailure(native: {
  readonly code: string
  readonly message: string
  readonly user_action: string
  readonly retry: HostError['retry']
  readonly start_again_for?: string
}): HostError {
  const said = failureWords(native)
  const action = Object.hasOwn(ACTION_WORDS, native.user_action) ? ACTION_WORDS[native.user_action] : undefined
  const sentence = said.trimEnd()
  return {
    code: native.code,
    message: native.message,
    retry: native.retry,
    ...(native.start_again_for === undefined ? {} : { startAgainFor: native.start_again_for }),
    line: action === undefined ? said : `${sentence}${/[.!?…]$/.test(sentence) ? '' : '.'} ${action}`
  }
}

/** The shape native code sends a failure in. It is not exported: only this file holds it. */
type NativeFailure = Parameters<typeof receivedFailure>[0]

/** A call's closure as native code answers with it, before its host failure is made the page's. */
type NativeClosure = Omit<VoiceClosure, 'host_failure'> & { readonly host_failure: NativeFailure | null }

/** How contact with a host stands as native code sends it: a refusal is a native failure. */
type NativeContact =
  | Exclude<HostContact, { readonly state: 'refused' }>
  | (Omit<Extract<HostContact, { readonly state: 'refused' }>, 'refusal'> & {
      readonly state: 'refused'
      readonly refusal: NativeFailure
    })

/** The connection's state as native code sends it, before each refusal in it is made the page's. */
type NativeConnection = Omit<ConnectionState, 'contact' | 'others'> & {
  readonly contact: NativeContact
  readonly others: readonly (Omit<OtherHost, 'contact'> & { readonly contact: NativeContact })[]
}

/** What native code answers a request for the states a page missed with. */
type NativeSince = Omit<ConnectionSince, 'states'> & { readonly states: readonly NativeConnection[] }

const receivedContact = (native: NativeContact): HostContact =>
  native.state === 'refused' ? { ...native, refusal: receivedFailure(native.refusal) } : native

/**
 * A connection state as the page takes it in, from a read, a change or a replay alike: a blank
 * reason is none, and the refusal of the host in use or of another host is the page's failure, with
 * the words of what the person can do about it kept.
 */
function receivedPublication(native: NativeConnection): ConnectionState {
  return receivedConnection({
    ...native,
    contact: receivedContact(native.contact),
    others: native.others.map((other) => ({ ...other, contact: receivedContact(other.contact) }))
  })
}

/** The most host events a listener holds for a state it has not yet taken in. */
const HELD_EVENTS_MAX = 256

/** What a command rejected with: a failure in native code's shape is the page's failure from here. */
function rejected(raw: unknown): unknown {
  const native = raw as Partial<NativeFailure> | null
  return typeof native === 'object' && native !== null && typeof native.code === 'string' && typeof native.message === 'string'
    ? receivedFailure(raw as NativeFailure)
    : raw
}

/** One `invoke` of one named command, with its rejection turned into the page's failure. */
function invoking<T>(command: string, args?: InvokeArgs, options?: InvokeOptions): Promise<T> {
  return invoke<T>(command, args, options).catch((raw: unknown) => {
    throw rejected(raw)
  })
}

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

/** What the backend publishes for one host event. */
interface PublishedEvent {
  /** The environment of the host it came from. */
  readonly host?: string
  readonly stream_id: string
  readonly sequence: string
  readonly event_type: string
  readonly payload: unknown
  /** The revision of the connection state this event follows. */
  readonly revision: number
}

/** Builds the desktop port. */
export function tauriPort(): HostPort {
  // The environment of the host the connection last said it was to: undefined before it has said
  // anything, null while there is no host, as when one is being chosen. An event that names another
  // host, or one that comes while there is none, was on its way when the host changed, and is not the
  // new host's.
  let host: string | null | undefined
  // The highest revision of a connection state taken in. A state below it never moves the host back.
  let seen = 0
  // How many choices of a host were begun, and how many are out.
  let attempts = 0
  let out = 0
  /**
   * A raw event or a replayed state. One at or above the highest seen is the connection speaking,
   * and while a choice is out only a higher one is: an equal state may come from a read begun
   * before the choice, and must not put the old host back.
   */
  const observe = (state: ConnectionState): void => {
    if (state.revision < seen || (out > 0 && state.revision === seen)) return
    seen = state.revision
    host = state.environment_id
  }
  /**
   * The answer to a read or a choice that began when `at` choices had been made. It counts only while
   * that is the newest choice, and then it restores the host in use after a choice that was refused
   * or changed nothing, neither of which makes a revision.
   */
  const learned = (at: number) => (state: ConnectionState): ConnectionState => {
    if (at === attempts && state.revision >= seen) {
      seen = state.revision
      host = state.environment_id
    }
    return state
  }
  const ofThisHost = (published: { readonly host?: string }): boolean =>
    published.host === undefined || host === undefined || published.host === host
  /** The host is being chosen: nothing the old one sent is the new one's. */
  const choosing = (): number => {
    attempts += 1
    out += 1
    host = null
    return attempts
  }

  const readState = (): Promise<ConnectionState> => {
    const at = attempts
    return invoking<NativeConnection>('connection_state', {})
      .then(receivedPublication)
      .then(learned(at))
  }
  const readSince = (after: number): Promise<ConnectionSince> => {
    const was = seen
    return invoking<NativeSince>('connection_since', { after }).then((since) => {
      const states = since.states.map(receivedPublication)
      // The page was ahead of native code: native code started over, and what the page held before
      // says nothing now. Only a whole state below the one the page held needs that. One at or above
      // it is taken by the rule of `observe`, which an equal state does not pass while a choice is
      // out; and unless a state was taken in while the request was out, the whole state is older
      // than the page and takes nothing back.
      if (since.resync && seen === was && states.every((state) => state.revision < was)) seen = 0
      for (const state of states) observe(state)
      return { revision: since.revision, states, resync: since.resync }
    })
  }
  // The one feed of the connection's state: every view follows it, and a raw event is told to it only
  // after the filter of the host in use has taken it in.
  const feed = createConnectionFeed({
    read: readState,
    since: readSince,
    listen: (heard) =>
      listening<NativeConnection>(CONNECTION_EVENT, (native) => {
        const state = receivedPublication(native)
        observe(state)
        heard(state)
      })
  })

  const call = <T,>(command: string, args: Record<string, unknown>): Promise<T> =>
    invoking<T>(command, args)

  /**
   * Asks native code to use or forget a host. While it is asked, nothing of the old host is the new
   * one's. A refusal changes nothing there: the connection it kept is asked what it is, so the host
   * still in use is heard again, unless the connection has said something since.
   */
  const choose = (command: string, reference: string): Promise<ConnectionState> => {
    const at = choosing()
    return invoking<NativeConnection>(command, { reference })
      .then(receivedPublication)
      .then(learned(at))
      .catch(async (failure: unknown) => {
        await invoking<NativeConnection>('connection_state', {})
          .then(receivedPublication)
          .then(learned(at))
          .catch(() => {
            // Nothing can say which host is in use: events are taken as they come, as before any
            // host was known.
            if (attempts === at) host = undefined
          })
        throw failure
      })
      .finally(() => {
        out -= 1
      })
  }

  const read = <T,>(command: string, params: unknown): Promise<T> => call<T>(command, { params })

  /**
   * What native code answers a read of the owner's authority with: the answer under its key, or that
   * the read was superseded, which is a value of that command and fails here with the page's own
   * code and no data.
   */
  type KeyedReply<T> = { readonly key: ReadKey; readonly result: T } | { readonly key: ReadKey; readonly superseded: true }
  const keyed = async <T,>(reply: Promise<KeyedReply<T>>): Promise<Keyed<T>> => {
    const answered = await reply
    // eslint-disable-next-line @typescript-eslint/only-throw-error -- a superseded read fails as data, as a command's failure does
    if ('superseded' in answered) throw supersededRead()
    return { key: answered.key, value: answered.result }
  }

  const mutate = <T,>(
    command: string,
    params: unknown,
    subject: SessionSubject,
    extra: Record<string, unknown> = {}
  ): Promise<T> => call<T>(command, { params, subject, ...extra })

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
    connectionState: readState,
    connectionSince: readSince,
    watchConnection: feed.watch,
    onConnection: feed.onChange,
    connectionLatest: feed.latest,

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

    launchSurface: (params) => read('launch_surface', params),
    launchCommands: () => call<LaunchCommandsReading>('launch_commands_list', {}),
    launchCommandSave: (params) => mutate('launch_commands_save', params, {}),
    launchCommandRemove: (params) => mutate('launch_commands_remove', params, {}),

    // The agent's calls go to the session's own worker, which native code reaches and which checks
    // this device's rights itself. A mutation names its session, instance and binding revision in
    // its own parameters, and native code builds its envelope from exactly those.
    sessionAgents: (sessionId, opening) =>
      call<SessionAgents>('session_agents', { sessionId, opening }),
    agentCapabilities: (params, opening) => readIn('agent_capabilities', params, opening),
    agentSnapshot: (params, opening) => readIn('agent_snapshot', params, opening),
    agentCommands: (params, opening) => readIn('agent_commands', params, opening),
    approvalInspect: (params, opening) => readIn('agent_approval_inspect', params, opening),
    composerSubmit: (params, opening, supersedes, mark) =>
      call('agent_prompt_submit', { params, opening, supersedes, mark }),
    composerQueue: (params, opening, mark) =>
      call('agent_prompt_queue', { params, opening, mark }),
    composerSteer: (params, opening) => call('agent_turn_steer', { params, opening }),
    composerInterrupt: (params, opening) => call('agent_turn_cancel', { params, opening }),
    approvalRespond: (params, opening) => call('agent_approval_respond', { params, opening }),
    pluginActionInvoke: (params, opening) => call('plugin_action_invoke', { params, opening }),

    deviceDrafts: () => call('device_drafts', {}),
    deviceDraftSave: (request) => read('device_draft_save', request),
    deviceDraftRetarget: (request) => read('device_draft_retarget', request),
    deviceDraftDiscard: (request) => read('device_draft_discard', request),
    deviceDraftMarkRemoval: (request) => read('device_draft_mark_removal', request),
    deviceChannelMessages: (request) => read('device_channel_messages', request),
    deviceChannelMessageKeep: (request) => read('device_channel_message_keep', request),
    deviceChannelMessageRemove: (request) => read('device_channel_message_remove', request),
    deviceChannelHoldCreate: (request) => read('device_channel_hold_create', request),
    deviceChannelHoldUpdate: (request) => read('device_channel_hold_update', request),
    deviceChannelHoldClear: (request) => read('device_channel_hold_clear', request),
    deviceDraftsLedgerSetAside: () => call('device_drafts_ledger_set_aside', {}),
    draftCreate: (params, subject, mark) =>
      mutate<Settled>('draft_create', params, subject, { mark }),
    // The upload belongs to the same session the subject names; sending the subject without it
    // would reserve the transfer against no session while the action targeted one.
    attachmentUpload: (path, subject, mark) =>
      call<AttachmentHandle>('attachment_upload', {
        path,
        subject,
        sessionId: subject.sessionId ?? null,
        mark
      }),
    // The bytes are the call's raw body; the name and the subject travel as its two headers.
    attachmentUploadBytes: (file, subject, transferKey, mark) =>
      invoking<AttachmentHandle>('attachment_upload_bytes', file.bytes, {
        headers: {
          'kr-file-name': encodeURIComponent(file.name),
          'kr-subject': JSON.stringify(subject),
          // Over a paired host the key names the upload to `uploads_open` and `upload_cancel`.
          ...(transferKey === undefined ? {} : { 'kr-transfer-key': transferKey }),
          // The account the page acted under: native code refuses it when it is not the account's.
          ...(mark === undefined ? {} : { 'kr-mark': mark })
        }
      }),
    draftAddAttachment: (params, subject, mark) =>
      mutate<Settled>('draft_add_attachment', params, subject, { mark }),
    uploadsOpen: (mark) => call('uploads_open', { mark }),
    uploadCancel: (transferKey, mark) => call('upload_cancel', { transferKey, mark }),
    draftEnd: (subject, sessionId, mark) => call('draft_end', { subject, sessionId, mark }),
    draftSetText: (subject, sessionId, text, mark) =>
      call('draft_set_text', { subject, sessionId, text, mark }),

    historyPage: (params, opening) => readIn('history_page', params, opening),
    actionRead: (params, opening) => readIn('action_read', params, opening),
    settleAction: (params, opening) => readIn<void>('agent_action_settle', params, opening),
    // Attention and review belong to the environment, so an acknowledgement names no session.
    attentionRead: (params) => keyed(read('attention_read', params)),
    sessionNumbers: () => keyed(call('session_numbers', {})),
    attentionAcknowledge: (params) => mutate('attention_acknowledge', params, {}),
    reviewRead: (params) => read('review_read', params),
    reviewAcknowledge: (params) => mutate('review_acknowledge', params, {}),
    questionRead: (params, opening) => readIn('question_read', params, opening),
    questionAnswer: (params, opening, acknowledged) =>
      call('question_answer', { params, opening, acknowledged }),
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

    privacyStatus: () => read('privacy_status', {}),

    retainedSyncCopies: () => call('retained_sync_copies', {}),
    retainedDeleteAsk: (reference) => call('retained_delete_ask', { reference }),
    retainedDeleteFinish: (token) => call('retained_delete_finish', { token }),
    retainedDeleteCancel: (token) => call<undefined>('retained_delete_cancel', { token }),

    // Each view has a channel of its own, which native code publishes that view's states on and
    // nothing else: no protocol event and no other view's state ever reaches its listener.
    openTerminalView: async (sessionId, grid, listener, opening, anchor): Promise<TerminalView> => {
      const states = new Channel<TerminalViewState>()
      states.onmessage = listener
      const view = await call<string>('terminal_view_open', {
        sessionId,
        ...viewSizeArguments(grid),
        opening,
        anchor,
        onState: states
      })
      return {
        resize: (next) => call<undefined>('terminal_view_resize', { view, ...viewSizeArguments(next) }),
        move: (next) => call<undefined>('terminal_view_move', { view, ...viewMoveArguments(next) }),
        // The person's input goes in the shape native code reads, and nothing else is sent.
        input: (next) => call<undefined>('terminal_view_input', { view, input: next }),
        launchSurface: () => call('terminal_view_launch_surface', { view }),
        launch: (press) => call('terminal_view_launch', { view, press }),
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
        afterActionId: request.afterActionId,
        subject
      }),
    voiceScope: () => call<VoiceScope>('voice_scope', {}),
    voiceAllow: (request, subject) =>
      mutate(
        'voice_allow',
        {
          session_ids: request.sessionIds,
          actions: request.actions,
          environment_id: request.environmentId
        },
        subject
      ),
    // The host's failure to take the stop is a native failure inside the answer: the page's before it
    // leaves here.
    voiceStop: (voiceSessionId, subject) =>
      call<NativeClosure>('voice_stop', { voiceSessionId, subject }).then(
        (closure): VoiceClosure => ({
          ...closure,
          host_failure: closure.host_failure === null ? null : receivedFailure(closure.host_failure)
        })
      ),
    voiceContext: (params) => read('voice_context', params),
    voiceSetMuted: (what, muted) => call<VoiceCallState>('voice_set_muted', { what, muted }),
    voiceCallState: () => call<VoiceCallState>('voice_call_state', {}),
    voiceDismissStart: (actionId) => call<undefined>('voice_dismiss_start', { actionId }),

    hostsUse: (reference) => choose('hosts_use', reference),
    hostsForget: (reference) => choose('hosts_forget', reference),
    // A pass read its rows at a revision of the connection's state: when the feed has not reached
    // it, the feed is asked for what it is missing, so the contact the rows go with is not left.
    inboxHosts: () =>
      call<InboxHosts>('inbox_hosts', {}).then((answer) => {
        if (answer.revision > feed.appliedThrough()) feed.catchUp()
        return answer
      }),
    pushView: () => call<PushView>('push_view', {}),
    pushEnable: (reference, afterUnknown) =>
      call<PushView>('push_enable', { reference, afterUnknown }),
    pushPreviews: (reference, on) => call<PushView>('push_previews', { reference, on }),
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
    accountServices: () => call<readonly ServiceLine[]>('account_services', {}),
    accountDeletionView: () => call<DeletionViewAnswer>('account_deletion_view', {}),
    accountDeletionSendCode: () => call<DeletionSendAnswer>('account_deletion_send_code', {}),
    accountDeletionConfirm: (code, acknowledged) =>
      call<DeletionConfirmAnswer>('account_deletion_confirm', { code, acknowledged }),
    accountDeletionStatus: (following) =>
      call<DeletionStatusAnswer>('account_deletion_status', { following }),
    accountDeletionHide: () => call<DeletionStatusAnswer>('account_deletion_hide', {}),
    accountDeletionResultShown: () =>
      call<DeletionStatusAnswer>('account_deletion_result_shown', {}),
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
    recoveryCoverHost: (replace) => call<HostCoverView>('recovery_cover_host', { replace }),
    recoverySaveKitQr: (path) => call<KitSaved>('recovery_save_kit_qr', { path }),
    recoveryArchives: () => call<readonly RecoveryArchive[]>('recovery_archives', {}),
    recoveryExportOffline: (path, archive) =>
      call<ExportSaved>('recovery_export_offline', { path, archive }),

    // An event follows the connection state of its revision, and the page never shows a host's events
    // before the state that announces the host: one that is ahead of the feed is held until the feed
    // has applied its revision, and the feed is asked for what it is missing.
    subscribe: (listener: (event: HostEvent) => void) => {
      const held: PublishedEvent[] = []
      let dropped: PublishedEvent | null = null
      const pass = (published: PublishedEvent): void => {
        if (!ofThisHost(published)) return
        listener({
          stream_id: published.stream_id,
          sequence: published.sequence,
          body: { kind: published.event_type, payload: published.payload }
        })
      }
      const release = (revision: number, resynced: boolean): void => {
        const ahead = held.findIndex((each) => each.revision > revision)
        const ready = held.splice(0, resynced || ahead === -1 ? held.length : ahead)
        for (const each of ready) pass(each)
        // The events dropped at the cap are told as one, after the ones that were kept.
        if (dropped !== null && (ready.length > 0 || resynced)) {
          const lost = dropped
          dropped = null
          pass({ ...lost, stream_id: '', sequence: '', event_type: 'resync_required', payload: null })
        }
      }
      const untap = feed.onApplied(release)
      return listening<PublishedEvent>(HOST_EVENT, (published) => {
        if (held.length === 0 && published.revision <= feed.appliedThrough()) {
          pass(published)
          return
        }
        held.push(published)
        if (held.length > HELD_EVENTS_MAX) dropped = held.shift() ?? dropped
        feed.catchUp()
      }).then(
        (stop) => () => {
          untap()
          stop()
        },
        (failure: unknown) => {
          untap()
          throw failure
        }
      )
    },

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
