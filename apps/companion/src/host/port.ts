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
  ActionReadParams,
  ActionReadResult,
  ActionRight,
  AgentApprovalInspectParams,
  AgentApprovalInspectResult,
  AgentApprovalRespondParams,
  AgentApprovalRespondResult,
  AgentCancelParams,
  AgentCapabilitiesParams,
  AgentCapabilitiesResult,
  AgentCommandsParams,
  AgentCommandsResult,
  AgentInstanceList,
  AgentMutationResult,
  AgentPromptParams,
  AgentSnapshotParams,
  AgentSnapshotResult,
  AgentSteerParams,
  AttachmentSummary,
  AttentionAcknowledgeParams,
  AttentionAcknowledgeResult,
  ActionTarget,
  AttachmentHandle,
  AttentionReadParams,
  AttentionReadResult,
  AuthorityNotice,
  CapabilityChecks,
  CatalogueListParams,
  CatalogueListResult,
  CellRendition,
  ChangesetReadParams,
  ChangesetReadResult,
  ClosureRecord,
  DescriptionConfigureParams,
  DescriptionDownloadParams,
  DescriptionSetup,
  DeviceListParams,
  DeviceListResult,
  Dimensions,
  EnvironmentCapabilitiesParams,
  EnvironmentCapabilitiesResult,
  EnvironmentListResult,
  GrantCreateParams,
  GrantCreateResult,
  GrantListParams,
  GrantListResult,
  GrantRedeemParams,
  GrantRedeemResult,
  GrantRevokeParams,
  GrantTransferParams,
  GrantTransferResult,
  HeldShare,
  HistoryPageParams,
  HistoryPageResult,
  HostInfoResult,
  PaletteState,
  PendingResource,
  PluginListParams,
  PluginListResult,
  ProjectedHyperlink,
  Question,
  QuestionAnswer,
  QuestionAnswerParams,
  QuestionReadParams,
  QuestionReadResult,
  QuestionResolveResult,
  Receipt,
  ReviewAcknowledgeParams,
  ReviewAcknowledgeResult,
  ReviewReadParams,
  ReviewReadResult,
  RoleSelection,
  SessionCreateParams,
  SessionCreateResult,
  SessionDescribeParams,
  SessionDescribeResult,
  SessionListResult,
  SessionReadResult,
  SessionScreenPreviewResult,
  RevocationResult,
  ShareOffer,
  ShellLaunchResult,
  VoiceContextResult,
  VoiceAction,
  VoiceGrantResult,
  VoicePrepareResult,
  VoiceSessionDescriptor,
  VoiceStartResult,
  VoiceStopResult
} from '@kalareach/protocol'

import type { AccountView, UsageView } from '../model/account'
import type { LaunchSurface } from '../model/pending'

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
  /**
   * Why there is no connection, in plain words, when there is none. Never blank: a reason that is
   * empty or only spaces says nothing, so the page takes it in as null (`receivedConnection`), and a
   * reader's own words for a loss with no reason show in its place.
   */
  readonly reason: string | null
  /**
   * What this connection may do, while it is live, or null when native code has not said. The
   * host checks every right again when an action arrives; this is what a control's visibility is
   * decided from.
   */
  readonly rights: readonly ActionRight[] | null
  /**
   * True while the live connection is to a host this device is paired with, and false for the host
   * on this computer and when there is no connection. A file this application sends goes to the host
   * on this computer; a host this device is paired with takes no file from it, so no file is offered
   * over one.
   */
  readonly paired: boolean
}

/**
 * A connection state as the page takes it in: a blank reason is no reason.
 *
 * Every state a port hands the page, read or heard, passes through here, so a reader tells a
 * reason from its absence by null alone. A reason with words is kept exactly as it was sent.
 */
export function receivedConnection(sent: ConnectionState): ConnectionState {
  const words = sent.reason?.trim() ?? ''
  return { ...sent, reason: words.length > 0 ? sent.reason : null }
}

/**
 * What a session screen is told of the opening it holds.
 *
 * A screen opens its session under one grant, and the host says what that grant allows. On the host
 * on this computer the application is the owner and every right is held. On a host this device is
 * paired with, `open` carries the host's own decision, `ended` says the share the screen runs under
 * is over, and `refused` says the host would not open or keep the session, in its own words.
 * `reconnecting` is contact lost without the grant ending, and is being taken up again.
 */
export type SessionStanding =
  | {
      readonly state: 'open'
      /** Whether the screen runs under this computer's ownership, the pairing, or a share. */
      readonly via: 'owner' | 'pairing' | 'share'
      readonly grant_id: string
      /** What the host lets this screen do. */
      readonly actions: readonly ActionRight[]
      /** Whether the grant includes the session's live screen. */
      readonly includes_live_screen: boolean
      /** How far back the grant's history reaches, in UTC milliseconds, when it reaches back. */
      readonly history_from_ms: number | null
      /** When the grant is scheduled to end, in UTC milliseconds, when it ends. */
      readonly ends_at_ms: number | null
    }
  | { readonly state: 'ended'; readonly reason: 'revoked' | 'expired' }
  | { readonly state: 'closed' }
  | { readonly state: 'refused'; readonly code: string; readonly message: string }
  | { readonly state: 'reconnecting'; readonly reason: string }
  | { readonly state: 'superseded' }

/** One change of an opened session's standing, as native code publishes it. */
export interface StandingEvent {
  readonly session_id: string
  /** The opening it belongs to. A screen applies it only when this is the opening it holds. */
  readonly opening: string
  readonly standing: SessionStanding
}

/** What a screen asks for to open a session. */
export interface OpenRequest {
  readonly sessionId: string
  /** The share the screen runs under, or null for the pairing. */
  readonly grantId: string | null
  /** The screen's own token for this opening: up to 64 letters, digits and dashes, used once. */
  readonly opening: string
}

/* ---- First-start setup ------------------------------------------------------------------------
 *
 * Three additions, and they are all reads. Setup is where a person is guided through permissions
 * the operating system grants and this application cannot, so nothing here grants, enables or
 * writes anything: it reads what may be done on this desktop, reads the identity a grant would be
 * recorded against, and opens a settings pane the person asked for.
 */

/** The identity an operating system would record a permission against. */
export interface SetupIdentity {
  /** The bundle identifier this build declares, which is what a grant is filed under. */
  readonly application_id: string
  /** The version this build declares. */
  readonly application_version: string
  /** The executable this application is running from. */
  readonly executable: string | null
  /** Whether that executable sits inside an application bundle. */
  readonly bundled: boolean
  /** The signing identity on that executable, as the platform's own tool names it. */
  readonly signature: SigningIdentity
  /** Whether the identity is the same on the next launch. */
  readonly stable: boolean
  /** Why it is not, when it is not. */
  readonly instability: string | null
  /** What this check did not establish, always stated. */
  readonly unverified: string
  /** The host build this application is in contact with, where there is one. */
  readonly helper_build: string | null
  /** The environment that host owns. */
  readonly helper_environment: string | null
}

/** The signature on the application, as the platform reports it. */
export interface SigningIdentity {
  /** Whether the platform read a signature at all. */
  readonly read: boolean
  /** The authority that signed it, where there is one. Absent for an ad-hoc signature. */
  readonly authority: string | null
  /** The team the signature belongs to, where it carries one. */
  readonly team: string | null
  /** The identifier the signature seals, which is what a grant is filed under. */
  readonly identifier: string | null
  /** Whether the signature is ad-hoc: one this machine made, that nothing else can vouch for. */
  readonly ad_hoc: boolean
  /** Whether the platform verified the signature against what it seals, rather than only read it. */
  readonly valid: boolean
  /** What the platform said, where it would not answer. */
  readonly refusal: string | null
}

/** One settings pane this application will open, by name. */
export interface SettingsPane {
  /** The name the interface asks for. */
  readonly id: string
  /** Where the person is going, in the platform's own words. */
  readonly route: string
  /** The address the platform opens that pane with. */
  readonly url: string
}

/* ---- Pairing ------------------------------------------------------------------------------------
 *
 * This computer pairs with a host in native code. The page types a code or presses a button, and
 * is told where the attempt has got to: never an invitation's text, a secret, a key, a transcript,
 * a challenge or a proof. The one secret the page holds is a code a person types into its field.
 */

/** The service codes go through. */
export interface PairingOrigin {
  readonly origin: string
  readonly host: string
  readonly is_default: boolean
}

/* ---- Sync service and recovery -------------------------------------------------------------------
 *
 * The sync service is a choice of its own: the managed service until the person picks another. Recovery
 * keeps an encrypted bundle on it, with the account's sign-in beside this device's signature, and
 * a kit the person keeps. The seed, the locator and the token stay in native code: the page is
 * told where recovery stands and what stops the next step, and a kit is written by native code to
 * a destination the platform's save dialog returned.
 */

/** The sync service this computer is set to use. */
export interface SyncServiceView {
  readonly origin: string
  readonly host: string
  readonly is_default: boolean
}

/** Where recovery stands on this computer. */
export type RecoveryState = 'off' | 'unfinished' | 'on' | 'unsettled'

/** What stops the next step of recovery, and so what the person is asked to mend. */
export type RecoveryBlocker =
  | { readonly reason: 'signed_out' }
  | { readonly reason: 'needs_sign_in' }
  | {
      readonly reason: 'wrong_service'
      /** The sync service the setting names. */
      readonly sync_service: string
      /** The service the account is signed in to. */
      readonly account: string
    }

/** Everything the recovery section shows. */
export interface RecoveryView {
  readonly sync_service: SyncServiceView
  readonly state: RecoveryState
  /** The host of the service the bundle is kept at, once recovery has been turned on. */
  readonly kept_at: string | null
  readonly blocker: RecoveryBlocker | null
}

/** Where a recovery kit was written. */
export interface KitSaved {
  readonly path: string
}

/* ---- The person's settings -----------------------------------------------------------------------
 *
 * Native code keeps the settings in a file on this computer and is their one source: the page holds
 * no copy of its own, asks for a change and is told what stands. Settings sync keeps the same
 * settings, sealed, at the sync service so the person's other devices find them. It is off until the
 * person turns it on. The key, the identities and the content other devices wrote stay in native
 * code; the page is told how many copies wait for a choice.
 */

/** How the window is coloured: light, dark, or whatever the device is set to. */
export type ColourMode = 'light' | 'dark' | 'system'

/** Where settings sync stands on this computer. */
export type SettingsSyncState = 'off' | 'starting' | 'on'

/** What the page is shown of settings sync. */
export interface SettingsSyncView {
  readonly state: SettingsSyncState
  /** The sync service a collection started now would be kept at, when this computer can sync. */
  readonly service: SyncServiceView | null
  /** The host of the service the collection is kept at, once it was started. */
  readonly kept_at: string | null
  /** How many writes left this computer and have no answer yet. */
  readonly outstanding: number
  /** How many copies of other devices' settings wait for the person to choose. */
  readonly conflicts: number
  /** Whether privacy mode has stopped sync from sending. */
  readonly paused: boolean
  /** What the last step could not do, in words, until a step succeeds. */
  readonly problem: string | null
  /** Drafts, which travel in the same collection once the person asks for that. */
  readonly drafts: DraftsSyncView
  /** Who shares the settings, and who could. */
  readonly devices: DevicesView
}

/** A device that holds the key of the shared settings. */
export interface DeviceMember {
  /** What a command names it by. It is not a key. */
  readonly reference: string
  /** What the person's hosts call it. */
  readonly name: string
  readonly this_computer: boolean
  /** Whether a host still lists it as able to manage the host. */
  readonly vouched: boolean
}

/** A device a host lists that could be given the key. */
export interface DeviceCandidate {
  readonly reference: string
  readonly name: string
}

/** Settings another of the person's devices shares, which this computer could join. */
export interface DeviceOffer {
  readonly reference: string
  /** What the device that shares it is called, when a host lists it. */
  readonly name: string | null
}

/** What became of a change the person asked for or a host required. */
export interface DeviceHappened {
  readonly what: 'addition' | 'removal' | 'join'
  readonly ended: 'done' | 'cancelled' | 'refused'
  readonly name: string | null
}

/** What the page is shown of who shares the settings. */
export interface DevicesView {
  /** Whether this computer can ask the person to confirm. Without it nothing is added or joined. */
  readonly can_confirm: boolean
  /** Whether this computer was taken out of the shared settings. */
  readonly out: boolean
  /** Whether the shared settings wait to be sealed again by another device, for this computer. */
  readonly waiting: boolean
  readonly members: readonly DeviceMember[]
  readonly candidates: readonly DeviceCandidate[]
  readonly offers: readonly DeviceOffer[]
  readonly outcomes: readonly DeviceHappened[]
}

/** Why drafts are kept on this computer and not sent. */
export type DraftsKeptWhy = 'private' | 'unreadable' | 'unknown_host' | 'too_large'

/** Drafts kept on this computer and not sent, for one reason. */
export interface KeptDrafts {
  /** What the host is called, when the host is known and has a name. */
  readonly host: string | null
  readonly why: DraftsKeptWhy
  /** When this computer could not read a host's privacy mode: what it said. */
  readonly detail: string | null
  readonly drafts: number
}

/** What the page is shown of keeping drafts in step. */
export interface DraftsSyncView {
  /** Whether the person turned it on. */
  readonly enabled: boolean
  /** The drafts kept on this computer and not sent, with why. */
  readonly kept_here: readonly KeptDrafts[]
  /** What the last step could not do, in words, until a step succeeds. */
  readonly problem: string | null
  /** How many drafts of other devices have been brought down since the application started. */
  readonly arrivals: number
}

/** One version of the settings the person is asked to choose between. */
export interface SettingsVersion {
  /** The colour mode it holds, or null when it holds one this version cannot show. */
  readonly colour_mode: ColourMode | null
  /**
   * When the device that wrote it recorded it, in UTC milliseconds. It is shown and decides
   * nothing: no version is kept, or offered first, for being later.
   */
  readonly updated_at_ms: number
}

/** A version another device wrote, named so a choice can name it. */
export interface SettingsOtherVersion extends SettingsVersion {
  readonly conflict_id: string
}

/** What the person chooses between when two devices changed the same setting. */
export interface SettingsChoice {
  /** This device's own settings. */
  readonly mine: SettingsVersion
  /** Each version another device wrote, in the order this device received them. */
  readonly others: readonly SettingsOtherVersion[]
}

/** The version the person keeps: this device's own, or one another device wrote. */
export type SettingsKeep =
  | { readonly choice: 'mine' }
  | { readonly choice: 'copy'; readonly conflict_id: string }

/** The person's settings, and where keeping them in step with their other devices stands. */
export interface SettingsView {
  readonly colour_mode: ColourMode
  readonly sync: SettingsSyncView
}

/** Which of the outcomes a person is told apart an attempt ended with. */
export type FailureKind =
  | 'malformed'
  | 'device_tries_used'
  | 'service_unreachable'
  | 'service_not_pairing'
  | 'no_host_answered'
  | 'not_authenticated'
  | 'host_tries_used'
  | 'expired'
  | 'timed_out'
  | 'did_not_finish'
  | 'declined'
  | 'withdrawn'
  | 'host_restarted'
  | 'another_device_waiting'
  | 'host_unreachable'
  | 'relay_capacity'
  | 'host_mismatch'
  | 'already_paired'
  | 'not_an_invitation'
  | 'newer_invitation'
  | 'nothing_to_paste'
  | 'store_failed'
  | 'approval_unknown'

/** How an attempt ended, with the tries this computer has left when it was charged. */
export interface PairingFailure {
  readonly kind: FailureKind
  readonly tries_left: number | null
}

/** What a paired host is shown as. */
export interface PairedHostView {
  readonly name: string | null
  readonly owner: boolean
  /** What this computer may do there, in words. */
  readonly authority: string
  readonly grant_expires_at_ms: number | null
}

/** Where an attempt has got to. */
export type AttemptState =
  | { readonly state: 'idle' }
  | {
      readonly state: 'working'
      readonly stage: 'reaching_service' | 'checking_code' | 'reaching_host'
    }
  | {
      readonly state: 'awaiting_approval'
      readonly value: string
      readonly expires_at_ms: number | null
      readonly rights: readonly string[]
      /** What those rights would let this computer do, in words. */
      readonly authority: string
      readonly grant_expires_at_ms: number | null
    }
  | {
      readonly state: 'reconnecting'
      readonly value: string | null
      readonly expires_at_ms: number | null
    }
  | { readonly state: 'paired'; readonly host: PairedHostView }
  | {
      readonly state: 'ended'
      readonly failure: PairingFailure
      /** How the attempt was made: a direct invitation is tried again only by pasting it again. */
      readonly mode: 'code' | 'direct'
      /** The service a code attempt went through, which its failures name, when known. */
      readonly service: string | null
    }

/** What a person is shown of an invitation read from the pasteboard. */
export interface InvitationSummary {
  readonly mode: 'code' | 'direct'
  readonly origin_host: string | null
  readonly names_another_origin: boolean
  readonly rights: readonly string[] | null
  /** What a direct invitation's rights would let this computer do, in words. */
  readonly authority: string | null
  readonly grant_expires_at_ms: number | null
  readonly expires_at_ms: number | null
}

/** One host this computer is paired with. */
export interface HostRow {
  /**
   * What this application names the host by when it is asked to use it. It is made by native code,
   * and says nothing of the host's identity.
   */
  readonly reference: string
  /** True when this application's commands go to this host now. */
  readonly in_use: boolean
  readonly name: string
  readonly owner: boolean
  /** What this computer may do there, in words. */
  readonly authority: string
  readonly grant_expires_at_ms: number | null
  readonly in_contact: boolean | null
}

/** Everything the pairing screen shows. */
export interface PairingView {
  readonly origin: PairingOrigin
  readonly device_name: string
  readonly state: AttemptState
  readonly invitation: InvitationSummary | null
  readonly hosts: readonly HostRow[]
}

/**
 * What stands where the pairing screen would be when this device's pairing records are still not
 * open at a try made after the start: the words native code says, which replace the ones the page
 * holds.
 */
export interface PairingUnavailable {
  readonly unavailable: string
}

/** What reading the pasteboard found. */
export interface PasteView {
  readonly invitation: InvitationSummary | null
  readonly failure: FailureKind | null
  readonly cleared: boolean
  readonly declined: boolean
}

/** The ceremony this computer offers an owner. */
export type CeremonyKind = 'touch_id' | 'password' | 'windows_hello' | 'none'

/** One fact a confirmation names: what it is, and its exact value. */
export interface ConfirmationFact {
  readonly label: string
  readonly value: string
  /** True for an address, a hash or a list of identifiers, which is read character by character. */
  readonly code: boolean
}

/** One confirmation a host this computer owns asks for. */
export interface ConfirmationRequest {
  readonly reference: string
  readonly host_name: string
  readonly title: string
  readonly detail: string | null
  readonly value: string | null
  /** Everything the confirmation covers beyond the sentence, one fact to a line. */
  readonly facts: readonly ConfirmationFact[]
  /**
   * What the host says in its own words about what the request would grant: a notice for each
   * capability it describes, code placed outside the plugin sandbox and a command that starts
   * differently.
   */
  readonly notice: string | null
  /** What the publisher says in its own words about the release, quoted apart from the host's. */
  readonly statement: string | null
  /**
   * What the host reads of the release's command integration, exactly, where the request would
   * grant one. It is the host's, captioned apart from the publisher's words.
   */
  readonly reading: string | null
  readonly expires_at_ms: number
  readonly checkable: boolean
}

/** The confirmations this computer's hosts ask for. */
export interface OwnerView {
  readonly ceremony: CeremonyKind
  readonly requests: readonly ConfirmationRequest[]
}

/**
 * How a review ended. `unknown` is an answer the host was sent and never acknowledged: it may have
 * taken it, and whether it did shows in what it lists next.
 */
export type ReviewOutcome =
  | 'confirmed'
  | 'not_confirmed'
  | 'expired'
  | 'cannot_check'
  | 'no_ceremony'
  | 'unknown'

/* ---- Revoking a device -------------------------------------------------------------------------
 *
 * A computer that owns a host lists its devices and revokes one. The host on this computer takes the
 * revocation from native code at once; any other host is reached through its authority feed, which
 * the host reads and answers in. The page names a host and a device by references native code gave
 * it, and a revocation is done only once the host's acknowledgement has been read.
 */

/** How a revocation request reaches a host. */
export type RevocationRoute = 'direct' | 'feed'

/** Whether a host listed its devices when asked just now. */
export type RevocationContact = 'answered' | 'refused' | 'silent'

/** Why a host refused a request. */
export type RevocationRefusal = 'no_owner_authority' | 'unknown_target' | 'superseded'

/**
 * Where one device's revocation stands. Only `done` is a revocation carried out: the host
 * acknowledged it and every session confirmed it.
 */
export type RevocationStanding =
  | { readonly state: 'active' }
  | { readonly state: 'revoked' }
  | { readonly state: 'sent'; readonly at_ms: number; readonly host_lists_revoked: boolean }
  | {
      readonly state: 'acknowledged'
      readonly at_ms: number
      readonly pending_workers: number | null
      /** Whether the host's own list shows the device as revoked. A host that acknowledged and does not contradicts its feed. */
      readonly host_lists_revoked: boolean
    }
  | { readonly state: 'done'; readonly at_ms: number }
  | { readonly state: 'refused'; readonly reason: RevocationRefusal }

/** What a host's feed holds of its last acknowledgement. */
export interface RevocationAcknowledged {
  readonly at_ms: number
  readonly revision: number
  readonly pending_workers: number | null
}

/** A host's feed, as this computer read it. */
export interface RevocationFeed {
  readonly read: boolean
  readonly problem: string | null
  /** The feed answers that it removed the host: nothing published there reaches it. */
  readonly removed: boolean
  /** Whether the host has written anything in this feed. */
  readonly host_wrote_here: boolean
  readonly last_acknowledgement: RevocationAcknowledged | null
  readonly outstanding: number
  /** How often a host reads its feed while it is online, in seconds. */
  readonly poll_interval_seconds: number | null
}

/** One device of a host. */
export interface RevocationDevice {
  readonly reference: string
  readonly name: string
  readonly platform: 'macos' | 'windows' | 'linux' | 'ios' | 'android'
  /** Whether it holds the right to manage the host. */
  readonly manages_host: boolean
  /** Whether it is this computer, which does not revoke itself. */
  readonly this_computer: boolean
  readonly standing: RevocationStanding
  /**
   * When the feed last said the standing, in UTC milliseconds, for a standing native code keeps
   * from an earlier read because it could not read the feed this time. Null for one read now.
   */
  readonly stale_since_ms: number | null
}

/** One host this computer can revoke devices on. */
export interface RevocationHost {
  readonly reference: string
  readonly name: string
  readonly route: RevocationRoute
  readonly contact: RevocationContact
  /** When the devices below were listed, in UTC milliseconds. */
  readonly listed_at_ms: number | null
  /** When the host says it last read its feed, in UTC milliseconds. */
  readonly host_synchronised_at_ms: number | null
  /** Whether the host says it could not reach its feed at its last attempt. */
  readonly host_feed_stale: boolean
  readonly devices: readonly RevocationDevice[]
  /** The host's feed, for a host reached through one. */
  readonly feed: RevocationFeed | null
}

/** Every host this computer can revoke devices on. */
export interface RevocationView {
  /** The ceremony this computer offers, which names the revoke button. */
  readonly ceremony: CeremonyKind
  /** The service a request for a paired host is published at; null when there is none to publish at. */
  readonly feed_origin: string | null
  readonly hosts: readonly RevocationHost[]
}

/* ---- Voice ------------------------------------------------------------------------------------
 *
 * The page drives a voice call and never carries one. Section 15 ¶2 puts capture, playback and the
 * media path in native code, so what crosses this boundary is a request and an answer: the page
 * asks for a call, the native side makes the offer, sends it to the host and applies what comes
 * back, and the page is told what happened. A screen that held a peer connection would be the
 * `getUserMedia` path that paragraph forbids, wearing a different name.
 */

/** What the page asks for when it starts a call. */
export interface VoiceStartRequest {
  /** The sessions the call may reach, as the preparation the person was shown answered them. */
  readonly sessionIds: readonly string[]
  /**
   * The preparation the person was shown, as the host answered it. The host refuses a start whose
   * preparation no longer describes what the call would reach, do or be carried by.
   */
  readonly prepared: string
  /** Seconds of call to ask the service to authorise. */
  readonly durationSeconds: number
  /** Minor units to hold for reasoning and tools, or null to ask for none. */
  readonly reasoningBudgetMinor: string | null
  /**
   * The version of the managed rate the person was shown, as the host's preparation answered it.
   *
   * A start names it so the call runs under the terms the person saw. The service refuses a
   * version that is no longer current, and the answer carries the rate as it is now.
   */
  readonly expectedRateVersion: string
}

/** One action a voice grant permits by default, as the person is shown it before allowing it. */
export interface VoiceScopeAction {
  readonly action: VoiceAction
  /** The sentence the protocol states the action in. */
  readonly sentence: string
  /** True when using it still takes a confirmation on an unlocked screen every time. */
  readonly needs_unlocked_screen: boolean
}

/** What allowing voice on this device permits when the person chooses nothing further. */
export interface VoiceScope {
  readonly actions: readonly VoiceScopeAction[]
}

/**
 * What allowing voice came to: the sentences the grant states, what it could not carry, and what
 * the answer showed of the fence that replacing the grant owed. The device the grant is for is not
 * in it; native code holds that identity.
 */
export interface VoiceAllowed {
  readonly statement: VoiceGrantResult['statement']
  /** The actions asked for that this device's own access to the host does not include. */
  readonly not_held_by_device: readonly VoiceAction[]
  /**
   * The workers' status for the calls the replacement ended, read as a stop's is: that it owed no
   * fence, the barrier as the host's wait for it left it (without the names of the actions the
   * fence named; a worker still `pending` may yet take up what one of those calls sent), or that
   * the answer gave no status this build could read.
   */
  readonly fence: VoiceFence
}

/** What the page asks when the person allows voice for some of a host's sessions. */
export interface VoiceAllowRequest {
  /** The sessions a call may reach. A call is bound to sessions the grant names. */
  readonly sessionIds: readonly string[]
  /** The actions to permit, or null for the default scope. */
  readonly actions: readonly VoiceAction[] | null
}

/** Which of the two local silences a control acts on. */
export type VoiceMute = 'microphone' | 'playback'

/**
 * What the native call is doing, as the local side alone can report it.
 *
 * Every field here is read from the call this device is holding, so it stays true when nothing can
 * be reached: KR-REQ-15.17 keeps local mute and closure working when the broker fails, and a
 * screen that learned its own mute state from a service would lose it at exactly the moment it
 * matters.
 */
export interface VoiceCallState {
  /** Whether this device is holding a call that is permitted. */
  readonly running: boolean
  /**
   * Whether this device holds a call that does not run: one being set up, before the host has said
   * whether it made it too, or one being given up. There may be no call to name yet, and it can be
   * ended without naming it.
   */
  readonly setting_up: boolean
  /** Whether what the device holds is being ended, so that nothing more can be asked of it. */
  readonly ending: boolean
  /** What the microphone is doing, in the native layer's own vocabulary. */
  readonly capture: string
  /** Whether the model's voice is coming out of this device. */
  readonly playing: boolean
  /**
   * The call's own control channel to the voice service: `none` when it holds none, `connected`,
   * or `unreachable`. Whether the voice service is answering is read from here and nowhere else.
   */
  readonly control: string
  /**
   * Whether the host the call belongs to is being reached: `none` with no call, `reachable`, or
   * `lost`. A different fact from this application's own connection, which follows the host the
   * person chose to browse.
   */
  readonly host: string
  /**
   * The call, as the host described it without the provider's answer. Present while the call runs
   * and while it is being set up, which is what a screen that was loaded again finds a call by.
   */
  readonly session: VoiceSessionDescriptor | null
  /** How the last call ended, until another starts. */
  readonly ended: VoiceEnded | null
  /** The delegations the provider announced, and what this version did with each. */
  readonly delegations: readonly VoiceDelegationRow[]
  /** What a person is told before starting, from what the last call showed. */
  readonly warning: string | null
  /**
   * What this device could not finish and the host may still hold open, until the moment the call
   * would have closed. It outlives the call that left it.
   */
  readonly owed: readonly VoiceOwed[]
}

/** What the host did about the end of a call, kept apart from what happened on this device. */
export type VoiceHostEnd =
  | { readonly kind: 'revoked'; readonly fence: VoiceFence; readonly broker_notified: boolean }
  | { readonly kind: 'not_held'; readonly words: string }
  | { readonly kind: 'refused'; readonly words: string }
  | { readonly kind: 'not_told'; readonly words: string }
  | { readonly kind: 'not_needed' }

/** How a call ended. */
export interface VoiceEnded {
  /** Why, as a word the screen branches on. */
  readonly cause: string
  /** Why, in words for a person. */
  readonly words: string
  /** Whether the call's media was stopped on this device. */
  readonly closed_locally: boolean
  /** What the host did. */
  readonly host: VoiceHostEnd
  /**
   * What the voice service did: `pending` while its closure is awaited, then `closed`,
   * `closed_by_service`, `closed_by_host`, `closed_over_http` or `not_confirmed`; `unknown` when
   * the host never said whether it made a call, so the service may hold one this device cannot
   * name; `not_needed` when the host never created a call.
   */
  readonly broker: string
}

/** A delegation the provider announced, and the answer this version gives it. */
export interface VoiceDelegationRow {
  /** The provider's identifier. Correlation data, never authority. */
  readonly delegation_id: string
  /**
   * Where in the call it happened, in milliseconds from its start, or null when the voice service
   * did not say: a delegation listed when the control attached.
   */
  readonly offset_ms: number | null
  /** What became of it: always `not_done` in this version, which acts on no spoken request. */
  readonly state: string
  /** Whether the model was told so. */
  readonly told: boolean
}

/** Something this device could not finish, which the host may still hold open. */
export interface VoiceOwed {
  /** `revocation` when a call's grant may still be live; `start_unknown` for a start never answered. */
  readonly kind: string
  /** What a person is told. */
  readonly words: string
  /** The action a start was sent under, for `start_unknown`. */
  readonly action_id: string | null
  /** The call whose grant may be live, for `revocation`. */
  readonly voice_session_id: string | null
  /** The moment the grant ends by itself, in milliseconds since the epoch. */
  readonly until_ms: number
  /** What the list of hosts names the host this is owed to by. */
  readonly host_reference: string
  /** The name the host gives people. */
  readonly host_name: string
}

/**
 * What the host's answer to ending a call showed of the fence its withdrawal owed: that it owed
 * none (`not_owed`, the word native code gives it), the barrier of the workers it waited for
 * (without the names of the actions the fence named), or that the answer gave no status this build
 * could read, so whether every worker holds the revision that refuses what the call sent is not
 * known here. The grant is revoked in each. A page that meets a kind it does not know reads it as
 * `unreadable`, never as `not_owed`.
 */
export type VoiceFence =
  | { readonly kind: 'not_owed' }
  | { readonly kind: 'barrier'; readonly barrier: NonNullable<VoiceStopResult['barrier']> }
  | { readonly kind: 'unreadable' }

/** What ending a call did, locally and on the host. */
export interface VoiceClosure {
  /** Whether this device's own call was closed. True whenever a call was running. */
  readonly closed_locally: boolean
  /**
   * What the host's answer showed of its fence, or null when there was no answer to read: the host
   * could not be told, or its answer was not one to a stop.
   */
  readonly fence: VoiceFence | null
  /** Why the host could not be told or its answer not read, when it could not. */
  readonly host_failure: HostError | null
  /**
   * Whether the host answered that it holds no call of this device by that name. A stop from this
   * device can end nothing more there; the answer says nothing of a grant or of the workers' fence.
   */
  readonly not_held: boolean
}

/** A link the backend is willing to open. */
export interface ApprovedLink {
  readonly scheme: string
  readonly url: string
  readonly host: string | null
}

/** A completed, verified attachment, as `upload.finish` published it. */
export type { AttachmentHandle }

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

/** What a person's answer to a question came to. */
export type AnswerOutcome =
  /**
   * The worker took it. `leftover` is true when an answer kept earlier for the question could not
   * be removed afterwards; it stays kept, and is never sent again.
   */
  | {
      readonly outcome: 'taken'
      readonly resolution: QuestionResolveResult
      readonly leftover: boolean
    }
  /** The host did not confirm that it took it, so a copy is kept on this device. */
  | { readonly outcome: 'kept'; readonly draft: KeptAnswer }

/** Whether a stored draft still goes where it was written for, or waits for a person's choice. */
export type StoredMark = 'open' | 'conflicted' | 'orphaned'

/** A draft as this device's store keeps it. */
export interface StoredDraft {
  readonly id: string
  /** The version of it that the next save names. */
  readonly revision: string
  readonly sessionId: string
  readonly applicationInstanceId: string | null
  readonly agentBindingRevision: string | null
  readonly state: StoredMark
  readonly text: string
  /** The completed uploads on it, without their previews. */
  readonly attachments: readonly AttachmentHandle[]
  /** The draft this one was kept beside: when two windows changed the same draft, or when another device wrote it. */
  readonly copyOf: string | null
  /** True when the copy is another device's draft, brought down. */
  readonly fromAnotherDevice?: boolean
  readonly createdAtMs: string
  readonly updatedAtMs: string
}

/** The drafts of the store, and how many of its files could not be read. */
export interface StoredDrafts {
  readonly drafts: readonly StoredDraft[]
  readonly unreadable: number
  /** The removals an earlier run began and could not finish, each naming the version to remove. */
  readonly pendingRemovals: readonly DraftDiscardRequest[]
}

/** A save: a new draft when `id` is null, else a replacement of the version `expectedRevision`. */
export interface DraftSaveRequest {
  readonly id: string | null
  readonly expectedRevision: string | null
  readonly sessionId: string
  readonly applicationInstanceId: string | null
  readonly agentBindingRevision: string | null
  readonly state: StoredMark
  readonly text: string
  readonly attachments: readonly AttachmentHandle[]
}

/** What a save did: kept the draft, or kept this window's version as a copy beside another's. */
export interface DraftSaved {
  readonly outcome: 'stored' | 'copied'
  /** For a copy, the draft it sits beside. */
  readonly of: string | null
  /** The draft as stored: the one saved, or the copy. */
  readonly draft: StoredDraft
}

/** A retarget of the version `expectedRevision` of a draft. */
export interface DraftRetargetRequest {
  readonly id: string
  readonly expectedRevision: string
  readonly sessionId: string
  readonly applicationInstanceId: string | null
  readonly agentBindingRevision: string | null
}

/** A discard of the version `expectedRevision` of a draft. */
export interface DraftDiscardRequest {
  readonly id: string
  readonly expectedRevision: string
}

/** One answer a person gave that the host did not confirm it took. */
export interface KeptAnswer {
  /** Where the answer goes. */
  readonly target: ActionTarget
  readonly session_id: string
  readonly question_id: string
  /** The revision of the question the person was shown. */
  readonly question_revision: string
  readonly answer: QuestionAnswer
  /** When it was given, which names this copy of the answer among any kept for the question. */
  readonly drafted_at_ms: string
}

/** Where a kept answer stands against its question. */
export type Standing =
  /** The question is pending at the revision the person answered, so the answer can be sent. */
  | { readonly standing: 'offered' }
  /** The session lists no such question, and nothing says the session ended. */
  | { readonly standing: 'unlisted' }
  /** The question ended while the answer was kept. */
  | { readonly standing: 'ended'; readonly state: Question['state'] }
  /** The question is pending at a revision the person was not shown. */
  | { readonly standing: 'moved'; readonly revision: string }
  /** The session ended, and the question with it. */
  | { readonly standing: 'gone' }

/** A kept answer, the question as the worker lists it now when it does, and where it stands. */
export type SettledAnswer = {
  readonly draft: KeptAnswer
  readonly question: Question | null
} & Standing

/** The answers kept on this device, and how many environments' answers could not be read. */
export interface KeptAnswerList {
  readonly answers: readonly KeptAnswer[]
  readonly unreadable: number
}

/** Names one kept answer, as the person was shown it. */
export interface KeptRef {
  readonly questionId: string
  readonly draftedAtMs: string
}

/** The largest file the page may hand native code as bytes, as native code bounds it. */
export const MAX_HANDED_BYTES = 64 * 1024 * 1024

/** A file the platform gave the page: the name it came with, and its bytes. */
export interface HandedFile {
  readonly name: string
  readonly bytes: Uint8Array
}

/** A session's live agent instances, and every request its agents' broker is still arbitrating. */
export interface SessionAgents {
  readonly instances: AgentInstanceList
  readonly resources: readonly PendingResource[]
}

/** What an invitation would carry, in the host's own terms and words. */
export interface GrantNotices {
  /** The actions its role and choices compile to. The host authorises from these, never a role. */
  readonly actions: readonly ActionRight[]
  /** Every notice those actions carry, with the one sentence that states it. */
  readonly notices: readonly { readonly notice: AuthorityNotice; readonly sentence: string }[]
}

/** What an attempt to share, accept, take back or hand over does. */
export type AttemptKind = 'invite' | 'redeem' | 'revoke' | 'transfer'

/** Where an attempt stands. */
export type AttemptPhase = 'asking' | 'composed' | 'unfinished' | 'checking' | 'closed'

/** How an attempt ended. */
export type AttemptOutcome =
  | 'happened'
  | 'refused'
  | 'not_done'
  | 'not_accepted'
  | 'had_ended'
  | 'unknown'

/**
 * One attempt to share, accept, take back or hand over, as native code keeps it.
 *
 * The record exists from before the request is sent until the page removes it, and survives a
 * restart, so an action whose answer was lost is still one the person can ask the host about.
 */
export interface AttemptView {
  /** The action, which names the attempt. */
  readonly action_id: string
  readonly kind: AttemptKind
  readonly phase: AttemptPhase
  /** How it ended, once it has. */
  readonly outcome: AttemptOutcome | null
  /** One line that says what it was. */
  readonly label: string
  /** Whether the person hid it. Hiding releases nothing. */
  readonly hidden: boolean
  /**
   * Whether it closed with something still owed to the person that the host's result carries (the
   * screen the host kept with a live invitation, how far the workers have got with a revocation),
   * and the host can be asked for it until the record is removed.
   */
  readonly follow_up: boolean
  readonly session_id: string | null
  /** The device invited, or the one that receives control. */
  readonly device_id: string | null
  /** The grant it writes, revokes or accepts. */
  readonly grant_id: string | null
  /** The grant it takes away: the one a revocation names, the one a hand-over gives up. */
  readonly revoked_grant_id: string | null
  /** When it was composed, by this computer's clock. For display only. */
  readonly composed_at_ms: string
  /**
   * The earliest moment, by this computer's clock, at which a read of the host that finds nothing
   * can close it. Null once it is over, and once that moment has passed without an answer: the
   * attempt can then be asked about, and nothing says until when it might still happen.
   */
  readonly can_happen_until_ms: string | null
  /** How many times the host has been asked again. */
  readonly repeats: number
  /**
   * What the host said when it refused, or could not say what became of the request, in its words,
   * while that is known.
   */
  readonly refusal: string | null
  /**
   * The host's result, in the method's own shape, for an attempt that was carried on after the
   * command that sent it returned and ended with the result. Null after a restart.
   */
  readonly result: unknown
}

/** What a command that sends one of the four actions answers with. */
export interface Attempted<T = unknown> {
  readonly attempt: AttemptView
  /** The host's own result, when the host gave it. */
  readonly value: T | null
}

/** The attempts kept for the host this application is connected to. */
export interface Attempts {
  readonly attempts: readonly AttemptView[]
  /** Files the application keeps that this build does not read. They are never changed. */
  readonly unreadable: number
}

/** What the sheet is told once the host has put a hand-over to the owner devices. */
export interface HandoverAsked {
  /** Names the hand-over in the commands that follow. */
  readonly reference: string
  readonly expires_at_ms: string
  /** The attempt that holds the hand-over's place. */
  readonly attempt: AttemptView
  readonly from_device_id: string
  readonly from_device_name: string
  readonly to_device_id: string
  readonly to_device_name: string
  readonly session_number: number | null
}

/** Where a hand-over stands: waiting for an owner device, answered, or gone. */
export interface HandoverState {
  readonly state: 'waiting' | 'answered' | 'gone'
  readonly expires_at_ms: string
  /** The names the host's description of the plan carries, once it has been read. */
  readonly plan: {
    readonly from_device_name: string
    readonly to_device_name: string
  } | null
}

/** What this device is offered and holds. */
export interface Held {
  readonly offers: readonly ShareOffer[]
  readonly shares: readonly HeldShare[]
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
 *
 * A command about one session takes, last, the opening of the screen making it. On a host this
 * device is paired with, the host serves a session only on the connection opened for it, so the
 * command goes over the link of that opening; a command that names none goes over a link kept for
 * calls made outside any screen. On the host on this computer the opening is not used.
 */
export interface HostPort {
  /** Whether a host connection is live, and why not when it is not. */
  connectionState(): Promise<ConnectionState>
  /**
   * Calls `listener` with the connection's state each time native code publishes it. Resolves once
   * the listener is registered, with the function that stops it: a state read after that cannot
   * miss a change.
   */
  onConnection(listener: (state: ConnectionState) => void): Promise<() => void>

  /**
   * Opens a session for a screen and says what the host decided it may do. A refusal is the host's
   * own, as a failure. The commands the screen makes about the session carry `opening`; a command
   * of an opening that was replaced or left is refused with `STALE_SESSION` and reaches nothing.
   */
  openSession(request: OpenRequest): Promise<SessionStanding>
  /**
   * Leaves an opening: its commands are refused from now on, and what is in flight on its link
   * answers before the link closes. A token that is not the session's current opening is ignored.
   */
  leaveSession(sessionId: string, opening: string): Promise<void>
  /**
   * Calls `listener` with each change of an opened session's standing. Resolves once the listener
   * is registered, with the function that stops it.
   */
  onStanding(listener: (event: StandingEvent) => void): Promise<() => void>

  hostInfo(): Promise<HostInfoResult>
  environmentList(): Promise<EnvironmentListResult>

  /**
   * What may actually be done on one environment's desktop.
   *
   * One document per environment: the desktop itself, one record per capability with the state,
   * what produced it, what it was established about and what makes it stale, what a logout does to
   * each execution profile, and the host's sleep setting. First-start setup is built on this, and
   * it is a read: asking for it grants nothing and changes nothing.
   */
  environmentCapabilities(params: unknown): Promise<EnvironmentCapabilitiesResult>

  /** The identity an operating system would record a permission against. */
  setupIdentity(): Promise<SetupIdentity>

  /**
   * Opens one of the platform's settings panes by name.
   *
   * The interface names a pane the application already knows. It never names an address, and this
   * opens a settings pane rather than pressing anything inside it: a grant that needs System
   * Settings cannot be enabled programmatically and this does not pretend to.
   */
  openSettingsPane(pane: string): Promise<SettingsPane>

  sessionList(params: unknown): Promise<SessionListResult>
  sessionRead(params: unknown): Promise<SessionReadResult>
  /**
   * Creates a session in the environment the parameters name. A managed shell the host cannot
   * qualify is refused with `SHELL_INTEGRATION_UNSUPPORTED`; the host never starts a stock shell in
   * its place.
   */
  sessionCreate(
    params: SessionCreateParams,
    subject: SessionSubject
  ): Promise<Settled<SessionCreateResult>>
  sessionClose(
    params: unknown,
    subject: SessionSubject,
    opening?: string
  ): Promise<Settled<ClosureRecord>>
  /**
   * What one session is called and what it is doing: the title and where it came from, the
   * generated activity line when there is one, and how current it is.
   *
   * The parameters name a session and nothing else. A description cannot be asked for, chosen a
   * model for or produced from here; this reads what the host has, filtered for this device.
   */
  sessionDescribe(params: SessionDescribeParams): Promise<SessionDescribeResult>
  /**
   * What session descriptions offer on this host: the exact size and the sources before anything
   * is fetched, how a fetch is going, the two settings, and why nothing is offered when nothing
   * is. A read: asking grants nothing and changes nothing.
   */
  descriptionSetup(): Promise<DescriptionSetup>
  /**
   * Turns descriptions on or off, or whether they may run on battery. A null leaves a setting as
   * it is. Both apply at once on the host, which answers with its setup as it now stands.
   */
  descriptionConfigure(params: DescriptionConfigureParams): Promise<Settled<DescriptionSetup>>
  /**
   * Starts the fetch of the selected profile's files, or stops one that is running. The page names
   * the action and nothing else: what is fetched and from where are the host's own.
   */
  descriptionDownload(params: DescriptionDownloadParams): Promise<Settled<DescriptionSetup>>
  /**
   * Starts the disclosed checks in a session's worker, and answers where they stand: running, or
   * why nothing was started. The page names the environment and nothing else; the file the read
   * check reads is not the page's to name. A run takes about two minutes, so the answer to this
   * is not its result: `environmentCapabilities` carries that.
   */
  environmentCapabilitiesCheck(
    params: EnvironmentCapabilitiesParams
  ): Promise<Settled<CapabilityChecks>>

  /**
   * What the launch surface may draw right now.
   *
   * The prompt generation in the answer is the one a launch must name. A button drawn at an older
   * generation is disabled rather than launched against a prompt the person has not seen.
   */
  launchSurface(params: unknown): Promise<LaunchSurface>
  shellLaunch(params: unknown, subject: SessionSubject): Promise<Settled<ShellLaunchResult>>

  /**
   * A session's live agent instances, and every request its agents' broker is still arbitrating.
   *
   * Read on the session's own worker, as every page of one snapshot: the page is given the
   * instances and the requests, never parts of two states.
   */
  sessionAgents(sessionId: string, opening?: string): Promise<SessionAgents>
  /** What one agent instance can do now, with the evidence behind each capability. */
  agentCapabilities(
    params: AgentCapabilitiesParams,
    opening?: string
  ): Promise<AgentCapabilitiesResult>
  /**
   * One part of an agent instance's semantic history, from the node the parameters name, filtered
   * as this device's authority requires.
   */
  agentSnapshot(params: AgentSnapshotParams, opening?: string): Promise<AgentSnapshotResult>
  /** The commands an agent instance advertises. */
  agentCommands(params: AgentCommandsParams, opening?: string): Promise<AgentCommandsResult>
  /**
   * What an installed decoder read of one approval request and the decisions it offered, with the
   * request's original bytes.
   */
  approvalInspect(
    params: AgentApprovalInspectParams,
    opening?: string
  ): Promise<AgentApprovalInspectResult>
  /**
   * The agent mutations. Each names the session, the instance and the binding revision it was
   * prepared against in its own parameters, and nothing else: native code builds the envelope from
   * exactly those, so the two cannot disagree.
   */
  composerSubmit(params: AgentPromptParams, opening?: string): Promise<Settled<AgentMutationResult>>
  composerQueue(params: AgentPromptParams, opening?: string): Promise<Settled<AgentMutationResult>>
  composerSteer(params: AgentSteerParams, opening?: string): Promise<Settled<AgentMutationResult>>
  composerInterrupt(
    params: AgentCancelParams,
    opening?: string
  ): Promise<Settled<AgentMutationResult>>
  approvalRespond(
    params: AgentApprovalRespondParams,
    opening?: string
  ): Promise<Settled<AgentApprovalRespondResult>>
  pluginActionInvoke(params: unknown, subject: SessionSubject): Promise<Settled>

  /**
   * The drafts this device keeps, and how many files in its store could not be read.
   *
   * Native code keeps them in a store of its own that outlives the application. A store that
   * cannot be opened refuses, and the page keeps its drafts in the window and says so.
   */
  deviceDrafts(): Promise<StoredDrafts>
  /** Keeps a draft: makes it, or replaces the version the request names. */
  deviceDraftSave(request: DraftSaveRequest): Promise<DraftSaved>
  /** Points a draft at a session and conversation a person chose, which clears its mark. */
  deviceDraftRetarget(request: DraftRetargetRequest): Promise<StoredDraft>
  /** Throws away a draft, if it is still the version the request names. */
  deviceDraftDiscard(request: DraftDiscardRequest): Promise<{ readonly removed: boolean }>
  /**
   * Records a removal that could not be made, so that the next start makes it: a prompt the host
   * took does not return as a draft because the store refused once.
   */
  deviceDraftMarkRemoval(request: DraftDiscardRequest): Promise<void>

  draftCreate(params: unknown, subject: SessionSubject): Promise<Settled>
  /**
   * Sends one dropped file to the host and answers with the verified handle.
   *
   * The page never holds the bytes. The platform gave the backend a path when the person dropped
   * the file on the window; this names that path back, and the backend refuses any other.
   */
  attachmentUpload(path: string, subject: SessionSubject): Promise<AttachmentHandle>
  /**
   * Sends one file the platform gave the page rather than a path, pasted onto the window or
   * picked on a phone, and answers with the verified handle.
   *
   * The page hands the bytes to native code, which sends them through the same upload a dropped
   * file takes. A file larger than {@link MAX_HANDED_BYTES} is refused there.
   */
  attachmentUploadBytes(file: HandedFile, subject: SessionSubject): Promise<AttachmentHandle>
  draftAddAttachment(params: unknown, subject: SessionSubject): Promise<Settled>

  /**
   * One page of a session's retained output, from the cursor and within the byte bound the
   * parameters name. A live session's is read on its own worker, and an ended one's from the host's
   * archive.
   */
  historyPage(params: HistoryPageParams): Promise<HistoryPageResult>
  /**
   * The receipt an action stands at now.
   *
   * A request whose answer never came, or came as only its identity, is not asked again: what the
   * host recorded of it is read, under the same authority, and no request is dispatched twice.
   * Over a host the application is paired with, a screen reads it under its opening, which names
   * the session's own link.
   */
  actionRead(params: ActionReadParams, opening?: string): Promise<ActionReadResult>
  attentionRead(params: AttentionReadParams): Promise<AttentionReadResult>
  /** Records that items were seen, each at the revision shown. An environment's, not a session's. */
  attentionAcknowledge(params: AttentionAcknowledgeParams): Promise<Settled<AttentionAcknowledgeResult>>
  /** Which completed turns and change sets wait for review, at which versions. */
  reviewRead(params: ReviewReadParams): Promise<ReviewReadResult>
  /** Records that one exact version was reviewed. It approves nothing and changes no file. */
  reviewAcknowledge(params: ReviewAcknowledgeParams): Promise<Settled<ReviewAcknowledgeResult>>
  /**
   * A session's questions, read on the session's own worker. What is read is what a later answer
   * is checked against: an answer names a question and the revision the person was shown.
   */
  questionRead(params: QuestionReadParams, opening?: string): Promise<QuestionReadResult>
  /**
   * Answers a question, or keeps the answer on this device when the worker cannot be reached. A
   * kept answer has not been sent, and nothing sends it but {@link HostPort.questionSendKept}.
   */
  questionAnswer(params: QuestionAnswerParams, opening?: string): Promise<AnswerOutcome>
  /** Every answer kept on this device, oldest first, whatever host it was given to. */
  questionKept(): Promise<KeptAnswerList>
  /**
   * Where each answer kept for one session stands against the questions the session lists now.
   * Reads and says; it sends and removes nothing.
   */
  questionSettle(sessionId: string, opening?: string): Promise<readonly SettledAnswer[]>
  /** Sends one kept answer, for a person who chose to, after the question is read again. */
  questionSendKept(which: KeptRef, opening?: string): Promise<AnswerOutcome>
  /**
   * Dismisses one kept answer, if it is still the one the person was shown. Answers whether it was
   * removed.
   */
  questionDismissKept(which: KeptRef): Promise<boolean>
  /** The devices paired with this host, which is who an invitation can go to. */
  deviceList(params: DeviceListParams): Promise<DeviceListResult>
  /**
   * What an invitation with this role and these choices would carry: the actions they compile to,
   * and every notice those actions carry in the one sentence that states it. It reaches nothing.
   */
  grantNotices(selection: RoleSelection): Promise<GrantNotices>
  /**
   * The lines on a session's screen, as an invitation that includes the live view would carry
   * them. It reaches the session's own worker, on the machine that runs it.
   */
  sessionScreenPreview(params: {
    readonly session_id: string
    readonly selection: RoleSelection
  }): Promise<SessionScreenPreviewResult>
  /**
   * Issues an invitation. The request is kept before it is sent, so an answer the host gave and
   * the connection lost is something to ask the host about, never something to send again.
   */
  grantCreate(
    params: GrantCreateParams,
    subject: SessionSubject
  ): Promise<Attempted<GrantCreateResult>>
  grantList(params: GrantListParams): Promise<GrantListResult>
  /** Takes a share back, or withdraws an invitation nobody has accepted. */
  grantRevoke(params: GrantRevokeParams): Promise<Attempted<RevocationResult>>
  /** Accepts an invitation that names this device. */
  grantRedeem(params: GrantRedeemParams): Promise<Attempted<GrantRedeemResult>>
  /** What this device is offered and holds, every page of both lists. */
  grantHeld(): Promise<Held>
  /**
   * Asks the owner devices to confirm handing a session's control to another device. Nothing that
   * changes who holds the session is sent.
   */
  transferAsk(params: GrantTransferParams, subject: SessionSubject): Promise<HandoverAsked>
  /** Whether an owner device has answered the confirmation a hand-over waits for. */
  transferAnswered(reference: string): Promise<HandoverState>
  /** Sends the hand-over an owner device confirmed, once. */
  transferFinish(reference: string): Promise<Attempted<GrantTransferResult>>
  /** Stops waiting for an owner device's confirmation. */
  transferCancel(reference: string): Promise<void>
  /** The attempts kept for the host this application is connected to. */
  attemptsList(): Promise<Attempts>
  /**
   * Asks the host what became of an attempt, once, with the exact request that was sent. It is the
   * person's choice and is never made by the application itself.
   */
  attemptAsk(actionId: string): Promise<Attempted>
  /**
   * Takes an attempt out of view, or shows it again. Hiding releases nothing, a hand-over still
   * being confirmed is cancelled and not hidden, and an attempt that is over is removed.
   */
  attemptSetHidden(actionId: string, hidden: boolean): Promise<AttemptView>
  /**
   * Deletes the record of an attempt that is over, or cancels a hand-over that was never sent.
   * Refuses an attempt that can still happen.
   */
  attemptRemove(actionId: string): Promise<void>

  pluginList(params: PluginListParams): Promise<PluginListResult>
  catalogueList(params: CatalogueListParams): Promise<CatalogueListResult>

  changesetRead(params: ChangesetReadParams): Promise<ChangesetReadResult>

  storageStatus(params: unknown): Promise<unknown>
  storageObjectDelete(params: unknown, subject: SessionSubject): Promise<Settled>

  /**
   * Opens a raw terminal view of one session, `grid` in size. Native code attaches it to the
   * session and holds its screen; every state it is in reaches `listener`, and nothing else does.
   * Resolves with the view as soon as native code holds it, before the host has answered anything.
   * A session identifier native code cannot parse, or a size outside a terminal's bounds, is
   * refused with `INVALID_ARGUMENT`, and nothing opens.
   */
  openTerminalView(
    sessionId: string,
    grid: TerminalGrid,
    listener: (state: TerminalViewState) => void,
    opening?: string
  ): Promise<TerminalView>

  /**
   * What a voice session started now would be, before one exists.
   *
   * Section 15 ¶12 wants the provider and the selected context scope shown before voice starts.
   * This is the read that can answer it: it creates no provider session, reserves nothing and
   * sends no context, so a person can be told what a call would be and then decline it.
   */
  voicePrepare(params: unknown): Promise<VoicePrepareResult>

  /**
   * What allowing voice permits by default, from the protocol's own table, so the question the
   * person is asked is worded as the host states it.
   */
  voiceScope(): Promise<VoiceScope>

  /**
   * Allows voice on this device for some of the host's sessions. Native code names the device; the
   * answer states every action the grant permits and every one the device's own grant could not
   * carry.
   */
  voiceAllow(request: VoiceAllowRequest, subject: SessionSubject): Promise<Settled<VoiceAllowed>>

  /**
   * Starts a call.
   *
   * The offer is the native layer's, which is why the page passes a request rather than protocol
   * parameters: an offer written by anything that could run in this page would name a transport
   * this page does not have.
   */
  voiceStart(request: VoiceStartRequest, subject: SessionSubject): Promise<Settled<VoiceStartResult>>

  /**
   * Ends the call and revokes its grant.
   *
   * The local call closes first and the host is told after, so hanging up works when nothing can
   * be reached (KR-REQ-15.17). The answer says both halves separately rather than reporting a
   * revocation that may not have happened.
   */
  voiceStop(voiceSessionId: string | null, subject: SessionSubject): Promise<VoiceClosure>

  /** Reads the context the host selected for this call, to be sent on as a bounded request. */
  voiceContext(params: unknown): Promise<VoiceContextResult>

  /** Silences the microphone or the speaker on this device. Reaches no service and cancels nothing. */
  voiceSetMuted(what: VoiceMute, muted: boolean): Promise<VoiceCallState>

  /** What the native call is doing right now. */
  voiceCallState(): Promise<VoiceCallState>

  /**
   * Takes a host this computer is paired with, named by its pairing-screen reference, as the one
   * this application's commands go to. Resolves once the first attempt to reach it has ended, with
   * where the connection stands.
   */
  hostsUse(reference: string): Promise<ConnectionState>

  /**
   * Forgets a host this computer is paired with, named by its pairing-screen reference: it is no
   * longer listed, used or tried. A local action that reaches no host, so it works for one that has
   * revoked this computer. Resolves with where the connection stands: unchanged unless the host
   * was the one in use, and then there is none until another is chosen.
   */
  hostsForget(reference: string): Promise<ConnectionState>

  /** Everything the pairing screen shows. */
  pairingView(): Promise<PairingView>
  /** Changes the service codes go through, before an attempt starts. */
  pairingSetOrigin(origin: string): Promise<PairingOrigin>
  /** Starts pairing with a code the person typed. Native code parses it and never hands it back. */
  pairingStartCode(code: string): Promise<void>
  /** Reads an invitation from the pasteboard in native code, and holds it. */
  pairingPaste(): Promise<PasteView>
  /** Starts pairing with the invitation read from the pasteboard. */
  pairingStartRead(): Promise<void>
  /** Ends the attempt on this computer, or drops a pasted invitation. */
  pairingStop(): Promise<void>
  /**
   * Tells `listener` each time the pairing screen's state changes: its view, or, while this
   * device's pairing records are not open, the words that stand in its place. Resolves, with the
   * function that stops it, once the listener is registered: nothing published before then
   * reaches it.
   */
  onPairing(listener: (view: PairingView | PairingUnavailable) => void): Promise<() => void>

  /** The confirmations this computer's hosts ask for. */
  ownerConfirmations(): Promise<OwnerView>
  /**
   * Reviews one confirmation: native code checks it, the platform's own ceremony asks the person,
   * and only a confirmed ceremony signs it. The page names the reference and nothing else.
   */
  ownerConfirmationReview(reference: string): Promise<ReviewOutcome>
  /**
   * The devices of every host this computer can revoke on, each with where a revocation of it
   * stands. Every host and every feed is asked.
   */
  revocationView(): Promise<RevocationView>
  /**
   * Revokes the device `device` names on the host `host` names, once the person confirms with the
   * platform's own ceremony, and answers with the view as it then stands. The page names references
   * native code gave it and nothing else; a host other than the one on this computer is reached
   * through its feed, so the answer says the request was sent and not that it was carried out.
   */
  revocationRevoke(host: string, device: string): Promise<RevocationView>
  /**
   * Tells `listener` each time the confirmations change. Resolves, with the function that stops
   * it, once the listener is registered: nothing published before then reaches it.
   */
  onConfirmations(listener: (view: OwnerView) => void): Promise<() => void>

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

  /** Where this device stands with an account. */
  accountStatus(): Promise<AccountView>

  /**
   * Signs this device in, and settles when the attempt ends.
   *
   * The backend hands the passkey ceremony to the system browser on reach.kala.to. The page names
   * nothing: not the address the browser opens, and never a code or a token. What comes back is
   * where the device stands.
   */
  accountSignIn(): Promise<AccountView>

  /**
   * Signs this device in again, asking for the right to write the account's backup storage as
   * well, which keeping a recovery bundle takes. Settles when the attempt ends.
   */
  accountSignInForRecovery(): Promise<AccountView>

  /** Ends the sign-in that is waiting for the browser. */
  accountSignInCancel(): Promise<void>

  /** Signs this device out, and tells the service. */
  accountSignOut(): Promise<AccountView>

  /** The account's usage, and nothing about money. */
  accountUsage(): Promise<UsageView>

  /**
   * Tells `listener` where the device stands each time that changes by itself. Resolves, with the
   * function that stops it, once the listener is registered: nothing published before then
   * reaches it.
   */
  onAccount(listener: (view: AccountView) => void): Promise<() => void>

  /** The sync service this computer is set to use. */
  syncServiceView(): Promise<SyncServiceView>
  /** Chooses another sync service. The page names an origin, and nothing else. */
  syncServiceSet(origin: string): Promise<SyncServiceView>

  /** The person's settings, and where settings sync stands. Nothing is sent to any service. */
  settingsView(): Promise<SettingsView>
  /**
   * Keeps the person's choice of colour mode on this computer and, when settings sync is on, sends
   * it. The choice is kept whether or not the sync service can be reached; `sync.problem` says
   * when it could not.
   */
  settingsSetColourMode(mode: ColourMode): Promise<SettingsView>
  /** Turns settings sync on. Native code starts the collection and seals the settings in it. */
  settingsSyncTurnOn(): Promise<SettingsView>
  /** Brings this computer and the sync service to the same settings now, when sync is on. */
  settingsSyncNow(): Promise<SettingsView>
  /**
   * Turns the keeping of drafts in step on or off. Refused while settings sync is off, since drafts
   * travel in its collection.
   */
  settingsDraftsSet(enabled: boolean): Promise<SettingsView>
  /**
   * Asks every host who it lists, brings this computer and the service to the same settings, and
   * on a computer that shares none, looks for settings other devices share with it.
   */
  settingsDevicesRefresh(): Promise<SettingsView>
  /**
   * Gives the device `reference` names the key of the shared settings, once the person confirms on
   * this computer with the platform's ceremony. Refused when they do not.
   */
  settingsDeviceShare(reference: string): Promise<SettingsView>
  /** Takes the device `reference` names out of the shared settings. Needs no confirmation. */
  settingsDeviceRemove(reference: string): Promise<SettingsView>
  /** Joins the settings the offer `reference` names, once the person confirms on this computer. */
  settingsJoin(reference: string): Promise<SettingsView>
  /** Lets go of the outcomes the page has shown. */
  settingsDevicesDismiss(): Promise<SettingsView>
  /** The versions of the settings to choose between, or null when two devices changed none. */
  settingsConflicts(): Promise<SettingsChoice | null>
  /**
   * Records which version the person keeps and sends it. Every other version is let go, here and
   * at the sync service. Refused when nothing waits for a choice.
   */
  settingsConflictResolve(keep: SettingsKeep): Promise<SettingsView>
  /**
   * Tells `listener` the settings each time they change by themselves: another device's change
   * was followed, a step ended, or content waits for a choice. Resolves, with the function that
   * stops it, once the listener is registered.
   */
  onSettings(listener: (view: SettingsView) => void): Promise<() => void>

  /** Where recovery stands, and what stops the next step. Nothing is sent to any service. */
  recoveryView(): Promise<RecoveryView>
  /** Makes the recovery seed in native code and puts the first bundle at the sync service. */
  recoveryTurnOn(): Promise<RecoveryView>
  /** Ends a write to the recovery bundle that was not answered, so the next one can go. */
  recoverySettle(): Promise<RecoveryView>
  /**
   * Writes the recovery kit to `path`, which must be one `chooseExportPath` returned. Native code
   * writes it; nothing the kit holds reaches the page.
   */
  recoverySaveKit(path: string): Promise<KitSaved>

  /**
   * Tells `listener` each event the host publishes. Resolves, with the function that stops it,
   * once the listener is registered: nothing published before then reaches it. The connection's
   * own changes are `onConnection`'s.
   */
  subscribe(listener: (event: HostEvent) => void): Promise<() => void>

  /**
   * Tells `listener` the files the platform hands this window, as they are dropped. Resolves, with
   * the function that stops it, once the listener is registered.
   */
  onFilesDropped(listener: (files: readonly DroppedFile[]) => void): Promise<() => void>
}

/**
 * A view's listeners, from their registration until they stop, and the reads made meanwhile.
 *
 * A view reads the state its listeners follow only while every one of them is registered, so no
 * change they would hear can fall between a read and them, and it shows a read's answer only while
 * the watch runs and no newer read has been started. `read` holds a view to both: it starts nothing
 * before every listener is registered or once the watch has ended, and it answers the check each
 * answer is shown under.
 */
export interface Watch {
  /** Ends the watch: every listener stops, and no read started in it is answered after this. */
  readonly stop: () => void
  /**
   * Starts a read. Until every listener is registered, and once the watch has ended, there is none
   * to start and this answers null. Otherwise it answers a check that stays true while this is the
   * newest read started and the watch has not ended.
   */
  readonly read: () => (() => boolean) | null
}

/**
 * Listens, and then reads.
 *
 * Every listener the port offers resolves once it is registered. This registers all of
 * `registrations` and, once every one of them is, calls `listening`, where a view starts its first
 * read. `stop` stops them all, including one whose registration completes after it, and `listening`
 * is never called after it. The first registration that fails ends the watch at once, as `stop`
 * does, and goes to `failed`.
 */
export function watch(
  registrations: readonly Promise<() => void>[],
  listening: () => void = () => undefined,
  failed: (failure: unknown) => void = () => undefined
): Watch {
  let stage: 'registering' | 'listening' | 'ended' = 'registering'
  let unregistered = registrations.length
  let newest = 0
  const stops: (() => void)[] = []
  const stop = () => {
    stage = 'ended'
    for (const each of stops.splice(0)) each()
  }
  const registered = () => {
    if (stage !== 'registering') return
    stage = 'listening'
    listening()
  }
  if (unregistered === 0) void Promise.resolve().then(registered)
  for (const registration of registrations) {
    void registration.then(
      (unlisten) => {
        if (stage === 'ended') {
          unlisten()
          return
        }
        stops.push(unlisten)
        unregistered -= 1
        if (unregistered === 0) registered()
      },
      (failure: unknown) => {
        if (stage === 'ended') return
        stop()
        failed(failure)
      }
    )
  }
  return {
    stop,
    read: () => {
      if (stage !== 'listening') return null
      newest += 1
      const started = newest
      return () => stage === 'listening' && started === newest
    }
  }
}

/**
 * Follows one state whose every change carries the state itself.
 *
 * `listen` registers for its changes and `read` asks for it once that registration is complete,
 * so no change falls between the two. `show` is given every change heard, and the read's answer
 * only when no change was heard first: a change heard before the answer is at least as new as it.
 * `failed` is given a failure to register or to read, on the same terms. The returned function
 * stops following, including a registration that completes after it was called.
 */
export function follow<T>(
  listen: (listener: (value: T) => void) => Promise<() => void>,
  read: () => Promise<T>,
  show: (value: T) => void,
  failed: (failure: unknown) => void
): () => void {
  let stopped = false
  let heard = false
  const following: Watch = watch(
    [
      listen((value) => {
        if (stopped) return
        heard = true
        show(value)
      })
    ],
    () => {
      const current = following.read()
      if (current === null) return
      const answered = (settle: () => void) => {
        if (current() && !heard) settle()
      }
      // A port can refuse before it returns a promise; that refusal is an answer like any other.
      void (async () => {
        try {
          const value = await read()
          answered(() => {
            show(value)
          })
        } catch (failure: unknown) {
          answered(() => {
            failed(failure)
          })
        }
      })()
    },
    (failure) => {
      if (!heard) failed(failure)
    }
  )
  return () => {
    stopped = true
    following.stop()
  }
}

/** A raw terminal view's grid: the cells its surface holds at its cell size. */
export interface TerminalGrid {
  readonly columns: number
  readonly rows: number
}

/**
 * What a raw terminal view is, as native code publishes it on the view's own channel.
 *
 * Waiting: attached, with no complete screen to draw, before the first or between the host's reset
 * or resynchronisation and the next. Showing: attached, with a complete screen. Ended: the view is
 * over, for a reason in the host's words or the link's, and every move the page made with it is
 * settled. The attachment's summary, which says how the host presents the view and why, rides on
 * the first two, and so does `settled`: the newest of the page's moves it may take as settled,
 * which native code says only with a screen that holds it. So does `control`: whether the view
 * controls the program, told at once whenever it changes.
 */
export type TerminalViewState =
  | {
      readonly state: 'waiting'
      readonly attachment: AttachmentSummary
      readonly settled: number
      readonly control: TerminalControl
    }
  | {
      readonly state: 'showing'
      readonly attachment: AttachmentSummary
      readonly screen: TerminalScreen
      readonly settled: number
      readonly control: TerminalControl
    }
  | { readonly state: 'ended'; readonly reason: string }

/**
 * Whether a view controls the program: it watches, and nothing of the person's reaches the program;
 * it is taking control, and waits for the session's answer; or it holds the session's input, and the
 * program gets its wheel and keys. `number` is the page's newest control request native code took,
 * and `ended` says why control last ended or was refused, until a newer request.
 */
export interface TerminalControl {
  readonly number: number
  readonly state: 'watching' | 'taking' | 'controlling'
  readonly ended: string | null
}

/**
 * Whether a wheel turn over a screen reaches its program: it reports the mouse in an encoding the
 * view writes, it does not report the mouse, or it reports it in an encoding the view does not
 * write.
 */
export type TerminalWheel = 'reaches' | 'unreported' | 'unwritable'

/**
 * What the page tells a view of the person: taking control or giving it back, numbered in the order
 * the page asks, or a turn of the program's wheel at a cell of the session's grid, a key, text or a
 * paste, each made under the page's take `take`. `turns` go towards the person when positive.
 */
export type TerminalInput =
  | { readonly kind: 'take'; readonly number: number }
  | { readonly kind: 'release'; readonly number: number }
  | ({ readonly take: number } & ProgramInput)

/**
 * What reaches the program while a view controls it: its wheel turned at a cell, a key named as the
 * platform reported it, text that came with no key, or a paste. The page never spells a byte:
 * native code spells each in the encoding the program negotiated.
 */
export type ProgramInput =
  | {
      readonly kind: 'wheel'
      /** The cell's column in the session's grid, from 0. */
      readonly column: number
      /** The cell's line of the live screen, from 0. */
      readonly line: number
      readonly turns: number
      readonly shift: boolean
      readonly alt: boolean
      readonly control: boolean
    }
  | ({ readonly kind: 'key'; readonly event: KeyAction } & TypedKey)
  /** Text an input method, a software keyboard or dictation committed, with no control character. */
  | { readonly kind: 'text'; readonly text: string }
  /** Text the person pasted, as it was on the pasteboard. */
  | { readonly kind: 'paste'; readonly text: string }

/** Whether a key went down, repeated while held, or came up. */
export type KeyAction = 'press' | 'repeat' | 'release'

/**
 * The keys of the numeric keypad native code knows, by the code the platform gives their place on
 * the keyboard.
 */
export const KEYPAD_CODES = [
  'Numpad0',
  'Numpad1',
  'Numpad2',
  'Numpad3',
  'Numpad4',
  'Numpad5',
  'Numpad6',
  'Numpad7',
  'Numpad8',
  'Numpad9',
  'NumpadDecimal',
  'NumpadComma',
  'NumpadDivide',
  'NumpadMultiply',
  'NumpadSubtract',
  'NumpadAdd',
  'NumpadEqual',
  'NumpadEnter'
] as const

/** A key of the numeric keypad, by its code. */
export type KeypadCode = (typeof KEYPAD_CODES)[number]

/** One key as its platform reported it, named rather than spelled. */
export interface TypedKey {
  /** The character it made, never a control character, or the name of a key that makes none. */
  readonly key: string
  /** The character it makes with nothing held, where the platform said; null where it did not. */
  readonly base: string | null
  /** The keypad key it is, or null for a key that is not on the keypad. */
  readonly keypad: KeypadCode | null
  readonly shift: boolean
  readonly alt: boolean
  readonly control: boolean
  readonly caps_lock: boolean
  readonly num_lock: boolean
}

/** The window the host drew for a view: its size in cells, and where it starts. */
export interface TerminalWindow {
  readonly rows: number
  readonly columns: number
  /** The first of the session's columns it shows. */
  readonly column: number
  /** The line of the live screen it starts at; 0 in the history. */
  readonly line: number
  /** How many rows above the live screen's first line it starts; 0 on the live screen. */
  readonly above: number
}

/** How many cells a window can still move each way before it reaches a limit. */
export interface TerminalRoom {
  /** Rows up, back into the session's history. */
  readonly up: number
  /** Rows down, as far as the live screen's last line that still fills the window. */
  readonly down: number
  readonly left: number
  /** Columns to the right, as far as the last that still fills the window. */
  readonly right: number
}

/**
 * One move of a view's window, numbered by the page in the order it makes them: by `across` columns
 * and `down` rows (to the right and down when positive), or back to the live screen.
 */
export type TerminalMove =
  | { readonly number: number; readonly across: number; readonly down: number }
  | { readonly number: number; readonly live: true }

/**
 * The arguments native code's commands take for a view's size, as the page's port sends them for
 * `grid`: the opening's and the resize's, beside the session or the view they name.
 */
export function viewSizeArguments(grid: TerminalGrid): { readonly columns: number; readonly rows: number } {
  return { columns: grid.columns, rows: grid.rows }
}

/**
 * The arguments native code's command for a move takes, as the page's port sends them for `move`,
 * beside the view it names. A move that has `live` goes back to the live screen, whatever else it
 * holds.
 */
export function viewMoveArguments(move: TerminalMove): {
  readonly number: number
  readonly across: number
  readonly down: number
  readonly live: boolean
} {
  return 'live' in move
    ? { number: move.number, across: 0, down: 0, live: true }
    : { number: move.number, across: move.across, down: move.down, live: false }
}

/** The part of a session's screen one view shows, as cells, never bytes. */
export interface TerminalScreen {
  /** The session's own size. */
  readonly dimensions: Dimensions
  /** The window the host drew for this view: its size, and where it starts. */
  readonly window: TerminalWindow
  /** How far the window can still move each way. */
  readonly room: TerminalRoom
  /** Exactly the window's rows, top to bottom. */
  readonly lines: readonly TerminalLine[]
  /** The cursor, or null when it is outside the window. */
  readonly cursor: TerminalCursor | null
  /** The session's palette, with where it came from. */
  readonly palette: PaletteState
  /** Whether the session had to shorten content to stay inside a bound. */
  readonly degraded: boolean
  /** How many runs and clusters could not be placed, and are blank or left out. */
  readonly replaced: number
  /** Whether a wheel turn over the screen reaches the program. */
  readonly wheel: TerminalWheel
}

/** One line of a view's window. */
export interface TerminalLine {
  /** The row's stable identifier in the session. */
  readonly row: string
  readonly soft_wrapped: boolean
  /** Whether the session left runs out of the row to keep it inside a page's bound. */
  readonly truncated: boolean
  /** What is drawn on the line, left to right. A cell no piece covers is blank. */
  readonly pieces: readonly TerminalPiece[]
}

/** Text drawn at one column of a line, never past its cells. */
export interface TerminalPiece {
  /** The column, in the window, of its first cell. */
  readonly column: number
  readonly cells: number
  readonly text: string
  /** How it is drawn, with the screen's reverse video already applied. */
  readonly rendition: CellRendition
  /**
   * The link it is inside, as inert metadata: nothing draws or opens it. Its parameters tell it
   * from another link to the same target.
   */
  readonly hyperlink: ProjectedHyperlink | null
}

/** The cursor, in the window's coordinates. */
export interface TerminalCursor {
  readonly column: number
  readonly line: number
  readonly visible: boolean
  /** The cursor-style number the session set. */
  readonly style: number
}

/** One open raw terminal view. */
export interface TerminalView {
  /**
   * Tells the view the page's grid is now `grid`. A size outside a terminal's bounds is refused
   * with `INVALID_ARGUMENT`, and the grid stays as it was.
   */
  resize(grid: TerminalGrid): Promise<void>
  /** Moves the view's window. A move native code cannot read is refused, and nothing moves. */
  move(move: TerminalMove): Promise<void>
  /**
   * Hands the view the person's input. Resolves once native code has taken it; an input the view may
   * not write, since it does not control the program under the take it names, is refused with
   * `LEASE_LOST`, as is any input once the view has ended, and a shape native code does not read
   * with `INVALID_ARGUMENT`. A key, text or paste that cannot reach the program as it reads keys now,
   * or before the view holds the session's screen, is refused with `INPUT_INCOMPATIBLE` and words
   * that say why, and the view keeps control.
   */
  input(input: TerminalInput): Promise<void>
  /** Closes the view. Resolves once it has ended: nothing it publishes arrives after. */
  close(): Promise<void>
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

/**
 * What a person can do about a failure, in words, for each key native code names an action by.
 *
 * Section 23 has the interface translate a code into a direct action rather than show the code.
 * Native code attaches the key of the action a code maps to (`UserAction::as_str` in the client
 * library) to every failure it answers with, and these are the words for each key, the library's own
 * (`UserAction::message`). `nothing` has none: the host's words are all there is to say.
 */
export const USER_ACTIONS: Readonly<Record<string, string>> = {
  pair_again: 'Pair this device with the host again.',
  sign_in: 'Sign in to your account.',
  update: 'Update this app or the host: their versions do not agree.',
  wait: 'Wait a moment and try again.',
  resync: 'Refresh: this view has fallen behind.',
  check_the_outcome: 'Check whether this went through before trying it again.',
  fix_configuration: 'Change a setting on this device or on the host.'
}

/**
 * The message to show for a failure, whatever shape it arrived in, and never an empty one: a
 * failure that came with no words of its own is still a failure, and says so in these. A host
 * failure whose code maps to something the person can do says that after the host's words.
 *
 * The client library says a host's refusal as its code, a colon and the host's words. The words are
 * for the person and the code is not, so the code goes: section 23 has the interface translate a
 * code into a direct action, and not show the code by default.
 */
export function failureMessage(value: unknown): string {
  const said = failureWords(value)
  const key = isHostError(value) ? value.user_action : undefined
  const action = typeof key === 'string' && Object.hasOwn(USER_ACTIONS, key) ? USER_ACTIONS[key] : undefined
  if (action === undefined) return said
  const sentence = said.trimEnd()
  return `${sentence}${/[.!?…]$/.test(sentence) ? '' : '.'} ${action}`
}

/**
 * The words of a failure, without the code the client library puts before a host's and without
 * the action, for a place that says what a person can do about it in its own words, or where
 * nothing can be done.
 */
export function failureWords(value: unknown): string {
  const failure = isHostError(value) ? value : null
  const own = failure !== null ? failure.message : value instanceof Error ? value.message : ''
  const codeFirst = failure === null ? '' : `${failure.code}: `
  const words = codeFirst !== '' && own.startsWith(codeFirst) ? own.slice(codeFirst.length) : own
  return words.trim().length > 0 ? words : 'Something went wrong.'
}

/** The protocol code of a failure, or null when it did not carry one. */
export function failureCode(value: unknown): string | null {
  return isHostError(value) ? value.code : null
}
