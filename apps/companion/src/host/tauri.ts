/**
 * The port the desktop application runs on.
 *
 * Every method here is one `invoke` of one named command. Nothing builds a command name from a
 * value, so the set of commands this file can reach is the set written in it, and the set the
 * backend registers is the set it will answer.
 */

import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWebview } from '@tauri-apps/api/webview'
import { save } from '@tauri-apps/plugin-dialog'

import type { LaunchSurface } from '../model/pending'
import type {
  ApprovedLink,
  DroppedFile,
  HostEvent,
  HostPort,
  ImportedImage,
  OwnerPresence,
  ProjectedScreen,
  RendezvousOrigin,
  ScannedCode,
  Settled,
  Written
} from './port'

/** The event the backend publishes host events on. */
export const HOST_EVENT = 'kr://event'

/** Builds the desktop port. */
export function tauriPort(): HostPort {
  const call = <T,>(command: string, args: Record<string, unknown>): Promise<T> =>
    invoke<T>(command, args)

  const protocol = <T,>(command: string, environmentId: string, params: unknown): Promise<T> =>
    call<T>(command, { environmentId, params })

  return {
    connectionState: () => call<boolean>('connection_state', {}),

    hostInfo: (environmentId) => protocol('host_info', environmentId, {}),
    environmentList: (environmentId) => protocol('environment_list', environmentId, {}),
    environmentCapabilities: (environmentId, params) =>
      protocol('environment_capabilities', environmentId, params),

    sessionList: (environmentId, params) => protocol('session_list', environmentId, params),
    sessionRead: (environmentId, params) => protocol('session_read', environmentId, params),
    sessionClose: (environmentId, params) => protocol('session_close', environmentId, params),

    // The environment reports which of the six profiles it actually has, and the session reports
    // the prompt generation a launch must name. Both come from the host; nothing here guesses at
    // an executable.
    launchSurface: (environmentId, params) =>
      protocol<LaunchSurface>('environment_capabilities', environmentId, params),
    shellLaunch: (environmentId, params) => protocol('shell_launch', environmentId, params),

    agentSnapshot: (environmentId, params) => protocol('agent_snapshot', environmentId, params),
    agentCommands: (environmentId, params) => protocol('agent_commands', environmentId, params),
    composerSubmit: (environmentId, params) =>
      protocol<Settled>('composer_submit', environmentId, params),
    composerQueue: (environmentId, params) =>
      protocol<Settled>('composer_queue', environmentId, params),
    composerSteer: (environmentId, params) =>
      protocol<Settled>('composer_steer', environmentId, params),
    composerInterrupt: (environmentId, params) =>
      protocol<Settled>('composer_interrupt', environmentId, params),
    approvalRespond: (environmentId, params) =>
      protocol<Settled>('approval_respond', environmentId, params),
    pluginActionInvoke: (environmentId, params) =>
      protocol<Settled>('plugin_action_invoke', environmentId, params),

    draftCreate: (environmentId, params) => protocol<Settled>('draft_create', environmentId, params),
    draftUpdate: (environmentId, params) => protocol<Settled>('draft_update', environmentId, params),
    draftAddAttachment: (environmentId, params) =>
      protocol<Settled>('draft_add_attachment', environmentId, params),
    attachmentImage: (environmentId, params) =>
      protocol<{ bytes: number[]; media_type: string }>('attachment_image', environmentId, params),

    historyPage: (environmentId, params) => protocol('history_page', environmentId, params),
    attentionRead: (environmentId, params) => protocol('attention_read', environmentId, params),
    attentionAcknowledge: (environmentId, params) =>
      protocol<Settled>('attention_acknowledge', environmentId, params),
    questionRead: (environmentId, params) => protocol('question_read', environmentId, params),
    questionAnswer: (environmentId, params) =>
      protocol<Settled>('question_answer', environmentId, params),
    grantList: (environmentId, params) => protocol('grant_list', environmentId, params),
    grantCreate: (environmentId, params) => protocol<Settled>('grant_create', environmentId, params),

    pluginList: (environmentId, params) => protocol('plugin_list', environmentId, params),
    catalogueList: (environmentId, params) => protocol('catalogue_list', environmentId, params),

    changesetRead: (environmentId, params) => protocol('changeset_read', environmentId, params),

    storageStatus: (environmentId, params) => protocol('storage_status', environmentId, params),
    storageObjectDelete: (environmentId, params) =>
      protocol<Settled>('storage_object_delete', environmentId, params),

    terminalProjection: (environmentId, params) =>
      protocol<ProjectedScreen>('events_snapshot', environmentId, params),
    terminalInput: (environmentId, params) => protocol('input_write', environmentId, params),
    attachmentViewport: (environmentId, params) =>
      protocol<Settled>('attachment_viewport', environmentId, params),

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

    chooseExportPath: (suggestedName) => save({ defaultPath: suggestedName }),

    subscribe(listener: (event: HostEvent) => void) {
      let stop: (() => void) | null = null
      let cancelled = false
      void listen<HostEvent>(HOST_EVENT, (event) => {
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
