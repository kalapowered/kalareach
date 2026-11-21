/**
 * What the desktop port sends for a raw terminal view, for the published agent, attention, review,
 * sharing and package methods, and how it takes in the connection state native code reports.
 *
 * A view is opened with the session and the grid the command takes, and a channel of its own that
 * native code publishes that view's states on; its size and its close go to their own commands with
 * the handle the open answered. Every published method goes to its own named command with the
 * parameters the protocol defines, unchanged. A connection state's reason that is blank is no
 * reason, so the port hands it on as none, from a read and from a change alike.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import type { GrantCreateParams, RoleSelection, SessionCreateParams } from '@kalareach/protocol'

import { READ_SUPERSEDED, type ConnectionState } from '../src/host/port'
import {
  CONNECTION_EVENT,
  HOST_EVENT,
  SETTINGS_EVENT,
  STANDING_EVENT,
  tauriPort
} from '../src/host/tauri'

const shell = vi.hoisted(() => ({
  invoked: [] as { command: string; args: unknown; options?: unknown }[],
  /** What a command answers, by its name; one not named here answers a session snapshot. */
  answers: new Map<string, unknown>(),
  /** The handler native code publishes each event to, by the event's name. */
  handlers: new Map<string, (published: { payload: unknown }) => void>()
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (command: string, args: unknown, options?: unknown) => {
    shell.invoked.push(options === undefined ? { command, args } : { command, args, options })
    return Promise.resolve(shell.answers.has(command) ? shell.answers.get(command) : null)
  },
  // The page's end of a channel: native code calls `onmessage` with each message.
  Channel: class {
    onmessage: (message: unknown) => void = () => undefined
  }
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: (event: string, handler: (published: { payload: unknown }) => void) => {
    shell.handlers.set(event, handler)
    return Promise.resolve(() => undefined)
  }
}))

afterEach(() => {
  shell.invoked.length = 0
  shell.answers.clear()
  shell.handlers.clear()
})

describe('the desktop port and a raw terminal view', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

  it('opens a view with the session, the grid and a channel of its own', async () => {
    shell.answers.set('terminal_view_open', '7')
    const heard: unknown[] = []
    await tauriPort().openTerminalView(
      SESSION,
      { columns: 80, rows: 24 },
      (state) => {
        heard.push(state)
      },
      undefined,
      null
    )
    expect(shell.invoked).toHaveLength(1)
    const [opened] = shell.invoked
    expect(opened?.command).toBe('terminal_view_open')
    const args = opened?.args as {
      sessionId: string
      columns: number
      rows: number
      anchor: unknown
      onState: { onmessage: (message: unknown) => void }
    }
    expect({ sessionId: args.sessionId, columns: args.columns, rows: args.rows, anchor: args.anchor }).toEqual({
      sessionId: SESSION,
      columns: 80,
      rows: 24,
      anchor: null
    })
    // What native code publishes on the view's channel reaches the view's listener, and only it.
    const ended = { state: 'ended', reason: 'This session has closed.' }
    args.onState.onmessage(ended)
    expect(heard).toEqual([ended])
  })

  it('sends the size, the moves and the close to their own commands, with the handle the open answered', async () => {
    shell.answers.set('terminal_view_open', '7')
    const view = await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined, undefined, null)
    await view.resize({ columns: 100, rows: 30 })
    await view.move({ number: 1, across: -2, down: 3 })
    await view.move({ number: 2, live: true })
    await view.close()
    expect(shell.invoked.slice(1)).toEqual([
      { command: 'terminal_view_resize', args: { view: '7', columns: 100, rows: 30 } },
      {
        command: 'terminal_view_move',
        args: { view: '7', number: 1, across: -2, down: 3, live: false }
      },
      { command: 'terminal_view_move', args: { view: '7', number: 2, across: 0, down: 0, live: true } },
      { command: 'terminal_view_close', args: { view: '7' } }
    ])
  })

  it("sends the person's input to the view's own command, in the shape native code reads", async () => {
    shell.answers.set('terminal_view_open', '7')
    const view = await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined, undefined, null)
    const wheel = { kind: 'wheel', take: 1, column: 3, line: 2, turns: -1, shift: false, alt: true, control: false } as const
    const escape = {
      kind: 'key',
      take: 1,
      key: 'Escape',
      base: null,
      keypad: null,
      shift: false,
      alt: false,
      control: false,
      caps_lock: false,
      num_lock: true,
      event: 'press'
    } as const
    await view.input({ kind: 'take', number: 1 })
    await view.input(wheel)
    await view.input(escape)
    await view.input({ kind: 'text', take: 1, text: '日本' })
    await view.input({ kind: 'paste', take: 1, text: 'one\ntwo' })
    await view.input({ kind: 'release', number: 2 })
    expect(shell.invoked.slice(1)).toEqual([
      { command: 'terminal_view_input', args: { view: '7', input: { kind: 'take', number: 1 } } },
      { command: 'terminal_view_input', args: { view: '7', input: wheel } },
      { command: 'terminal_view_input', args: { view: '7', input: escape } },
      { command: 'terminal_view_input', args: { view: '7', input: { kind: 'text', take: 1, text: '日本' } } },
      { command: 'terminal_view_input', args: { view: '7', input: { kind: 'paste', take: 1, text: 'one\ntwo' } } },
      { command: 'terminal_view_input', args: { view: '7', input: { kind: 'release', number: 2 } } }
    ])
    // The page names no other way to write to a program.
    expect('terminalInput' in tauriPort()).toBe(false)
  })
})

describe('the desktop port and the published methods', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
  const subject = {
    session_id: SESSION,
    application_instance_id: '8a7b6c50-22bb-4c3d-8e4f-000000000201'
  }
  const target = { subject, binding_revision: '3' }

  it("sends each of the agent's calls to its own command, with the protocol's own parameters", async () => {
    const port = tauriPort()
    const prompt = { target, text: 'Summarise the diff', draft_id: null }
    const steer = { target, text: 'Stop after the tests', turn_id: 'turn-2' }
    const cancel = { target, turn_id: 'turn-2' }
    const answer = { target, resource_id: 'resource-1', option_id: 'approve' }
    const invocation = {
      target,
      plugin_id: 'openai.codex',
      action: 'thread.refresh',
      draft_id: null,
      resource_id: null,
      parameters: 'e30'
    }
    await port.sessionAgents(SESSION)
    await port.agentCapabilities({ subject })
    await port.agentSnapshot({ subject, from_node: '5' })
    await port.agentCommands({ subject })
    await port.approvalInspect({ subject, resource_id: 'resource-1' })
    await port.composerSubmit(prompt)
    await port.composerQueue(prompt)
    await port.composerSteer(steer)
    await port.composerInterrupt(cancel)
    await port.approvalRespond(answer)
    await port.pluginActionInvoke(invocation)
    await port.historyPage({ session_id: SESSION, from_cursor: '0', max_bytes: '65536' })
    expect(shell.invoked).toEqual([
      { command: 'session_agents', args: { sessionId: SESSION } },
      { command: 'agent_capabilities', args: { params: { subject } } },
      { command: 'agent_snapshot', args: { params: { subject, from_node: '5' } } },
      { command: 'agent_commands', args: { params: { subject } } },
      {
        command: 'agent_approval_inspect',
        args: { params: { subject, resource_id: 'resource-1' } }
      },
      { command: 'agent_prompt_submit', args: { params: prompt } },
      { command: 'agent_prompt_queue', args: { params: prompt } },
      { command: 'agent_turn_steer', args: { params: steer } },
      { command: 'agent_turn_cancel', args: { params: cancel } },
      { command: 'agent_approval_respond', args: { params: answer } },
      { command: 'plugin_action_invoke', args: { params: invocation } },
      {
        command: 'history_page',
        args: { params: { session_id: SESSION, from_cursor: '0', max_bytes: '65536' } }
      }
    ])
  })

  it('hands a pasted or picked file over as raw bytes, with its name and subject in headers', async () => {
    const bytes = new Uint8Array([1, 2, 3])
    await tauriPort().attachmentUploadBytes(
      { name: 'café notes.txt', bytes },
      { sessionId: SESSION }
    )
    expect(shell.invoked).toEqual([
      {
        command: 'attachment_upload_bytes',
        args: bytes,
        options: {
          headers: {
            'kr-file-name': 'caf%C3%A9%20notes.txt',
            'kr-subject': JSON.stringify({ sessionId: SESSION })
          }
        }
      }
    ])
  })

  it('reads the inbox and the numbers under the key native code answered with, and fails a superseded read with the page’s own code and no data', async () => {
    const port = tauriPort()
    const key = { host: { kind: 'paired', reference: 'studio' }, epoch: 3, link: 2 }
    const params = { session_id: null, after: null, include_acknowledged: false, max_items: '200' }
    shell.answers.set('attention_read', { key, result: { items: [], more: false } })
    await expect(port.attentionRead(params)).resolves.toEqual({ key, value: { items: [], more: false } })
    shell.answers.set('session_numbers', { key, result: { sessions: [] } })
    await expect(port.sessionNumbers()).resolves.toEqual({ key, value: { sessions: [] } })
    expect(shell.invoked.at(-1)?.command).toBe('session_numbers')
    shell.answers.set('attention_read', { key, superseded: true })
    const inbox = await port.attentionRead(params).catch((failure: unknown) => failure)
    expect(inbox).toMatchObject({ code: READ_SUPERSEDED })
    expect(inbox).not.toHaveProperty('value')
    shell.answers.set('session_numbers', { key, superseded: true })
    await expect(port.sessionNumbers()).rejects.toMatchObject({ code: READ_SUPERSEDED })
  })

  it('sends attention, review, sharing, packages and change sets to their own commands', async () => {
    const port = tauriPort()
    const environment = '3f1a2c40-11aa-4b2c-9d3e-000000000001'
    const selection: RoleSelection = {
      role: 'viewer',
      history_from_cursor_ms: null,
      include_live_screen: false,
      include_question_respond: true,
      named_questions: [],
      named_approvals: []
    }
    const grant: GrantCreateParams = {
      session_id: SESSION,
      recipient_device_id: '3f1a2c40-11aa-4b2c-9d3e-000000000301',
      parent_grant_id: null,
      selection,
      lifetime_ms: null,
      accepted_notices: ['agent_permissions'],
      owner_confirmation: null
    }
    const review = {
      session_id: SESSION,
      subject: { change_set: { session_id: SESSION, change_set_id: 'change-1' } },
      version: '2'
    }
    shell.answers.set('attention_read', { key: { host: null, epoch: 0, link: 1 }, result: {} })
    await port.attentionRead({
      session_id: null,
      after: null,
      include_acknowledged: false,
      max_items: '200'
    })
    await port.attentionAcknowledge({ items: [{ key: 'key-1', revision: '4' }] })
    await port.reviewRead({ session_id: null, subject: null, max_reviews: '200', after: null })
    await port.reviewAcknowledge(review)
    await port.deviceList({ include_revoked: false })
    await port.privacyStatus()
    await port.grantNotices(selection)
    await port.grantCreate(grant, { sessionId: SESSION })
    await port.grantList({ session_id: SESSION, include_resolved: false })
    await port.sessionScreenPreview({ session_id: SESSION, selection })
    await port.grantRevoke({ grant_id: 'grant-1' })
    await port.grantRedeem({ invitation_id: 'invitation-1' })
    await port.grantHeld()
    await port.transferAsk(
      { session_id: SESSION, from_grant_id: 'grant-1', to_device_id: 'device-2' },
      { sessionId: SESSION }
    )
    await port.transferAnswered('reference-1')
    await port.transferFinish('reference-1')
    await port.transferCancel('reference-1')
    await port.attemptsList()
    await port.attemptAsk('action-1')
    await port.attemptSetHidden('action-1', true)
    await port.attemptRemove('action-1')
    await port.pluginList({ environment_id: environment })
    await port.catalogueList({ environment_id: environment })
    await port.changesetRead({ change_set_id: 'change-1', version: null })
    await port.retainedSyncCopies()
    await port.retainedDeleteAsk('copy-1')
    await port.retainedDeleteFinish('token-1')
    await port.retainedDeleteCancel('token-1')
    expect(shell.invoked.map((each) => each.command)).toEqual([
      'attention_read',
      'attention_acknowledge',
      'review_read',
      'review_acknowledge',
      'device_list',
      'privacy_status',
      'grant_notices',
      'grant_create',
      'grant_list',
      'session_screen_preview',
      'grant_revoke',
      'grant_redeem',
      'grant_held',
      'transfer_ask',
      'transfer_answered',
      'transfer_finish',
      'transfer_cancel',
      'attempts_list',
      'attempt_ask',
      'attempt_set_hidden',
      'attempt_remove',
      'plugin_list',
      'catalogue_list',
      'changeset_read',
      'retained_sync_copies',
      'retained_delete_ask',
      'retained_delete_finish',
      'retained_delete_cancel'
    ])
    // An acknowledgement belongs to the environment, so it names no session; an invitation names
    // the session it shares; the consequences are read for the selection alone.
    expect(shell.invoked[1]?.args).toEqual({
      params: { items: [{ key: 'key-1', revision: '4' }] },
      subject: {}
    })
    expect(shell.invoked[3]?.args).toEqual({ params: review, subject: {} })
    expect(shell.invoked[6]?.args).toEqual({ selection })
    expect(shell.invoked[7]?.args).toEqual({ params: grant, subject: { sessionId: SESSION } })
    // A hand-over names its session and the references it is later asked about by; an attempt is
    // named by its action alone, and nothing here names a method.
    const named = (command: string) => shell.invoked.find((each) => each.command === command)?.args
    expect(named('transfer_ask')).toEqual({
      params: { session_id: SESSION, from_grant_id: 'grant-1', to_device_id: 'device-2' },
      subject: { sessionId: SESSION }
    })
    expect(named('transfer_answered')).toEqual({ reference: 'reference-1' })
    expect(named('attempt_ask')).toEqual({ actionId: 'action-1' })
    expect(named('attempt_set_hidden')).toEqual({ actionId: 'action-1', hidden: true })
    expect(named('grant_revoke')).toEqual({ params: { grant_id: 'grant-1' } })
    expect(named('grant_held')).toEqual({})
    // Deleting a copy that left the host names the copy by the reference it is listed under and the
    // confirmation by the token the person's yes returned: never a method, never a parameter of one.
    expect(named('retained_sync_copies')).toEqual({})
    expect(named('retained_delete_ask')).toEqual({ reference: 'copy-1' })
    expect(named('retained_delete_finish')).toEqual({ token: 'token-1' })
    expect(named('retained_delete_cancel')).toEqual({ token: 'token-1' })
  })
})

describe('the desktop port and a session creation', () => {
  it('sends the creation to its own command, naming the environment and no session', async () => {
    const creation: SessionCreateParams = {
      environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
      presentation: 'invisible',
      shell: null,
      shell_mode: 'native_compat',
      cwd: '/Users/rs/work/notes',
      dimensions: null,
      worker_profile: 'desktop_bound',
      environment_snapshot: [],
      palette: null,
      launch_profile: { startup: 'host_default', fenced_launch: false, command_integrations: [] },
      terminal: null
    }
    await tauriPort().sessionCreate(creation, {})
    expect(shell.invoked).toEqual([
      { command: 'session_create', args: { params: creation, subject: {} } }
    ])
  })
})

describe('the desktop port and the connection state', () => {
  const lost = (reason: string | null, revision = 1): ConnectionState => ({
    connected: false,
    environment_id: null,
    reason,
    rights: null,
    paired: false,
    replaced: 0,
    revision,
    link: 1,
    host: null,
    contact: { state: 'unknown' },
    inbox_epoch: 0,
    others: []
  })

  /** What a view following the port hears when native code publishes `state`. */
  async function heard(state: ConnectionState): Promise<ConnectionState[]> {
    const states: ConnectionState[] = []
    tauriPort().watchConnection(
      (each) => {
        states.push(each)
      },
      () => undefined
    )
    await Promise.resolve()
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: state })
    return states
  }

  it('takes a blank reason in as no reason when it reads the state', async () => {
    for (const blank of ['', '   ', '\n\t ']) {
      shell.answers.set('connection_state', lost(blank))
      expect(await tauriPort().connectionState()).toEqual(lost(null))
    }
  })

  it('takes a blank reason in as no reason when it hears a change', async () => {
    for (const blank of ['', '   ', '\n\t ']) {
      expect(await heard(lost(blank))).toEqual([lost(null)])
    }
  })

  it('hands on a reason with words, and a live connection, as native code sent them', async () => {
    const said = lost('  the relay closed this connection ')
    shell.answers.set('connection_state', said)
    expect(await tauriPort().connectionState()).toEqual(said)
    expect(await heard(said)).toEqual([said])

    const live: ConnectionState = {
      ...lost(null, 2),
      connected: true,
      environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
      rights: ['session.view', 'agent.prompt'],
      paired: true,
      host: { kind: 'paired', reference: 'studio', name: 'Studio' },
      contact: { state: 'in_contact' },
      inbox_epoch: 1
    }
    shell.answers.set('connection_state', live)
    expect(await tauriPort().connectionState()).toEqual(live)
    expect(await heard(live)).toEqual([live])
  })

  it('asks native code for what the page missed above a revision, and takes in each state', async () => {
    shell.answers.set('connection_since', {
      revision: 3,
      resync: false,
      states: [lost('  ', 2), lost('the relay closed this connection', 3)]
    })
    const since = await tauriPort().connectionSince(1)
    expect(shell.invoked).toEqual([{ command: 'connection_since', args: { after: 1 } }])
    expect(since.revision).toBe(3)
    expect(since.resync).toBe(false)
    expect(since.states.map((state) => [state.revision, state.reason])).toEqual([
      [2, null],
      [3, 'the relay closed this connection']
    ])
  })
})

describe('the desktop port and an agent’s questions', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
  const QUESTION = 'b1000000-0000-4000-8000-000000000001'

  it('reads and answers a question with the method’s own parameters and nothing else', async () => {
    const port = tauriPort()
    await port.questionRead({ session_id: SESSION, question_id: null, include_resolved: false })
    await port.questionAnswer({
      session_id: SESSION,
      question_id: QUESTION,
      expected_revision: '2',
      answer: { kind: 'choice', choice_id: 'main' }
    })
    expect(shell.invoked).toEqual([
      {
        command: 'question_read',
        args: { params: { session_id: SESSION, question_id: null, include_resolved: false } }
      },
      {
        command: 'question_answer',
        args: {
          params: {
            session_id: SESSION,
            question_id: QUESTION,
            expected_revision: '2',
            answer: { kind: 'choice', choice_id: 'main' }
          }
        }
      }
    ])
  })

  it('settles, sends and dismisses a kept answer by naming the question and when it was given', async () => {
    const port = tauriPort()
    const which = { questionId: QUESTION, draftedAtMs: '1763000000001' }
    await port.questionKept()
    await port.questionSettle(SESSION)
    await port.questionSendKept(which)
    await port.questionDismissKept(which)
    expect(shell.invoked).toEqual([
      { command: 'question_kept', args: {} },
      { command: 'question_settle', args: { params: { sessionId: SESSION } } },
      { command: 'question_send_kept', args: { params: which } },
      { command: 'question_dismiss_kept', args: { params: which } }
    ])
  })
})

describe('the desktop port and the drafts this device keeps', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000102'
  const DRAFT = 'c1000000-0000-4000-8000-000000000001'

  it('names a draft, the version it replaces and nothing else the native commands refuse', async () => {
    const port = tauriPort()
    await port.deviceDrafts()
    await port.deviceDraftSave({
      id: DRAFT,
      expectedRevision: '2',
      sessionId: SESSION,
      applicationInstanceId: null,
      agentBindingRevision: null,
      state: 'open',
      text: 'half a thought',
      attachments: []
    })
    await port.deviceDraftRetarget({
      id: DRAFT,
      expectedRevision: '3',
      sessionId: SESSION,
      applicationInstanceId: null,
      agentBindingRevision: null
    })
    await port.deviceDraftDiscard({ id: DRAFT, expectedRevision: '4' })
    expect(shell.invoked).toEqual([
      { command: 'device_drafts', args: {} },
      {
        command: 'device_draft_save',
        args: {
          params: {
            id: DRAFT,
            expectedRevision: '2',
            sessionId: SESSION,
            applicationInstanceId: null,
            agentBindingRevision: null,
            state: 'open',
            text: 'half a thought',
            attachments: []
          }
        }
      },
      {
        command: 'device_draft_retarget',
        args: {
          params: {
            id: DRAFT,
            expectedRevision: '3',
            sessionId: SESSION,
            applicationInstanceId: null,
            agentBindingRevision: null
          }
        }
      },
      { command: 'device_draft_discard', args: { params: { id: DRAFT, expectedRevision: '4' } } }
    ])
  })
})

describe('the desktop port and a session screen’s opening', () => {
  const SESSION = '8a7b6c50-22bb-4c3d-8e4f-000000000101'
  const OPENING = 'opening-0001'
  const subject = {
    session_id: SESSION,
    application_instance_id: '8a7b6c50-22bb-4c3d-8e4f-000000000201'
  }
  const target = { subject, binding_revision: '3' }

  it('opens and leaves a session by the screen’s own token, naming the share when it holds one', async () => {
    const port = tauriPort()
    await port.openSession({ sessionId: SESSION, grantId: null, opening: OPENING })
    await port.openSession({ sessionId: SESSION, grantId: 'grant-1', opening: 'opening-0002' })
    await port.leaveSession(SESSION, OPENING)
    expect(shell.invoked).toEqual([
      { command: 'session_open', args: { sessionId: SESSION, grantId: null, opening: OPENING } },
      {
        command: 'session_open',
        args: { sessionId: SESSION, grantId: 'grant-1', opening: 'opening-0002' }
      },
      { command: 'session_leave', args: { sessionId: SESSION, opening: OPENING } }
    ])
  })

  it('hands on each standing native code publishes, with the opening it belongs to', async () => {
    const heard: unknown[] = []
    await tauriPort().onStanding((event) => {
      heard.push(event)
    })
    const event = {
      session_id: SESSION,
      opening: OPENING,
      standing: { state: 'ended', reason: 'revoked' }
    }
    shell.handlers.get(STANDING_EVENT)?.({ payload: event })
    expect(heard).toEqual([event])
  })

  it('carries the opening on every command about the session, and on none without one', async () => {
    const port = tauriPort()
    const prompt = { target, text: 'Summarise the diff', draft_id: null }
    await port.sessionAgents(SESSION, OPENING)
    await port.agentCapabilities({ subject }, OPENING)
    await port.agentSnapshot({ subject, from_node: '5' }, OPENING)
    await port.agentCommands({ subject }, OPENING)
    await port.composerSubmit(prompt, OPENING)
    await port.composerQueue(prompt, OPENING)
    await port.composerSteer({ target, text: 'Stop', turn_id: 'turn-2' }, OPENING)
    await port.composerInterrupt({ target, turn_id: 'turn-2' }, OPENING)
    await port.approvalRespond({ target, resource_id: 'resource-1', option_id: 'approve' }, OPENING)
    await port.questionRead({ session_id: SESSION, question_id: null, include_resolved: false }, OPENING)
    await port.sessionClose({ session_id: SESSION }, { sessionId: SESSION }, OPENING)
    await port.historyPage({ session_id: SESSION, from_cursor: '0', max_bytes: '65536' }, OPENING)
    const carried = shell.invoked.map((call) => (call.args as { opening?: string }).opening)
    expect(carried).toEqual(Array<string>(12).fill(OPENING))
    // A call made outside any screen names none, and native code serves it on a link of its own.
    shell.invoked.length = 0
    await port.sessionAgents(SESSION)
    await port.questionRead({ session_id: SESSION, question_id: null, include_resolved: false })
    expect(shell.invoked.map((call) => (call.args as { opening?: string }).opening)).toEqual([
      undefined,
      undefined
    ])
  })

  it('opens a terminal view under the screen’s opening', async () => {
    shell.answers.set('terminal_view_open', '7')
    await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined, OPENING, null)
    const [opened] = shell.invoked
    const args = opened?.args as { opening?: string; anchor?: unknown }
    expect({ opening: args.opening, anchor: args.anchor }).toEqual({ opening: OPENING, anchor: null })
  })

  it('opens a terminal view with the anchor of the place it restores, its row kept as a decimal string', async () => {
    shell.answers.set('terminal_view_open', '7')
    const anchor = {
      row: '9007199254740993',
      line: 0,
      column: 4,
      buffer: 'primary' as const,
      columns: 80,
      generation: '3',
      fingerprint: '12345678901234567890'
    }
    await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined, undefined, anchor)
    const [opened] = shell.invoked
    expect((opened?.args as { anchor?: unknown }).anchor).toEqual(anchor)
  })
})

/** The connection's state as native code publishes it, for the host of `environment` at `revision`. */
const published = (environment: string | null, revision: number, over: Record<string, unknown> = {}) => ({
  connected: environment !== null,
  environment_id: environment,
  reason: null,
  rights: [],
  paired: true,
  replaced: 0,
  revision,
  link: 1,
  host: environment === null ? null : { kind: 'paired', reference: environment, name: environment },
  contact: { state: 'in_contact' },
  inbox_epoch: environment === null ? 0 : 1,
  others: [],
  ...over
})

/** One host event as native code publishes it, following the state of `revision`. */
const hostEvent = (host: string, sequence: string, revision: number) => ({
  payload: { host, stream_id: 'session_state', sequence, event_type: 'x', payload: null, revision }
})

/** The page's end of a refusal, as native code sends it. */
const refusal = (user_action: string) => ({
  code: 'PERMISSION_DENIED',
  message: 'PERMISSION_DENIED: the host would not.',
  user_action,
  retry: 'no_retry'
})

/** Lets every promise that is ready run. */
async function settle(): Promise<void> {
  for (let turn = 0; turn < 8; turn += 1) await Promise.resolve()
}

/** A port that follows the connection and hears host events, with the first state heard. */
async function following(first: ReturnType<typeof published> = published('env-a', 1)) {
  const port = tauriPort()
  const heard: string[] = []
  await port.subscribe((event) => {
    heard.push(event.sequence)
  })
  port.watchConnection(
    () => undefined,
    () => undefined
  )
  await settle()
  shell.handlers.get(CONNECTION_EVENT)?.({ payload: first })
  return { port, heard }
}

describe('the desktop port and a host that changed', () => {
  it('drops an event of the host it no longer uses, and keeps the next host’s', async () => {
    const { heard } = await following()
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-b', 2) })
    // An event of the earlier host that was still on its way.
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '2', 2))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '3', 2))
    expect(heard).toEqual(['1', '3'])
  })

  it('holds an event until the state it follows has been taken in, and then takes it', async () => {
    const port = tauriPort()
    const heard: string[] = []
    await port.subscribe((event) => {
      heard.push(event.sequence)
    })
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))
    expect(heard).toEqual([])
    port.watchConnection(
      () => undefined,
      () => undefined
    )
    await settle()
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 1) })
    expect(heard).toEqual(['1'])
  })

  it('does not move the host back on a state older than one it has taken in', async () => {
    const { port, heard } = await following(published('env-b', 3))
    // A state of the earlier host arrives late.
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 2) })
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 3))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 3))
    expect(heard).toEqual(['2'])
    // And a replay that holds earlier states does not move it back either.
    shell.answers.set('connection_since', {
      revision: 2,
      resync: false,
      states: [published('env-a', 1), published('env-a', 2)]
    })
    await port.connectionSince(0)
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '3', 3))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '4', 3))
    expect(heard).toEqual(['2', '4'])
  })

  it('does not move the host back on a resync that answers after later states', async () => {
    const { heard } = await following(published('env-a', 1))
    let answer: (since: unknown) => void = () => undefined
    shell.answers.set(
      'connection_since',
      new Promise((resolve) => {
        answer = resolve
      })
    )
    // 3 is ahead of the page, so the replay is asked for; 2 and then 4 are heard while it is out, and
    // 4 names the next host.
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 3) })
    await settle()
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 2) })
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-b', 4) })
    // Native code says the page is too far behind, with the state it held when it was asked.
    answer({ revision: 3, resync: true, states: [published('env-a', 3)] })
    await settle()
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 4))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 4))
    expect(heard).toEqual(['2'])
  })

  it('takes the host of a resync that restarts native code when nothing was heard meanwhile', async () => {
    const { port, heard } = await following(published('env-a', 500))
    shell.answers.set('connection_since', {
      revision: 3,
      resync: true,
      states: [published('env-b', 3)]
    })
    await port.connectionSince(500)
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 3))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 3))
    expect(heard).toEqual(['2'])
  })

  it('tells the views no failure when a replay of what they missed cannot be read', async () => {
    const port = tauriPort()
    const shown: number[] = []
    const failures: unknown[] = []
    shell.answers.set('connection_state', published('env-a', 1))
    port.watchConnection(
      (state) => shown.push(state.revision),
      (failure) => failures.push(failure)
    )
    await settle()
    let fail: (failure: unknown) => void = () => undefined
    shell.answers.set(
      'connection_since',
      new Promise((_, reject) => {
        fail = reject
      })
    )
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 3) })
    await settle()
    fail(new Error('the replay could not be read'))
    await settle()
    expect(shown).toEqual([1])
    expect(failures).toEqual([])
  })

  it('holds the host events that are ahead of the feed and asks it to catch up', async () => {
    const { heard } = await following()
    shell.answers.set('connection_since', { revision: 3, resync: false, states: [] })
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 3))
    await settle()
    expect(heard).toEqual([])
    expect(shell.invoked.filter((each) => each.command === 'connection_since')).toEqual([
      { command: 'connection_since', args: { after: 1 } }
    ])
    // The missed states come: the event is released once the feed has applied its revision.
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 2) })
    expect(heard).toEqual([])
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 3) })
    expect(heard).toEqual(['1'])
  })

  it('an inbox_hosts answer above the cursor asks the feed to catch up', async () => {
    const { port } = await following()
    shell.answers.set('inbox_hosts', { revision: 4, hosts: [] })
    shell.answers.set('connection_since', { revision: 4, resync: false, states: [] })
    const answer = await port.inboxHosts()
    await settle()
    expect(answer).toEqual({ revision: 4, hosts: [] })
    expect(shell.invoked.filter((each) => each.command === 'connection_since')).toEqual([
      { command: 'connection_since', args: { after: 1 } }
    ])
  })

  it('an inbox_hosts answer at the cursor asks the feed for nothing', async () => {
    const { port } = await following()
    shell.answers.set('inbox_hosts', { revision: 1, hosts: [] })
    await port.inboxHosts()
    await settle()
    expect(shell.invoked.filter((each) => each.command === 'connection_since')).toEqual([])
  })

  it('holds at most 256 events and delivers one resync after the ones it kept', async () => {
    const { heard } = await following()
    shell.answers.set('connection_since', new Promise(() => undefined))
    for (let sequence = 1; sequence <= 300; sequence += 1) {
      shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', String(sequence), 2))
    }
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 2) })
    // The 44 oldest were dropped; the rest come in order, and the one resync comes after them.
    expect(heard).toHaveLength(257)
    expect(heard[0]).toBe('45')
    expect(heard[255]).toBe('300')
    expect(heard[256]).toBe('')
  })

  it('releases the resync together with the held events and after them', async () => {
    const { heard } = await following()
    shell.answers.set('connection_since', new Promise(() => undefined))
    for (let sequence = 1; sequence <= 258; sequence += 1) {
      shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', String(sequence), 2))
    }
    // While the state is not applied nothing is released, the resync included.
    expect(heard).toEqual([])
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 2) })
    expect(heard.slice(0, 2)).toEqual(['3', '4'])
    expect(heard.at(-1)).toBe('')
    expect(heard.filter((each) => each === '')).toHaveLength(1)
  })
})

describe('the desktop port and a host being chosen', () => {
  it('takes no event of the host it is leaving until the connection names the new one', async () => {
    const { port, heard } = await following()
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))

    // The host is chosen: the connection says nothing yet, and the old host's events are not heard.
    let answer: (state: unknown) => void = () => undefined
    shell.answers.set(
      'hosts_use',
      new Promise((resolve) => {
        answer = resolve
      })
    )
    const choosing = port.hostsUse('host-b')
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '2', 1))
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-b', 2) })
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '3', 2))
    answer(published('env-b', 2))
    await choosing
    expect(heard).toEqual(['1', '3'])
  })

  it.each(['hosts_use', 'hosts_forget'] as const)(
    'goes on taking the events of the host in use when %s is refused, and restores the confirmed host',
    async (command) => {
      const { port, heard } = await following()
      shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))

      // Native code refuses the choice and changes nothing: no connection event comes, and no revision.
      const refused = Promise.reject(new Error('That host is not in the list.'))
      refused.catch(() => undefined)
      shell.answers.set(command, refused)
      shell.answers.set('connection_state', published('env-a', 1))
      await expect(
        command === 'hosts_use' ? port.hostsUse('host-x') : port.hostsForget('host-x')
      ).rejects.toThrow('That host is not in the list.')

      shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '2', 1))
      expect(heard).toEqual(['1', '2'])
    }
  )

  it('restores the confirmed host when the choice changed nothing and made no revision', async () => {
    const { port, heard } = await following()
    // Choosing the host already in use: native code answers the state it already had.
    shell.answers.set('hosts_use', published('env-a', 1))
    await port.hostsUse('env-a')
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))
    expect(heard).toEqual(['1'])
  })

  it('applies only the newest choice’s reply when choices overlap', async () => {
    const { port, heard } = await following()
    let answerFirst: (state: unknown) => void = () => undefined
    let answerSecond: (state: unknown) => void = () => undefined
    shell.answers.set(
      'hosts_use',
      new Promise((resolve) => {
        answerFirst = resolve
      })
    )
    const first = port.hostsUse('host-b')
    shell.answers.set(
      'hosts_use',
      new Promise((resolve) => {
        answerSecond = resolve
      })
    )
    const second = port.hostsUse('host-c')
    answerSecond(published('env-c', 3))
    await second
    // The first choice's answer comes late, and names a revision that is not below the last.
    answerFirst(published('env-b', 4))
    await first
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '1', 1))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-c', '2', 1))
    expect(heard).toEqual(['2'])
  })

  it('takes events as they come when a choice is refused and the connection cannot say which host is in use', async () => {
    const { port, heard } = await following()

    const refused = Promise.reject(new Error('That host is not in the list.'))
    refused.catch(() => undefined)
    const unread = Promise.reject(new Error('The connection could not be read.'))
    unread.catch(() => undefined)
    shell.answers.set('hosts_use', refused)
    shell.answers.set('connection_state', unread)
    await expect(port.hostsUse('host-x')).rejects.toThrow('That host is not in the list.')

    // Nothing says which host is in use, so nothing is dropped, as before any host was known.
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 1))
    expect(heard).toEqual(['1', '2'])
  })

  it('keeps what the connection said when a read made before it answers after it', async () => {
    const port = tauriPort()
    const heard: string[] = []
    await port.subscribe((event) => {
      heard.push(event.sequence)
    })
    port.watchConnection(
      () => undefined,
      () => undefined
    )
    await settle()
    let answer: (state: unknown) => void = () => undefined
    shell.answers.set(
      'connection_state',
      new Promise((resolve) => {
        answer = resolve
      })
    )
    const reading = port.connectionState()
    // The connection names the next host while the read is on its way, and the read then answers with
    // the host before.
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-b', 2) })
    answer(published('env-a', 1))
    await reading
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 2))
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 2))
    expect(heard).toEqual(['2'])
  })

  it('cannot be put back on the old host by a state read or told again while a choice is out', async () => {
    const { port, heard } = await following()
    let answerRead: (state: unknown) => void = () => undefined
    shell.answers.set(
      'connection_state',
      new Promise((resolve) => {
        answerRead = resolve
      })
    )
    // A one-shot read begins, and then the host is chosen.
    const reading = port.connectionState()
    let answer: (state: unknown) => void = () => undefined
    shell.answers.set(
      'hosts_use',
      new Promise((resolve) => {
        answer = resolve
      })
    )
    const choosing = port.hostsUse('host-b')
    // The read answers with the state it saw before the choice, and the same state is told again.
    answerRead(published('env-a', 1))
    await reading
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-a', 1) })
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-a', '1', 1))
    expect(heard).toEqual([])
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: published('env-b', 2) })
    answer(published('env-b', 2))
    await choosing
    shell.handlers.get(HOST_EVENT)?.(hostEvent('env-b', '2', 2))
    expect(heard).toEqual(['2'])
  })
})

describe('the desktop port and a refusal in the connection state', () => {
  const refused = (user_action: string) => ({
    state: 'refused',
    refusal: refusal(user_action),
    request: 'connection'
  })

  it('makes the refusal of the host in use the page’s failure with the action’s words, from a read, a change, a choice and a replay', async () => {
    const port = tauriPort()
    const said = published('env-a', 2, { contact: refused('sign_in') })
    const line = 'the host would not. Sign in to your account.'
    const contactOf = (state: { readonly contact: unknown }) => state.contact as { state: string; refusal: { line: string } }

    shell.answers.set('connection_state', said)
    expect(contactOf(await port.connectionState()).refusal.line).toBe(line)

    shell.answers.set('hosts_use', said)
    expect(contactOf(await port.hostsUse('x')).refusal.line).toBe(line)
    shell.answers.set('hosts_forget', said)
    expect(contactOf(await port.hostsForget('x')).refusal.line).toBe(line)

    shell.answers.set('connection_since', { revision: 2, resync: false, states: [said] })
    const replay = await port.connectionSince(1)
    expect(contactOf(replay.states[0] as never).refusal.line).toBe(line)

    const told: { contact: unknown }[] = []
    port.watchConnection(
      (each) => {
        told.push(each)
      },
      () => undefined
    )
    await settle()
    shell.handlers.get(CONNECTION_EVENT)?.({ payload: said })
    expect(contactOf(told[0] as never).refusal.line).toBe(line)
  })

  it('keeps the action’s words of another host’s refusal', async () => {
    const port = tauriPort()
    const said = published('env-a', 2, {
      others: [
        { reference: 'b', name: 'B', contact: refused('pair_again'), inbox_epoch: 3 },
        { reference: 'c', name: 'C', contact: { state: 'out_of_contact', since_ms: 5, escalates_at_ms: 9 }, inbox_epoch: 1 }
      ]
    })
    shell.answers.set('connection_state', said)
    const state = await port.connectionState()
    const [b, c] = state.others
    expect(b?.contact).toMatchObject({
      state: 'refused',
      request: 'connection',
      refusal: { line: expect.stringContaining('Pair this device with the host again.') as unknown }
    })
    expect(c?.contact).toEqual({ state: 'out_of_contact', since_ms: 5, escalates_at_ms: 9 })
  })
})

describe('the desktop port and recovery', () => {
  it('sends the sync service and each recovery step to its own command, naming no secret', async () => {
    const port = tauriPort()
    await port.syncServiceView()
    await port.syncServiceSet('https://sync.example')
    await port.recoveryView()
    await port.recoveryTurnOn()
    await port.recoverySettle()
    await port.recoverySaveKit('/tmp/kit.txt')
    await port.recoveryCoverHost(false)
    await port.recoveryCoverHost(true)
    await port.recoverySaveKitQr('/tmp/kit.svg')
    await port.recoveryArchives()
    await port.recoveryExportOffline('/tmp/copy.krexport', 'archive-1')
    await port.recoveryExportOffline('/tmp/bundle.krexport', null)
    await port.accountSignInForRecovery()
    expect(shell.invoked).toEqual([
      { command: 'sync_service_view', args: {} },
      { command: 'sync_service_set', args: { origin: 'https://sync.example' } },
      { command: 'recovery_view', args: {} },
      { command: 'recovery_turn_on', args: {} },
      { command: 'recovery_settle', args: {} },
      { command: 'recovery_save_kit', args: { path: '/tmp/kit.txt' } },
      { command: 'recovery_cover_host', args: { replace: false } },
      { command: 'recovery_cover_host', args: { replace: true } },
      { command: 'recovery_save_kit_qr', args: { path: '/tmp/kit.svg' } },
      { command: 'recovery_archives', args: {} },
      {
        command: 'recovery_export_offline',
        args: { path: '/tmp/copy.krexport', archive: 'archive-1' }
      },
      { command: 'recovery_export_offline', args: { path: '/tmp/bundle.krexport', archive: null } },
      { command: 'account_sign_in_for_recovery', args: {} }
    ])
  })
})

describe('the desktop port and the person\'s settings', () => {
  it('sends each settings step to its own command, naming a mode and nothing else', async () => {
    const port = tauriPort()
    await port.settingsView()
    await port.settingsSetColourMode('dark')
    await port.settingsSyncTurnOn()
    await port.settingsSyncNow()
    await port.settingsDraftsSet(true)
    expect(shell.invoked).toEqual([
      { command: 'settings_view', args: {} },
      { command: 'settings_colour_mode_set', args: { mode: 'dark' } },
      { command: 'settings_sync_turn_on', args: {} },
      { command: 'settings_sync_now', args: {} },
      { command: 'settings_drafts_set', args: { enabled: true } }
    ])
  })

  it('names a device or an offer by its reference and nothing else', async () => {
    const port = tauriPort()
    await port.settingsDevicesRefresh()
    await port.settingsDeviceShare('phone')
    await port.settingsDeviceRemove('phone')
    await port.settingsJoin('offer')
    await port.settingsDevicesDismiss()
    expect(shell.invoked).toEqual([
      { command: 'settings_devices_refresh', args: {} },
      { command: 'settings_device_share', args: { reference: 'phone' } },
      { command: 'settings_device_remove', args: { reference: 'phone' } },
      { command: 'settings_join', args: { reference: 'offer' } },
      { command: 'settings_devices_dismiss', args: {} }
    ])
  })

  it('asks for the versions waiting for a choice, and sends the choice by the word the backend reads', async () => {
    await tauriPort().settingsConflicts()
    await tauriPort().settingsConflictResolve({ choice: 'mine' })
    await tauriPort().settingsConflictResolve({ choice: 'copy', conflict_id: 'copy-1' })
    expect(shell.invoked).toEqual([
      { command: 'settings_conflicts', args: {} },
      { command: 'settings_conflict_resolve', args: { keep: { choice: 'mine' } } },
      {
        command: 'settings_conflict_resolve',
        args: { keep: { choice: 'copy', conflict_id: 'copy-1' } }
      }
    ])
  })

  it('hands on the settings native code publishes', async () => {
    const heard: unknown[] = []
    await tauriPort().onSettings((view) => {
      heard.push(view)
    })
    const published = { colour_mode: 'light' }
    shell.handlers.get(SETTINGS_EVENT)?.({ payload: published })
    expect(heard).toEqual([published])
  })
})
