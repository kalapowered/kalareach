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

import type { GrantCreateParams, RoleSelection } from '@kalareach/protocol'

import type { ConnectionState } from '../src/host/port'
import { CONNECTION_EVENT, tauriPort } from '../src/host/tauri'

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
    await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, (state) => {
      heard.push(state)
    })
    expect(shell.invoked).toHaveLength(1)
    const [opened] = shell.invoked
    expect(opened?.command).toBe('terminal_view_open')
    const args = opened?.args as {
      sessionId: string
      columns: number
      rows: number
      onState: { onmessage: (message: unknown) => void }
    }
    expect({ sessionId: args.sessionId, columns: args.columns, rows: args.rows }).toEqual({
      sessionId: SESSION,
      columns: 80,
      rows: 24
    })
    // What native code publishes on the view's channel reaches the view's listener, and only it.
    const ended = { state: 'ended', reason: 'This session has closed.' }
    args.onState.onmessage(ended)
    expect(heard).toEqual([ended])
  })

  it('sends the size, the moves and the close to their own commands, with the handle the open answered', async () => {
    shell.answers.set('terminal_view_open', '7')
    const view = await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined)
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
    const view = await tauriPort().openTerminalView(SESSION, { columns: 80, rows: 24 }, () => undefined)
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
    await port.grantNotices(selection)
    await port.grantCreate(grant, { sessionId: SESSION })
    await port.grantList({ session_id: SESSION, include_resolved: false })
    await port.pluginList({ environment_id: environment })
    await port.catalogueList({ environment_id: environment })
    await port.changesetRead({ change_set_id: 'change-1', version: null })
    expect(shell.invoked.map((each) => each.command)).toEqual([
      'attention_read',
      'attention_acknowledge',
      'review_read',
      'review_acknowledge',
      'device_list',
      'grant_notices',
      'grant_create',
      'grant_list',
      'plugin_list',
      'catalogue_list',
      'changeset_read'
    ])
    // An acknowledgement belongs to the environment, so it names no session; an invitation names
    // the session it shares; the consequences are read for the selection alone.
    expect(shell.invoked[1]?.args).toEqual({
      params: { items: [{ key: 'key-1', revision: '4' }] },
      subject: {}
    })
    expect(shell.invoked[3]?.args).toEqual({ params: review, subject: {} })
    expect(shell.invoked[5]?.args).toEqual({ selection })
    expect(shell.invoked[6]?.args).toEqual({ params: grant, subject: { sessionId: SESSION } })
  })
})

describe('the desktop port and the connection state', () => {
  const lost = (reason: string | null): ConnectionState => ({
    connected: false,
    environment_id: null,
    reason,
    rights: null
  })

  /** What a listener registered through the port hears when native code publishes `state`. */
  async function heard(state: ConnectionState): Promise<ConnectionState[]> {
    const states: ConnectionState[] = []
    await tauriPort().onConnection((each) => {
      states.push(each)
    })
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
      connected: true,
      environment_id: '3f1a2c40-11aa-4b2c-9d3e-000000000001',
      reason: null,
      rights: ['session.view', 'agent.prompt']
    }
    shell.answers.set('connection_state', live)
    expect(await tauriPort().connectionState()).toEqual(live)
    expect(await heard(live)).toEqual([live])
  })
})
