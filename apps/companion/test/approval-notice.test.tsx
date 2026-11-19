/**
 * An agent that asks for approvals in its terminal says so, and why they are not answered here
 * (KR-REQ-12.25).
 *
 * These render the real application against the scripted host, whose instance is one of Claude
 * Code and whose capability records a case sets.
 */

import { describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { App } from '../src/App'
import { AppProvider } from '../src/app/state'
import { fakeHost } from '../src/host/fake'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

type Controls = ReturnType<typeof fakeHost>['controls']

/** Opens the session's conversation with the host as `arrange` leaves it. */
function open(arrange: (controls: Controls) => void, channel = true): Controls {
  const { port, controls } = fakeHost()
  if (channel) controls.records.useChannel(SESSION_MAIN, 0)
  arrange(controls)
  render(
    <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
      <App />
    </AppProvider>
  )
  return controls
}

const notice = () => screen.findByRole('region', { name: 'Approvals' })

describe('the notice about approvals', () => {
  it('without_a_channel_record_the_session_says_approvals_are_answered_in_the_terminal', async () => {
    open((controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    })
    const region = await notice()
    expect(region).toHaveTextContent('Claude Code asks for approvals in its terminal. Answer them there.')
    expect(region).toHaveTextContent(
      'This device cannot answer Claude Code’s approvals. Channels has not shown that it is on for this session.'
    )
    await userEvent.click(within(region).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true')
    })
    expect(within(region).queryByTestId('approval')).toBeNull()
  })

  it('a_record_that_is_not_available_says_why', async () => {
    open((controls) => {
      controls.records.setCapability(
        SESSION_MAIN,
        'agent.approval',
        'temporarily_unavailable',
        'The channel is being restarted.'
      )
    })
    expect(await notice()).toHaveTextContent('The channel is being restarted.')
  })

  it.each([
    ['version_qualified', /was qualified, but nothing has shown/],
    ['missing_installation', /Channels connection is not installed/],
    ['permission_required', /operating-system permission is needed/],
    ['incompatible', /cannot relay approvals to this host/],
    ['temporarily_unavailable', /Channels is not available at the moment/],
    ['not_tested', /Nothing has shown yet whether approvals can be answered/]
  ] as const)('a_record_that_is_%s_and_gives_no_reason_gets_one_sentence_of_its_state', async (state, words) => {
    open((controls) => {
      controls.records.setCapabilityWithoutReason(SESSION_MAIN, 'agent.approval', state)
    })
    expect(await notice()).toHaveTextContent(words)
  })

  it('without_the_right_to_type_or_a_connection_the_notice_offers_no_terminal_button', async () => {
    open((controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      controls.setRights(['session.view', 'agent.prompt'])
    })
    const region = await notice()
    expect(region).toHaveTextContent(
      'This device cannot type in the terminal, so it cannot answer Claude Code’s approvals.'
    )
    expect(within(region).queryByRole('button')).toBeNull()
  })

  it('without_a_connection_the_notice_offers_no_terminal_button', async () => {
    const controls = open((each) => {
      each.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    })
    await notice()
    act(() => {
      controls.setConnected(false)
    })
    await waitFor(() => {
      expect(screen.getByRole('region', { name: 'Approvals' })).toHaveTextContent(
        'This device is not connected, so it cannot answer Claude Code’s approvals.'
      )
    })
    expect(within(screen.getByRole('region', { name: 'Approvals' })).queryByRole('button')).toBeNull()
  })

  it('a_live_channel_shows_no_notice', async () => {
    open(() => undefined)
    await screen.findByTestId('approval')
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('before_the_records_are_read_the_notice_says_nothing', async () => {
    const { port, controls } = fakeHost()
    controls.records.useChannel(SESSION_MAIN, 0)
    controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    const held = controls.hold('agentCapabilities')
    render(
      <AppProvider port={port} initialPlace={{ view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }}>
        <App />
      </AppProvider>
    )
    await waitFor(() => {
      expect(held.count).toBeGreaterThan(0)
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
    held.release()
    expect(await notice()).toBeInTheDocument()
  })

  it('an_agent_that_does_not_use_channels_gets_no_notice', async () => {
    open((controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    }, false)
    // The request is read with the instance's capabilities, so once it is shown the notice has what
    // it needs to appear, and its absence is a decision and not a page that has not read yet.
    await screen.findByTestId('approval')
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('an_instance_that_carries_a_refusal_shows_it_in_the_notice', async () => {
    open((controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      controls.records.refuseInstance(SESSION_MAIN, 'The launch did not keep the channel flag.')
    })
    const region = await notice()
    expect(region).toHaveTextContent('The launch did not keep the channel flag.')
    expect(region).not.toHaveTextContent('Channels has not shown that it is on for this session.')
  })
})
