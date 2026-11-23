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
import type { Place } from '../src/app/state'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

type Controls = ReturnType<typeof fakeHost>['controls']

/** Opens the session's conversation with the host as `arrange` leaves it. */
function open(
  arrange: (controls: Controls) => void,
  channel = true,
  place: Place = { view: 'session', sessionId: SESSION_MAIN, pane: 'semantic' }
): Controls {
  const { port, controls } = fakeHost()
  if (channel) controls.records.useChannel(SESSION_MAIN, 0)
  arrange(controls)
  render(
    <AppProvider port={port} initialPlace={place}>
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
    // The approval is drawn from the approvals' own read, and the notice from the conversation's
    // read of the instance's capabilities, which is not that read. The turn below lets what both
    // queued run before the absence is asserted.
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

describe('the inbox card of an approval that cannot be answered here', () => {
  const card = () => screen.findByTestId('approval')

  it('offers_the_terminal_beside_the_disabled_decisions_in_the_conversations_words', async () => {
    open(
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      true,
      { view: 'attention' }
    )
    const approval = await card()
    expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeDisabled()
    const offer = await within(approval).findByTestId('approval-offer')
    expect(offer).toHaveTextContent('Claude Code asks for approvals in its terminal. Answer them there.')
    expect(within(offer).getByTestId('approval-offer-reason')).toHaveTextContent(
      'This device cannot answer Claude Code’s approvals. Channels has not shown that it is on for this session.'
    )
    await userEvent.click(within(offer).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true')
    })
  })

  it('without_the_right_to_type_the_card_says_so_and_offers_no_button', async () => {
    open(
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
        controls.setRights(['session.view', 'agent.prompt'])
      },
      true,
      { view: 'attention' }
    )
    const approval = await card()
    const offer = await within(approval).findByTestId('approval-offer')
    expect(offer).toHaveTextContent(
      'This device cannot type in the terminal, so it cannot answer Claude Code’s approvals.'
    )
    expect(within(offer).queryByRole('button')).toBeNull()
  })

  it('a_live_channel_leaves_the_card_without_an_offer', async () => {
    open(() => undefined, true, { view: 'attention' })
    const approval = await card()
    await waitFor(() => {
      expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeEnabled()
    })
    expect(within(approval).queryByTestId('approval-offer')).toBeNull()
  })

  it('an_agent_that_does_not_use_channels_gets_no_offer_on_its_card', async () => {
    open(
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      false,
      { view: 'attention' }
    )
    const approval = await card()
    await within(approval).findByTestId('approval-unavailable')
    expect(within(approval).queryByTestId('approval-offer')).toBeNull()
  })
})

describe('the notice while the host suspends rich mutations', () => {
  const FENCE =
    'the record store has a fault, so messages, steering, interrupts and approvals wait until it works again; the terminal goes on working'
  const SENTENCE =
    'The record store has a fault, so messages, steering, interrupts and approvals wait until it works again; the terminal goes on working.'

  it('gives_the_hosts_reason_as_a_sentence_and_offers_the_terminal', async () => {
    open((controls) => {
      controls.records.suspend(SESSION_MAIN, FENCE)
    })
    const region = await notice()
    expect(region).toHaveTextContent('Claude Code asks for approvals in its terminal. Answer them there.')
    expect(within(region).getByTestId('approval-offer-reason')).toHaveTextContent(SENTENCE)
    await userEvent.click(within(region).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(screen.getByRole('tab', { name: 'Terminal' })).toHaveAttribute('aria-selected', 'true')
    })
  })

  it('draws_the_decisions_disabled_with_the_same_sentence_on_the_card_in_the_conversation', async () => {
    open((controls) => {
      controls.records.suspend(SESSION_MAIN, FENCE)
    })
    const approval = await screen.findByTestId('approval')
    expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeDisabled()
    expect(within(approval).getByTestId('approval-unavailable')).toHaveTextContent(SENTENCE)
  })

  it('names_the_reason_on_the_inbox_card_once', async () => {
    open(
      (controls) => {
        controls.records.suspend(SESSION_MAIN, FENCE)
      },
      true,
      { view: 'attention' }
    )
    const approval = await screen.findByTestId('approval')
    const offer = await within(approval).findByTestId('approval-offer')
    expect(within(offer).getByTestId('approval-offer-reason')).toHaveTextContent(SENTENCE)
    expect(within(approval).queryByTestId('approval-unavailable')).toBeNull()
  })

  it('a_record_that_is_not_usable_gives_its_own_reason_before_the_suspension', async () => {
    open((controls) => {
      controls.records.setCapability(
        SESSION_MAIN,
        'agent.approval',
        'incompatible',
        'This version of Claude Code does not relay approvals.'
      )
      controls.records.suspend(SESSION_MAIN, FENCE)
    })
    const region = await notice()
    const reason = within(region).getByTestId('approval-offer-reason')
    expect(reason).toHaveTextContent('This version of Claude Code does not relay approvals.')
    expect(reason).not.toHaveTextContent('record store')
  })

  it('an_instance_with_its_own_refusal_gives_it_before_the_suspension', async () => {
    open((controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      controls.records.refuseInstance(SESSION_MAIN, 'The launch did not keep the channel flag.')
      controls.records.suspend(SESSION_MAIN, FENCE)
    })
    const region = await notice()
    const reason = within(region).getByTestId('approval-offer-reason')
    expect(reason).toHaveTextContent('The launch did not keep the channel flag.')
    expect(reason).not.toHaveTextContent('record store')
  })

  it('an_agent_that_does_not_use_channels_gets_no_notice_for_a_suspension', async () => {
    open((controls) => {
      controls.records.suspend(SESSION_MAIN, FENCE)
    }, false)
    await screen.findByTestId('approval')
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('lifting_the_suspension_takes_the_notice_away', async () => {
    const controls = open((each) => {
      each.records.suspend(SESSION_MAIN, FENCE)
    })
    await notice()
    act(() => {
      controls.records.suspend(SESSION_MAIN, null)
    })
    await waitFor(() => {
      expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
    })
  })
})
