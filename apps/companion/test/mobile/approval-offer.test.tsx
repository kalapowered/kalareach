/**
 * An agent that asks for approvals in its terminal is answered there, from the phone too
 * (KR-REQ-12.25).
 *
 * These render the phone's shell against the scripted host, whose instance is one of Claude Code
 * and whose capability records a case sets, on each of the two platforms in turn.
 */

import { afterEach, describe, expect, it } from 'vitest'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import { MobileApp } from '../../src/mobile/MobileApp'
import type { MobilePlatform } from '../../src/mobile/platform'

const SESSION_MAIN = '8a7b6c50-22bb-4c3d-8e4f-000000000101'

const PLATFORMS: readonly MobilePlatform[] = ['ios', 'android']

const FENCE =
  'approvals cannot be recorded while the record store has a fault, so they are answered in the terminal, which goes on working'
const SENTENCE =
  'Approvals cannot be recorded while the record store has a fault, so they are answered in the terminal, which goes on working.'
const NO_RECORD =
  'This device cannot answer Claude Code’s approvals. Channels has not shown that it is on for this session.'

/** Starts the phone's shell as `arrange` leaves the host, on the inbox or inside the session. */
function start(
  surface: MobilePlatform,
  arrange: (controls: FakeHostControls) => void,
  { channel = true, inSession = false }: { channel?: boolean; inSession?: boolean } = {}
): FakeHostControls {
  const { port, controls } = fakeHost()
  if (channel) controls.records.useChannel(SESSION_MAIN, 0)
  arrange(controls)
  if (inSession) window.history.replaceState({}, '', `/?session=${SESSION_MAIN}`)
  render(
    <AppProvider port={port}>
      <MobileApp surface={surface} storage={null} />
    </AppProvider>
  )
  return controls
}

afterEach(() => {
  window.history.replaceState({}, '', '/')
})

/** The pane the session screen shows. */
const paneShown = () => document.querySelector('[data-pane]')?.getAttribute('data-pane') ?? null

/** Opens the inbox row of the approval and gives its card in the sheet. */
async function openCard(): Promise<HTMLElement> {
  const row = await screen.findByRole('button', {
    name: /Waiting for you\. Codex asks to run scripts\/release\.sh --publish/
  })
  await userEvent.click(row)
  return screen.findByTestId('approval')
}

describe.each(PLATFORMS)('the %s inbox sheet of an approval that cannot be answered here', (surface) => {
  it('offers_the_terminal_beside_the_disabled_decisions_in_the_conversations_words', async () => {
    start(surface, (controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    })
    const approval = await openCard()
    expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeDisabled()
    const offer = await within(approval).findByTestId('approval-offer')
    expect(offer).toHaveTextContent('Claude Code asks for approvals in its terminal. Answer them there.')
    expect(within(offer).getByTestId('approval-offer-reason')).toHaveTextContent(NO_RECORD)
    expect(within(approval).queryByTestId('approval-unavailable')).toBeNull()
    await userEvent.click(within(offer).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(paneShown()).toBe('terminal')
    })
  })

  it('gives_the_hosts_reason_for_a_suspension_as_a_sentence', async () => {
    start(surface, (controls) => {
      controls.records.suspend(SESSION_MAIN, FENCE)
    })
    const approval = await openCard()
    const offer = await within(approval).findByTestId('approval-offer')
    expect(within(offer).getByTestId('approval-offer-reason')).toHaveTextContent(SENTENCE)
    await userEvent.click(within(offer).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(paneShown()).toBe('terminal')
    })
  })

  it('without_the_right_to_type_the_sheet_says_so_and_offers_no_button', async () => {
    start(surface, (controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      controls.setRights(['session.view', 'agent.prompt'])
    })
    const approval = await openCard()
    const offer = await within(approval).findByTestId('approval-offer')
    expect(offer).toHaveTextContent(
      'This device cannot type in the terminal, so it cannot answer Claude Code’s approvals.'
    )
    expect(within(offer).queryByRole('button')).toBeNull()
  })

  it('a_live_channel_leaves_the_sheet_without_an_offer', async () => {
    start(surface, () => undefined)
    const approval = await openCard()
    await waitFor(() => {
      expect(within(approval).getByRole('button', { name: 'Allow once' })).toBeEnabled()
    })
    expect(within(approval).queryByTestId('approval-offer')).toBeNull()
  })

  it('an_agent_that_does_not_use_channels_gets_no_offer_in_the_sheet', async () => {
    start(
      surface,
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      { channel: false }
    )
    const approval = await openCard()
    await within(approval).findByTestId('approval-unavailable')
    expect(within(approval).queryByTestId('approval-offer')).toBeNull()
  })

  it('the_footer_still_opens_the_session_on_its_conversation', async () => {
    start(surface, (controls) => {
      controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
    })
    await openCard()
    await userEvent.click(screen.getByRole('button', { name: 'Open the session' }))
    await screen.findByTestId('mobile-conversation')
    expect(paneShown()).toBe('semantic')
  })
})

describe.each(PLATFORMS)('the %s session screen of an agent that asks for approvals in its terminal', (surface) => {
  const notice = () => screen.findByRole('region', { name: 'Approvals' })

  it('draws_the_notice_the_desktop_draws_and_offers_the_terminal', async () => {
    start(
      surface,
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      { inSession: true }
    )
    const region = await notice()
    expect(region).toHaveTextContent('Claude Code asks for approvals in its terminal. Answer them there.')
    expect(within(region).getByTestId('approval-offer-reason')).toHaveTextContent(NO_RECORD)
    expect(paneShown()).toBe('semantic')
    await userEvent.click(within(region).getByRole('button', { name: 'Open the terminal' }))
    await waitFor(() => {
      expect(paneShown()).toBe('terminal')
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('gives_the_hosts_reason_for_a_suspension_as_a_sentence', async () => {
    start(surface, (controls) => controls.records.suspend(SESSION_MAIN, FENCE), { inSession: true })
    const region = await notice()
    expect(within(region).getByTestId('approval-offer-reason')).toHaveTextContent(SENTENCE)
  })

  it('without_the_right_to_type_it_offers_no_button', async () => {
    start(
      surface,
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
        controls.setRights(['session.view', 'agent.prompt'])
      },
      { inSession: true }
    )
    const region = await notice()
    expect(region).toHaveTextContent(
      'This device cannot type in the terminal, so it cannot answer Claude Code’s approvals.'
    )
    expect(within(region).queryByRole('button')).toBeNull()
  })

  it('a_live_channel_shows_no_notice', async () => {
    start(surface, () => undefined, { inSession: true })
    await screen.findByTestId('mobile-conversation')
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('an_agent_that_does_not_use_channels_gets_no_notice', async () => {
    start(
      surface,
      (controls) => {
        controls.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      { channel: false, inSession: true }
    )
    await screen.findByTestId('mobile-conversation')
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0))
    })
    expect(screen.queryByRole('region', { name: 'Approvals' })).toBeNull()
  })

  it('without_a_connection_the_notice_offers_no_terminal_button', async () => {
    const controls = start(
      surface,
      (each) => {
        each.records.withoutCapability(SESSION_MAIN, 'agent.approval')
      },
      { inSession: true }
    )
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
})
