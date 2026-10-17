/**
 * What is shared with a phone, as the person sees it: the invitations at the head of the inbox, the
 * shares at the head of the sessions, and what each says when the host or the connection does not
 * do what was hoped.
 *
 * The scripted host stands in for native code and answers the two commands as they do. What these
 * hold the page to is what the person reads and can do: the card says what accepting lets the phone
 * do in the host's own terms, accepting commits once on a completed press, a refusal of the first
 * send is the host's sentence and never a claim that nothing was accepted, the list the host gives
 * decides what is held and what has ended, and a guest, whose pairing holds no view of any session,
 * has an inbox and a sessions list that say so rather than fail. The same flows run against a real
 * host in the backend's suite.
 */

import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'

import { AppProvider } from '../../src/app/state'
import { fakeHost, type FakeHostControls } from '../../src/host/fake'
import type { HostPort } from '../../src/host/port'
import { bookOf } from '../../src/model/held-shares'
import { MobileApp } from '../../src/mobile/MobileApp'

afterEach(() => {
  cleanup()
  window.history.replaceState({}, '', '/')
})

interface Phone {
  readonly controls: FakeHostControls
  readonly port: HostPort
}

/**
 * A phone paired with the scripted host, a guest unless `rights` say otherwise. `through` puts
 * something of the test's own between the page and the host's port.
 */
function start(options?: {
  readonly host?: string
  readonly rights?: readonly string[]
  readonly before?: (c: FakeHostControls) => void
  readonly through?: (port: HostPort) => HostPort
}): Phone {
  const { port: host, controls } = fakeHost()
  const port = options?.through === undefined ? host : options.through(host)
  controls.reachAsPhone({
    ...(options?.rights === undefined ? {} : { rights: options.rights as never }),
    ...(options?.host === undefined ? {} : { host: options.host })
  })
  options?.before?.(controls)
  render(
    <AppProvider port={port}>
      <MobileApp surface="ios" storage={null} />
    </AppProvider>
  )
  return { controls, port }
}

/** Lets what is already on its way finish, for a test that asserts nothing happened. */
async function settled(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0))
  })
}

async function openTab(name: string): Promise<void> {
  await userEvent.click(await screen.findByRole('button', { name }))
}

/** Reads the host's list again now, as the five-second cadence does. */
async function readAgain(port: HostPort): Promise<void> {
  await act(async () => {
    bookOf(port).refresh()
    await Promise.resolve()
  })
}

const INVITATION = 'Studio shared session 3 with you.'

describe('an invitation at the head of the inbox (KR-REQ-18.13)', () => {
  it('is the first thing the inbox shows, in the words of who shared which session', async () => {
    start({ before: (c) => c.sharing.offer({ role: 'controller', live: true }) })
    const offers = await screen.findByTestId('offers')
    expect(within(offers).getByRole('heading', { name: 'Invitations' })).toBeInTheDocument()
    expect(within(offers).getByText(INVITATION)).toBeInTheDocument()
    // It is above the filters the inbox starts with.
    const filters = screen.getByRole('group', { name: 'Filter the inbox' })
    expect(offers.compareDocumentPosition(filters) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  })

  it('is opened as a card that says what accepting lets the phone do, show and until when', async () => {
    start({ before: (c) => c.sharing.offer({ role: 'controller', live: true }) })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    const card = await screen.findByTestId('offer-card')

    const youCan = within(card).getByRole('heading', { name: 'You can' }).parentElement as HTMLElement
    expect(within(youCan).getByText('Type into the terminal')).toBeInTheDocument()
    expect(within(youCan).getByText('Resize the terminal')).toBeInTheDocument()

    // The host's consequences, said to the person they are about, with the host named.
    const lets = within(card).getByRole('heading', { name: 'This lets you' }).parentElement as HTMLElement
    expect(within(lets).getByText(/Terminal input runs as the owner’s account on Studio\./)).toBeInTheDocument()
    expect(within(lets).getByText(/may act on under its own permissions on Studio\./)).toBeInTheDocument()

    const shows = within(card).getByRole('heading', { name: 'Shows' }).parentElement as HTMLElement
    expect(within(shows).getByText(/^What the session does from /)).toBeInTheDocument()
    expect(within(shows).getByText('The terminal as it is when you open it.')).toBeInTheDocument()

    const ends = within(card).getByRole('heading', { name: 'Ends' }).parentElement as HTMLElement
    expect(within(ends).getByText(/\. Used once\.$/)).toBeInTheDocument()
  })

  it('names the control that closes the card by the card, and closing it leaves the invitation offered', async () => {
    start({ before: (c) => c.sharing.offer() })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    const card = await screen.findByRole('dialog')
    // A screen reader says what the control closes, here the invitation and not the settings.
    expect(within(card).queryByRole('button', { name: 'Close settings' })).toBeNull()
    await userEvent.click(within(card).getByRole('button', { name: 'Close invitation' }))
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })
    expect(screen.getByRole('button', { name: new RegExp(INVITATION) })).toBeInTheDocument()
  })

  it('says a share without the live view gives no terminal, whatever the role could do with one', async () => {
    start({ before: (c) => c.sharing.offer({ role: 'controller', live: false }) })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    const card = await screen.findByTestId('offer-card')
    const youCan = within(card).getByRole('heading', { name: 'You can' }).parentElement as HTMLElement
    expect(within(youCan).queryByText('Type into the terminal')).toBeNull()
    expect(within(youCan).queryByText('Resize the terminal')).toBeNull()
    expect(within(youCan).getByText('Not the terminal: the live view is not included')).toBeInTheDocument()
    expect(within(youCan).getByText('Send the agent prompts')).toBeInTheDocument()
    expect(within(card).queryByText('The terminal as it is when you open it.')).toBeNull()
  })

  it('starts the sentence with a capital when the host has no name of its own to give', async () => {
    // Native says "your host" for a pairing that has no name.
    start({ host: 'your host', before: (c) => c.sharing.offer({ role: 'controller', live: true }) })
    await userEvent.click(await screen.findByRole('button', { name: /Your host shared session 3 with you\./ }))
    const card = await screen.findByTestId('offer-card')
    // Inside a sentence the name reads as it was given.
    expect(within(card).getByText(/Terminal input runs as the owner’s account on your host\./)).toBeInTheDocument()
  })

  it('starts the sentence with a name that is the owner’s own text just as it is written', async () => {
    start({ host: 'iMac in the study', before: (c) => c.sharing.offer() })
    expect(await screen.findByText('iMac in the study shared session 3 with you.')).toBeInTheDocument()
  })

  it('names no moment for a share that reaches back to the start of what the host kept', async () => {
    start({ before: (c) => c.sharing.offer({ allHistory: true }) })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    const card = await screen.findByTestId('offer-card')
    expect(within(card).getByText('What the session does, from its start.')).toBeInTheDocument()
    expect(within(card).queryByText(/^What the session does from /)).toBeNull()
  })

  it('shows no consequences and no live screen for a viewer share that includes neither', async () => {
    start({ before: (c) => c.sharing.offer() })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    const card = await screen.findByTestId('offer-card')
    expect(within(card).queryByRole('heading', { name: 'This lets you' })).toBeNull()
    expect(within(card).queryByText('The terminal as it is when you open it.')).toBeNull()
  })

  it('is accepted by a completed press, once, with the host named in what is said', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))

    expect(await screen.findByText(/^Accepted\. Session 3 is shared with you until /)).toBeInTheDocument()
    expect(controls.sharing.sent().redeem).toBe(1)
    await waitFor(() => {
      expect(screen.queryByTestId('offers')).toBeNull()
    })
  })

  it('takes the accepted invitation out of sight at once, and a list from before the acceptance does not bring it back', async () => {
    // Once told to, the host's list is served as it was before the acceptance: a read asked for
    // before the host wrote it, which can answer after.
    let beforeIt: Awaited<ReturnType<HostPort['grantHeld']>> | null = null
    let serveThat = false
    const { controls, port } = start({
      before: (c) => c.sharing.offer(),
      through: (host) => ({
        ...host,
        grantHeld: async () => {
          const held = await host.grantHeld()
          if (!serveThat) beforeIt = held
          return serveThat && beforeIt !== null ? beforeIt : held
        }
      })
    })
    const row = await screen.findByRole('button', { name: new RegExp(INVITATION) })
    await userEvent.click(row)
    const accept = await screen.findByTestId('accept-offer')
    serveThat = true
    await userEvent.click(accept)

    // The host answered, so the card goes and so does the invitation, whatever the list says next.
    expect(await screen.findByText(/^Accepted\. Session 3 is shared with you until /)).toBeInTheDocument()
    expect(controls.sharing.sent().redeem).toBe(1)
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    await readAgain(port)
    await readAgain(port)
    expect(screen.queryByRole('button', { name: new RegExp(INVITATION) })).toBeNull()

    // A list from after it does not have the invitation, and the page lets go of it.
    serveThat = false
    await readAgain(port)
    await waitFor(() => {
      expect(screen.queryByTestId('offers')).toBeNull()
    })
  })

  it('puts focus on the screen when an invitation is gone by the time the host refuses to accept it', async () => {
    const offered = { id: '' }
    const { controls } = start({
      before: (c) => {
        offered.id = c.sharing.offer().invitation_id
      }
    })
    const row = await screen.findByRole('button', { name: new RegExp(INVITATION) })
    await userEvent.click(row)
    const accept = await screen.findByTestId('accept-offer')
    // The issuer withdraws it after the phone read its list: the host refuses the acceptance, and
    // the list that says it is gone is read after the card has closed.
    controls.sharing.withdrawOffer(offered.id)
    await userEvent.click(accept)
    expect(await screen.findByText(/no longer offered to this device/)).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    await waitFor(() => {
      expect(screen.queryByTestId('offers')).toBeNull()
    })
    await waitFor(() => {
      expect(document.activeElement?.id).toBe('main')
    })
  })

  it('keeps the acceptance the host did not settle against a list of acceptances asked for before it', async () => {
    // A read of the acceptances is held after it has been asked, and answers after the acceptance.
    let hold = false
    const waiting: (() => void)[] = []
    const { controls, port } = start({
      before: (c) => c.sharing.offer(),
      through: (host) => ({
        ...host,
        attemptsList: async () => {
          const listed = await host.attemptsList()
          if (hold) {
            hold = false
            await new Promise<void>((resolve) => {
              waiting.push(resolve)
            })
          }
          return listed
        }
      })
    })
    const row = await screen.findByRole('button', { name: new RegExp(INVITATION) })
    hold = true
    await readAgain(port)
    await waitFor(() => {
      expect(waiting).toHaveLength(1)
    })
    // The answer to the acceptance is lost, and so are the reads that follow it.
    controls.sharing.loseNextAnswer()
    controls.sharing.failNextHeld('the connection to the host was lost', 3)
    await userEvent.click(row)
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await screen.findByTestId('accept-attempt')
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })

    // The held read answers now, with the acceptances as they were before this one.
    waiting[0]?.()
    await settled()
    expect(screen.getByTestId('accept-attempt')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: new RegExp(INVITATION) }))
    expect(await screen.findByTestId('accept-offer')).toBeDisabled()
    expect(controls.sharing.sent().redeem).toBe(1)
  })

  it('leaves focus where the person put it when the row it was on goes later', async () => {
    const offered = { id: '' }
    const { controls, port } = start({
      before: (c) => {
        offered.id = c.sharing.offer().invitation_id
      }
    })
    const row = await screen.findByRole('button', { name: new RegExp(INVITATION) })
    await userEvent.click(row)
    await userEvent.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    // The person moves on to another control of the screen.
    const elsewhere = screen.getByRole('button', { name: 'Failed' })
    elsewhere.focus()
    expect(document.activeElement).toBe(elsewhere)

    // The invitation is withdrawn and the next read says so: the row goes, and focus stays put.
    controls.sharing.withdrawOffer(offered.id)
    await readAgain(port)
    await waitFor(() => {
      expect(screen.queryByTestId('offers')).toBeNull()
    })
    expect(document.activeElement).toBe(elsewhere)
  })

  it('arms nothing when the host answers an acceptance after the screen has gone', async () => {
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => {
      release = resolve
    })
    start({
      before: (c) => c.sharing.offer(),
      through: (host) => ({
        ...host,
        grantRedeem: async (params) => {
          const done = await host.grantRedeem(params)
          await gate
          return done
        }
      })
    })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await userEvent.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    await openTab('Sessions')
    await waitFor(() => {
      expect(screen.queryByTestId('offers')).toBeNull()
    })

    release()
    await screen.findByText(/^Accepted\. Session 3 is shared with you until /)
    // Focus falls to nothing and something changes in the page: no leftover moves it to the region
    // of a screen the person has gone to.
    ;(document.activeElement as HTMLElement | null)?.blur()
    document.body.append(document.createElement('div'))
    await settled()
    expect(document.activeElement).toBe(document.body)
  })

  it('puts focus on what is still there once the card has gone: the next invitation, or the screen', async () => {
    start({
      before: (c) => {
        c.sharing.offer({ session: '3' })
        c.sharing.offer({ session: '4' })
      }
    })
    // The newest is first: session 4. Accepting it leaves session 3, and focus goes to that row.
    await userEvent.click(await screen.findByRole('button', { name: /shared session 4 with you/ }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    await waitFor(() => {
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: /shared session 3 with you/ })
      )
    })

    // Putting the last one off leaves no row, and focus goes to the screen's own region.
    await userEvent.click(screen.getByRole('button', { name: /shared session 3 with you/ }))
    await userEvent.click(await screen.findByTestId('not-now'))
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })
    await waitFor(() => {
      expect(document.activeElement?.id).toBe('main')
    })
  })

  it('is put off with Not now, and shown again from the row that says one is hidden', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('not-now'))

    const hidden = await screen.findByTestId('hidden-offers')
    expect(hidden).toHaveTextContent('1 hidden invitation')
    expect(screen.queryByText(INVITATION)).toBeNull()
    // Putting it off decides nothing for the host: it never sent a redemption.
    expect(controls.sharing.sent().redeem).toBe(0)

    await userEvent.click(hidden)
    expect(await screen.findByText(INVITATION)).toBeInTheDocument()
    expect(screen.queryByTestId('hidden-offers')).toBeNull()
  })

  it('says the host’s sentence when the host refuses the first send, never that nothing was accepted', async () => {
    const { controls, port } = start({ before: (c) => c.sharing.offer() })
    controls.sharing.refuseNextRedeem('The host could not finish accepting that just now.', true)
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))

    // The row for the acceptance is unfinished, in the host's words.
    const attempt = await screen.findByTestId('accept-attempt')
    expect(attempt).toHaveTextContent('Unfinished: Accepting session 3.')
    expect(attempt).toHaveTextContent('The host said: The host could not finish accepting that just now.')
    expect(attempt).not.toHaveTextContent(/nothing was accepted|was not accepted/)

    // The host had written the share before it refused: the rows decide, and the share is held.
    await openTab('Sessions')
    const shared = await screen.findByTestId('shared-with-you')
    expect(within(shared).getByText('Session 3 · Studio')).toBeInTheDocument()

    // Once the host's bound has passed it says that it was accepted, and the record goes.
    act(() => {
      controls.sharing.passTheBound()
    })
    await openTab('Attention')
    await readAgain(port)
    expect(await screen.findByText(/^Accepted\. Session 3 is shared with you until /)).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.queryByTestId('accept-attempt')).toBeNull()
    })
  })

  it('closes an acceptance the host never wrote as not accepted, once the bound has passed', async () => {
    const { controls, port } = start({ before: (c) => c.sharing.offer() })
    controls.sharing.refuseNextRedeem('That invitation cannot be used right now.', false)
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    expect(await screen.findByTestId('accept-attempt')).toHaveTextContent('Unfinished')

    act(() => {
      controls.sharing.passTheBound()
    })
    await readAgain(port)
    await waitFor(() => {
      expect(screen.getByTestId('accept-attempt')).toHaveTextContent('it was not accepted, as far as the host shows')
    })
    // The invitation is still the host's to offer, and the person can try again.
    expect(screen.getByText(INVITATION)).toBeInTheDocument()
    await userEvent.click(screen.getByTestId('attempt-remove'))
    await waitFor(() => {
      expect(screen.queryByTestId('accept-attempt')).toBeNull()
    })
  })

  it('lists an acceptance whose answer was lost as unfinished, and the host’s record answers Ask the host', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    controls.sharing.loseNextAnswer()
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))

    const attempt = await screen.findByTestId('accept-attempt')
    expect(attempt).toHaveTextContent('Unfinished: Accepting session 3.')
    expect(attempt).toHaveTextContent('The host has not said whether it happened.')

    await userEvent.click(within(attempt).getByTestId('attempt-ask'))
    expect(await screen.findByText('Accepted.')).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.queryByTestId('accept-attempt')).toBeNull()
    })
  })

  it('holds a second acceptance of an invitation back while an earlier one is not settled', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    controls.sharing.loseNextRequest()
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await screen.findByTestId('accept-attempt')

    // The host never saw it, so it still offers the invitation, and the card says why it waits.
    await userEvent.click((await screen.findByText(INVITATION)).closest('button') as HTMLElement)
    expect(await screen.findByTestId('accept-offer')).toBeDisabled()
    expect(screen.getByTestId('offer-unsettled')).toBeInTheDocument()
    expect(controls.sharing.sent().redeem).toBe(1)
  })

  it('holds a second acceptance back even when the read after the first could not be made', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    const row = await screen.findByRole('button', { name: new RegExp(INVITATION) })
    // From here the answer to the acceptance is lost, and so are the next reads of what is held.
    controls.sharing.loseNextAnswer()
    controls.sharing.failNextHeld('the connection to the host was lost', 3)
    await userEvent.click(row)
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await waitFor(() => {
      expect(screen.queryByTestId('sheet')).toBeNull()
    })

    // The list could not be read after the acceptance, so the invitation is still listed as it was;
    // what the page was told of the acceptance is what keeps a second one from being sent.
    await userEvent.click(screen.getByRole('button', { name: new RegExp(INVITATION) }))
    expect(await screen.findByTestId('accept-offer')).toBeDisabled()
    expect(screen.getByTestId('offer-unsettled')).toBeInTheDocument()
    expect(controls.sharing.sent().redeem).toBe(1)
  })

  it('can hide an unfinished acceptance and show it again, which releases nothing', async () => {
    const { controls } = start({ before: (c) => c.sharing.offer() })
    controls.sharing.loseNextAnswer()
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await userEvent.click(await screen.findByTestId('attempt-hide'))

    const hidden = await screen.findByTestId('hidden-attempts')
    expect(hidden).toHaveTextContent('1 hidden attempt can still happen')
    await userEvent.click(within(hidden).getByTestId('attempt-show'))
    expect(await screen.findByTestId('accept-attempt')).toBeInTheDocument()
  })
})

describe('the shares held, at the head of the sessions (KR-REQ-18.13)', () => {
  async function accepted(): Promise<Phone> {
    const phone = start({ before: (c) => c.sharing.offer({ role: 'controller' }) })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await screen.findByText(/^Accepted\./)
    await openTab('Sessions')
    return phone
  }

  it('lists a share by its session, the host and its role, until the time the host gives', async () => {
    await accepted()
    const shared = await screen.findByTestId('shared-with-you')
    expect(within(shared).getByRole('heading', { name: 'Shared with you' })).toBeInTheDocument()
    expect(within(shared).getByText('Session 3 · Studio')).toBeInTheDocument()
    expect(within(shared).getByText('Controller')).toBeInTheDocument()
    expect(within(shared).getByText(/^Until /)).toBeInTheDocument()
  })

  it('opens the session under the share when the row is pressed', async () => {
    const { controls } = await accepted()
    const shared = await screen.findByTestId('shared-with-you')
    await userEvent.click(within(shared).getByRole('button', { name: /Session 3 · Studio/ }))
    await waitFor(() => {
      expect(controls.standings.opens.at(-1)).toMatchObject({
        sessionId: '8a7b6c50-22bb-4c3d-8e4f-000000000101',
        grantId: controls.sharing.held()[0]?.grant.grant_id
      })
    })
  })

  it('keeps a share the host stopped listing as a row that says it ended and leads nowhere', async () => {
    const { controls, port } = await accepted()
    const shared = await screen.findByTestId('shared-with-you')
    expect(within(shared).queryByTestId('ended-share')).toBeNull()

    const grantId = controls.sharing.held()[0]?.grant.grant_id ?? ''
    controls.sharing.endShare(grantId)
    await readAgain(port)
    const ended = await screen.findByTestId('ended-share')
    expect(ended).toHaveTextContent('Ended')
    expect(ended).toHaveTextContent('Session 3 · Studio')
    expect(within(shared).queryByRole('button', { name: /Session 3 · Studio/ })).toBeNull()
  })

  it('marks nothing as ended when the read that would have said so failed', async () => {
    const { controls, port } = await accepted()
    await screen.findByTestId('shared-with-you')
    const grantId = controls.sharing.held()[0]?.grant.grant_id ?? ''
    controls.sharing.endShare(grantId)
    controls.sharing.failNextHeld('the connection to the host was lost')
    await readAgain(port)

    const shared = await screen.findByTestId('shared-with-you')
    expect(await within(shared).findByText(/Not refreshed just now/)).toBeInTheDocument()
    expect(screen.queryByTestId('ended-share')).toBeNull()
    expect(within(shared).getByRole('button', { name: /Session 3 · Studio/ })).toBeInTheDocument()

    await readAgain(port)
    expect(await screen.findByTestId('ended-share')).toBeInTheDocument()
    expect(within(shared).queryByText(/Not refreshed just now/)).toBeNull()
  })
})

describe('a guest, whose pairing holds no view of any session (KR-REQ-25.28)', () => {
  it('has an inbox with nothing of its own and not one that failed, and an invitation above it', async () => {
    start({ before: (c) => c.sharing.offer() })
    expect(await screen.findByText(INVITATION)).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByText('Nothing needs you right now.')).toBeInTheDocument()
    })
    expect(screen.queryByText('The inbox could not be read')).toBeNull()
  })

  it('lists only what is shared with it, and says so when nothing is', async () => {
    start()
    await openTab('Sessions')
    expect(await screen.findByText('Nothing is shared with this phone.')).toBeInTheDocument()
    expect(screen.queryByText('The sessions could not be read')).toBeNull()
    expect(screen.queryByText('Session 1')).toBeNull()
  })

  it('lists its own sessions and the shared ones apart when its pairing holds a view', async () => {
    start({ rights: ['session.view'], before: (c) => c.sharing.offer({ session: '3' }) })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await screen.findByText(/^Accepted\./)
    await openTab('Sessions')

    const shared = await screen.findByTestId('shared-with-you')
    expect(within(shared).getByText('Session 3 · Studio')).toBeInTheDocument()
    expect(await screen.findByRole('heading', { name: 'On this host' })).toBeInTheDocument()
    expect(screen.getByText('Session 1')).toBeInTheDocument()
    expect(screen.queryByText('Nothing is shared with this phone.')).toBeNull()
  })

  it('says that what is shared could not be read, when it never could, and not that it is being read', async () => {
    // The phone opens on its sessions, so the first read of what is shared is the one that fails.
    window.history.replaceState({}, '', '/?tab=sessions')
    const { controls } = start({ before: (c) => c.sharing.failNextHeld('the host could not be reached') })
    expect(
      await screen.findByText('What is shared with this phone could not be read just now.')
    ).toBeInTheDocument()
    expect(screen.queryByText('Reading what is shared with this phone…')).toBeNull()
    expect(controls.sharing.heldReads()).toBeGreaterThanOrEqual(1)
  })

  it('shows a failure that follows a refusal as the failure it is, not as nothing of its own', async () => {
    const { controls } = start()
    await openTab('Sessions')
    expect(await screen.findByText('Nothing is shared with this phone.')).toBeInTheDocument()

    // Contact comes back after a loss, and the host cannot list its sessions for another reason.
    controls.failNextSessionList('the host could not list its sessions just now')
    act(() => {
      controls.setConnected(false)
    })
    act(() => {
      controls.setConnected(true)
    })
    expect(await screen.findByText('The sessions could not be read')).toBeInTheDocument()
    expect(screen.queryByText('Nothing is shared with this phone.')).toBeNull()
    // The host told this device nothing of its sessions, so the screen does not say there are none.
    expect(screen.queryByText('No sessions on this host.')).toBeNull()
  })
})

describe('contact with the host is lost and comes back (KR-REQ-18.13)', () => {
  it('keeps the shares and the ended row drawn while out of contact, and finds one that ended meanwhile', async () => {
    const { controls, port } = start({ rights: ['session.view'], before: (c) => c.sharing.offer() })
    await userEvent.click(await screen.findByRole('button', { name: new RegExp(INVITATION) }))
    await userEvent.click(await screen.findByTestId('accept-offer'))
    await screen.findByText(/^Accepted\./)
    await openTab('Sessions')
    const shared = await screen.findByTestId('shared-with-you')
    expect(within(shared).getByRole('button', { name: /Session 3 · Studio/ })).toBeInTheDocument()

    act(() => {
      controls.setConnected(false)
    })
    // Nothing the phone learned goes with the contact, and the list says it is not fresh.
    expect(await within(shared).findByText(/Not refreshed just now/)).toBeInTheDocument()
    expect(within(shared).getByRole('button', { name: /Session 3 · Studio/ })).toBeInTheDocument()

    const grantId = controls.sharing.held()[0]?.grant.grant_id ?? ''
    controls.sharing.endShare(grantId)
    act(() => {
      controls.setConnected(true)
    })
    await readAgain(port)
    expect(await screen.findByTestId('ended-share')).toHaveTextContent('Session 3 · Studio')
    expect(within(await screen.findByTestId('shared-with-you')).queryByText(/Not refreshed just now/)).toBeNull()
  })
})

describe('the host on this computer (KR-REQ-18.13)', () => {
  it('holds no share of itself, so neither half is drawn and nothing is asked', async () => {
    const { port, controls } = fakeHost()
    render(
      <AppProvider port={port}>
        <MobileApp surface="ios" storage={null} />
      </AppProvider>
    )
    await screen.findByRole('group', { name: 'Filter the inbox' })
    expect(screen.queryByTestId('offers')).toBeNull()
    await openTab('Sessions')
    await screen.findByText('Session 1')
    expect(screen.queryByTestId('shared-with-you')).toBeNull()
    expect(controls.sharing.heldReads()).toBe(0)
  })
})

describe('a host that does not know the read (KR-REQ-18.13)', () => {
  it('shows neither half, no failure, and asks once', async () => {
    const { controls } = start({ before: (c) => c.sharing.doesNotServeHeld() })
    await waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(1)
    })
    expect(screen.queryByTestId('offers')).toBeNull()
    await openTab('Sessions')
    expect(screen.queryByTestId('shared-with-you')).toBeNull()
    expect(controls.sharing.heldReads()).toBe(1)
    // With nothing shared to list, a guest's refusal stays the failure it was before shares existed.
    expect(await screen.findByText('The sessions could not be read')).toBeInTheDocument()
    expect(screen.queryByText('Nothing is shared with this phone.')).toBeNull()
    expect(screen.queryByText('No sessions on this host.')).toBeNull()
  })
})

describe('an invitation that arrives while the inbox is open (KR-REQ-18.13)', () => {
  it('is told once to a screen reader and takes its place at the head', async () => {
    const { controls, port } = start()
    await screen.findByText('Nothing needs you right now.')
    controls.sharing.offer({ session: '4' })
    await readAgain(port)

    expect(await screen.findByText('Studio shared session 4 with you.')).toBeInTheDocument()
    expect(screen.getByTestId('offers-said')).toHaveTextContent('New invitation. Studio shared session 4 with you.')

    // A read that finds nothing new says nothing more.
    const said = screen.getByTestId('offers-said').textContent
    await readAgain(port)
    expect(screen.getByTestId('offers-said').textContent).toBe(said)
  })
})
