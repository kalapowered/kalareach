/**
 * What a phone is offered and holds, kept by the page as the host lists it.
 *
 * The book reads `grant.held` from the scripted host, which answers as the real command does, and
 * keeps what the two sections draw. What these hold it to is what only the book decides: a share
 * ends only when a complete read no longer lists it, a read that failed changes nothing, a host
 * that does not serve the read is asked once, and what was learned under one host is never shown
 * under another.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { fakeHost, type FakeHostControls } from '../src/host/fake'
import type { HostPort } from '../src/host/port'
import { HeldBook, type HeldView } from '../src/model/held-shares'

/** A cadence so long that only a read the test asks for is made. */
const ONLY_WHEN_ASKED = 1_000_000

/** The host the phone is paired with, as the screens name the connection that reaches it. */
const STUDIO = 'host:studio'

const detaches: (() => void)[] = []
afterEach(() => {
  for (const detach of detaches.splice(0)) detach()
})

interface Phone {
  readonly book: HeldBook
  readonly port: HostPort
  readonly controls: FakeHostControls
}

/** A phone paired with the scripted host, with its book reading while the test runs. */
function phone(prepare?: (controls: FakeHostControls) => void): Phone {
  const { port, controls } = fakeHost()
  controls.reachAsPhone()
  prepare?.(controls)
  const book = new HeldBook(port, ONLY_WHEN_ASKED)
  detaches.push(book.attach())
  book.connect(STUDIO)
  return { book, port, controls }
}

/** Lets what is already on its way finish, for a test that asserts nothing happened. */
async function settled(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0))
}

const ready = (book: HeldBook): HeldView => {
  expect(book.snapshot().status).toBe('ready')
  return book.snapshot()
}

describe('what the host offers and what the phone holds (KR-REQ-18.13)', () => {
  it('lists an invitation that names the phone, and the share it becomes once accepted', async () => {
    const { book, port, controls } = phone()
    const offer = controls.sharing.offer({ role: 'controller', live: true })
    book.refresh()
    await vi.waitFor(() => {
      expect(ready(book).offers.map((each) => each.invitation_id)).toEqual([offer.invitation_id])
    })
    expect(book.snapshot().shares).toEqual([])

    await port.grantRedeem({ invitation_id: offer.invitation_id })
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().offers).toEqual([])
      expect(book.snapshot().shares.map((each) => each.grant.grant_id)).toEqual([offer.grant_id])
    })
  })

  it('names the host from the pairing this phone keeps and not from anything the host sent', async () => {
    const { book } = phone()
    await vi.waitFor(() => {
      expect(ready(book).hostName).toBe('Studio')
    })
  })

  it('tells what arrived since the read before once, and nothing for what was there at the start', async () => {
    const { book, controls } = phone((prepared) => {
      prepared.sharing.offer({ session: '2' })
    })
    await vi.waitFor(() => {
      expect(ready(book).offers).toHaveLength(1)
    })
    // What was waiting when the screen came is not news.
    expect(book.snapshot().arrived.seq).toBe(0)

    const fresh = controls.sharing.offer({ session: '3' })
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().arrived).toEqual({ seq: 1, invitationIds: [fresh.invitation_id] })
    })

    // A read that finds nothing new tells nothing.
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().offers).toHaveLength(2)
    })
    await settled()
    expect(book.snapshot().arrived.seq).toBe(1)
  })

  it('puts an invitation off and shows it again, and forgets one the host stops offering', async () => {
    const { book, controls } = phone()
    const first = controls.sharing.offer({ session: '1' })
    const second = controls.sharing.offer({ session: '2' })
    book.refresh()
    await vi.waitFor(() => {
      expect(ready(book).offers).toHaveLength(2)
    })

    book.putOff(first.invitation_id)
    expect(book.snapshot().hidden).toEqual([first.invitation_id])
    // The host still offers both: putting one off decides nothing there.
    expect(book.snapshot().offers).toHaveLength(2)

    controls.sharing.withdrawOffer(first.invitation_id)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().offers.map((each) => each.invitation_id)).toEqual([second.invitation_id])
    })
    expect(book.snapshot().hidden).toEqual([])

    book.putOff(second.invitation_id)
    book.showPutOff()
    expect(book.snapshot().hidden).toEqual([])
  })
})

describe('a share that is no longer listed has ended (KR-REQ-18.13, 18.14)', () => {
  async function holding(): Promise<Phone & { grantId: string }> {
    const world = phone()
    const offer = world.controls.sharing.offer()
    await world.port.grantRedeem({ invitation_id: offer.invitation_id })
    world.book.refresh()
    await vi.waitFor(() => {
      expect(ready(world.book).shares).toHaveLength(1)
    })
    return { ...world, grantId: offer.grant_id }
  }

  it('marks a share ended once a complete read no longer lists it, and keeps it so', async () => {
    const { book, controls, grantId } = await holding()
    controls.sharing.endShare(grantId)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().ended.map((each) => each.grantId)).toEqual([grantId])
    })
    expect(book.snapshot().shares).toEqual([])
    expect(book.snapshot().ended[0]).toMatchObject({ displayNumber: '3', role: 'Viewer' })

    // It stays for the run: a later read that lists other things does not take it away.
    book.refresh()
    await settled()
    expect(book.snapshot().ended.map((each) => each.grantId)).toEqual([grantId])
  })

  it('marks nothing as ended when the read failed, and says the list is not fresh', async () => {
    const { book, controls, grantId } = await holding()
    controls.sharing.endShare(grantId)
    controls.sharing.failNextHeld('the connection to the host was lost')
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().stale).toBe(true)
    })
    // The host no longer lists the share, and the read that would have said so did not complete.
    expect(book.snapshot().ended).toEqual([])
    expect(book.snapshot().shares).toHaveLength(1)

    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().ended.map((each) => each.grantId)).toEqual([grantId])
    })
    expect(book.snapshot().stale).toBe(false)
  })

  it('does not call a share ended that the host lists again', async () => {
    const { book, port, controls, grantId } = await holding()
    controls.sharing.endShare(grantId)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().ended).toHaveLength(1)
    })
    // The host offers the same grant again and it is accepted: it is held, not ended.
    const again = controls.sharing.offer({ session: '3' })
    await port.grantRedeem({ invitation_id: again.invitation_id })
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().shares).toHaveLength(1)
    })
    expect(book.snapshot().ended.filter((each) => each.grantId === again.grant_id)).toEqual([])
  })

  it('leaves what was learned under one host out of the next', async () => {
    const { book, controls, grantId } = await holding()
    controls.sharing.endShare(grantId)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().ended).toHaveLength(1)
    })
    const offer = controls.sharing.offer({ session: '5' })
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().offers).toHaveLength(1)
    })
    book.putOff(offer.invitation_id)

    book.connect('host:another')
    expect(book.snapshot()).toMatchObject({ status: 'unread', ended: [], hidden: [], offers: [] })
    await vi.waitFor(() => {
      expect(book.snapshot().status).toBe('ready')
    })
    expect(book.snapshot().ended).toEqual([])
    expect(book.snapshot().hidden).toEqual([])
  })
})

describe('a host that does not serve the read (KR-REQ-18.13)', () => {
  it('is asked once, and both halves stay out of sight', async () => {
    const { book, controls } = phone((prepared) => {
      prepared.sharing.doesNotServeHeld()
    })
    await vi.waitFor(() => {
      expect(book.snapshot().status).toBe('unsupported')
    })
    expect(controls.sharing.heldReads()).toBe(1)

    book.refresh()
    book.refresh()
    await settled()
    expect(controls.sharing.heldReads()).toBe(1)
    expect(book.snapshot()).toMatchObject({ offers: [], shares: [], ended: [] })
  })

  it('is asked again under another connection', async () => {
    const { book, controls } = phone((prepared) => {
      prepared.sharing.doesNotServeHeld()
    })
    await vi.waitFor(() => {
      expect(book.snapshot().status).toBe('unsupported')
    })
    book.connect('host:another')
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(2)
    })
  })
})
