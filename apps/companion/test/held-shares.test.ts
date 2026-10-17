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

/** The phone reaches the host it is paired with, as the shell hears of it. */
const STUDIO = { connected: true, paired: true, environmentId: 'studio' } as const
const ANOTHER = { connected: true, paired: true, environmentId: 'another' } as const
const OUT_OF_CONTACT = { connected: false, paired: false, environmentId: null } as const

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
  book.reach(STUDIO)
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

describe('a share that is no longer listed has ended (KR-REQ-18.13)', () => {
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
    const { book, controls, grantId } = await holding()
    controls.sharing.endShare(grantId)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().ended.map((each) => each.grantId)).toEqual([grantId])
    })
    // The host lists the very same share again: it is held, and the row that said it ended is gone.
    controls.sharing.restoreShare(grantId)
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().shares.map((each) => each.grant.grant_id)).toEqual([grantId])
    })
    expect(book.snapshot().ended).toEqual([])
  })

  it('keeps what it learned through a loss of contact, and finds a share that ended meanwhile', async () => {
    const { book, controls, grantId } = await holding()
    const offer = controls.sharing.offer({ session: '5' })
    book.refresh()
    await vi.waitFor(() => {
      expect(book.snapshot().offers).toHaveLength(1)
    })
    book.putOff(offer.invitation_id)

    // Contact is lost: nothing is forgotten, and the lists say they are not fresh.
    book.reach(OUT_OF_CONTACT)
    expect(book.snapshot()).toMatchObject({ status: 'ready', stale: true })
    expect(book.snapshot().shares).toHaveLength(1)
    expect(book.snapshot().hidden).toEqual([offer.invitation_id])
    const reads = controls.sharing.heldReads()
    book.refresh()
    await settled()
    expect(controls.sharing.heldReads(), 'nothing is asked of a host that is out of contact').toBe(reads)

    // The share ends while the phone is out of contact, and contact comes back to the same host.
    controls.sharing.endShare(grantId)
    book.reach(STUDIO)
    await vi.waitFor(() => {
      expect(book.snapshot().ended.map((each) => each.grantId)).toEqual([grantId])
    })
    expect(book.snapshot().stale).toBe(false)
    // What the person put off stays put off.
    expect(book.snapshot().hidden).toEqual([offer.invitation_id])
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

    book.reach(ANOTHER)
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

  it('is asked again under another connection, to the same host or to another', async () => {
    const { book, controls } = phone((prepared) => {
      prepared.sharing.doesNotServeHeld()
    })
    await vi.waitFor(() => {
      expect(book.snapshot().status).toBe('unsupported')
    })
    expect(controls.sharing.heldReads()).toBe(1)

    // The same host, reached again: it can have been updated since.
    book.reach(OUT_OF_CONTACT)
    book.reach(STUDIO)
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(2)
    })

    book.reach(ANOTHER)
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(3)
    })
  })

  it('is told of a connection while no screen is shown, so the next screen finds the host it is', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone()
    const book = new HeldBook(port, ONLY_WHEN_ASKED)
    book.reach(STUDIO)
    controls.sharing.offer()
    expect(controls.sharing.heldReads()).toBe(0)
    detaches.push(book.attach())
    await vi.waitFor(() => {
      expect(ready(book).offers).toHaveLength(1)
    })
  })
})

describe('reads that overlap (KR-REQ-18.13)', () => {
  it('takes in only the newest read: an older answer that comes after it changes nothing', async () => {
    const { port, controls } = fakeHost()
    controls.reachAsPhone()
    const offer = controls.sharing.offer()
    // Each read of the list waits for the test to let its answer go, and answers what the host held
    // when it was asked.
    const answers: (() => void)[] = []
    const slow: HostPort = {
      ...port,
      grantHeld: async () => {
        const held = await port.grantHeld()
        await new Promise<void>((resolve) => {
          answers.push(resolve)
        })
        return held
      }
    }
    const book = new HeldBook(slow, ONLY_WHEN_ASKED)
    book.reach(STUDIO)
    // A screen reads and is left while the read is on its way: the host offered the invitation then
    // and held no share.
    const first = book.attach()
    await vi.waitFor(() => {
      expect(answers).toHaveLength(1)
    })
    first()
    // The invitation is accepted, and another screen reads: the host lists the share.
    await port.grantRedeem({ invitation_id: offer.invitation_id })
    detaches.push(book.attach())
    await vi.waitFor(() => {
      expect(answers).toHaveLength(2)
    })
    answers[1]?.()
    await vi.waitFor(() => {
      expect(ready(book).shares.map((each) => each.grant.grant_id)).toEqual([offer.grant_id])
    })
    // The first read answers last, with the list from before the share: it is not taken in, so the
    // share is neither dropped from what is held nor called ended.
    answers[0]?.()
    await settled()
    expect(book.snapshot().shares.map((each) => each.grant.grant_id)).toEqual([offer.grant_id])
    expect(book.snapshot().ended).toEqual([])
  })
})

describe('when the list is read (KR-REQ-18.13)', () => {
  it('is read on a cadence of five seconds while a screen is shown, and not once the last has gone', async () => {
    vi.useFakeTimers()
    try {
      const { port, controls } = fakeHost()
      controls.reachAsPhone()
      const book = new HeldBook(port)
      const detach = book.attach()
      book.reach(STUDIO)
      await vi.advanceTimersByTimeAsync(0)
      expect(controls.sharing.heldReads()).toBe(1)

      await vi.advanceTimersByTimeAsync(4_999)
      expect(controls.sharing.heldReads()).toBe(1)
      await vi.advanceTimersByTimeAsync(1)
      expect(controls.sharing.heldReads()).toBe(2)
      await vi.advanceTimersByTimeAsync(5_000)
      expect(controls.sharing.heldReads()).toBe(3)

      detach()
      await vi.advanceTimersByTimeAsync(30_000)
      expect(controls.sharing.heldReads()).toBe(3)
    } finally {
      vi.useRealTimers()
    }
  })

  it('is read at once when a screen comes, when the page is shown again and when the connection changes', async () => {
    const { book, controls } = phone()
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(1)
    })

    // The page is shown again after being hidden.
    document.dispatchEvent(new Event('visibilitychange'))
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(2)
    })

    // Another host is the one reached.
    book.reach(ANOTHER)
    await vi.waitFor(() => {
      expect(controls.sharing.heldReads()).toBe(3)
    })
  })
})
