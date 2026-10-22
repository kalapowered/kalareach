/**
 * Revoking a device, in the words the page uses for it.
 *
 * A revocation is done only when the host's acknowledgement has been read. Everything before that is
 * said as what it is: sent, with nobody having answered it, or acknowledged while some of the host's
 * sessions have yet to confirm it. Nothing here calls a request that has not been acknowledged
 * revoked, and nothing here says a session stopped: a revocation ends what the device may do, and
 * the sessions stay on the host.
 */

import type {
  CeremonyKind,
  MailboxView,
  RevocationDevice,
  RevocationFeed,
  RevocationHost,
  RevocationRefusal,
  RevocationStanding,
  RevocationView
} from '../host/port'

/** How the person confirms, for the ceremony this computer offers. Null where it offers none. */
function by(ceremony: CeremonyKind): string | null {
  switch (ceremony) {
    case 'touch_id':
      return 'with Touch ID'
    case 'password':
      return 'with your password'
    case 'face_id':
      return 'with Face ID'
    case 'passcode':
      return 'with your passcode'
    case 'biometric':
      return 'with your fingerprint or face'
    case 'screen_lock':
      return 'with your screen lock'
    case 'windows_hello':
      return 'with Windows Hello'
    case 'none':
      return null
  }
}

/** The control's name, for the ceremony this computer offers. Null where it offers none. */
export function revokeLabel(ceremony: CeremonyKind, again = false): string | null {
  const how = by(ceremony)
  return how === null ? null : `${again ? 'Revoke again' : 'Revoke'} ${how}`
}

/** What a computer with no ceremony is told. */
export const CANNOT_CONFIRM =
  'This computer cannot check that it is you, so it revokes nothing. Revoke from a Mac or a Windows computer.'

/** What the screen is for, said once under its heading. */
export const REVOCATION_HELP =
  'Revoking a device ends its pairing with a host. Each revocation asks you to confirm on this computer first.'

/** A moment as a phrase: "at 11:40 AM" for today, "on 18 Oct at 11:40 AM" for another day. */
export function whenOf(ms: number, now: number = Date.now()): string {
  const at = new Date(ms)
  const time = at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  const today = new Date(now)
  const sameDay =
    at.getFullYear() === today.getFullYear() &&
    at.getMonth() === today.getMonth() &&
    at.getDate() === today.getDate()
  return sameDay
    ? `at ${time}`
    : `on ${at.toLocaleDateString([], { day: 'numeric', month: 'short' })} at ${time}`
}

/**
 * What a host is called inside a sentence. The host on this computer is shown under the name "This
 * computer", which as the subject of a sentence reads as the computer and not as its host.
 */
export function hostCalled(host: RevocationHost, startsSentence = false): string {
  if (host.route !== 'direct') return host.name
  return startsSentence ? 'The host on this computer' : 'the host on this computer'
}

/** How many sessions, counted: "1 session", "3 sessions". */
function sessions(count: number): string {
  return count === 1 ? '1 session' : `${count} sessions`
}

/** What a host's refusal of a request means, in words. */
export function describeRefusal(reason: RevocationRefusal, host: string): string {
  switch (reason) {
    case 'no_owner_authority':
      return `${host} does not take this computer as one of its owners, so it refused the request. Revoke the device at the host.`
    case 'unknown_target':
      return `${host} does not know this device, so it refused the request.`
    case 'superseded':
      return `${host} refused the request because an earlier revocation covers it.`
  }
}

/** Whether a refused request is one a second request can succeed after: only a superseded one. */
export function canAskAgainAfter(standing: RevocationStanding): boolean {
  return standing.state === 'refused' && standing.reason === 'superseded'
}

/** The short name of a standing, for its badge. Null where there is nothing to name. */
export function standingBadge(
  standing: RevocationStanding
): { readonly tone: 'neutral' | 'success' | 'warning' | 'danger'; readonly text: string } | null {
  switch (standing.state) {
    case 'active':
      return null
    case 'revoked':
      return { tone: 'neutral', text: 'Revoked at the host' }
    case 'sent':
      return { tone: 'warning', text: 'Sent' }
    case 'acknowledged':
      return { tone: 'warning', text: 'Acknowledged' }
    case 'done':
      return { tone: 'success', text: 'Revoked' }
    case 'refused':
      return { tone: 'danger', text: 'Refused' }
  }
}

/**
 * What a standing says in a sentence, where there is one to say. A request that has not been
 * acknowledged is not described as anything more than sent. A standing kept from an earlier read of
 * the feed (`staleSince`) says when it was read and that the feed has not been read since.
 */
export function describeStanding(
  standing: RevocationStanding,
  host: RevocationHost,
  staleSince: number | null = null,
  now: number = Date.now()
): string | null {
  const said = standingWords(standing, host, now)
  if (said === null || staleSince === null) return said
  return `${said} This is what the feed showed ${whenOf(staleSince, now)}: this computer has not been able to read it since.`
}

function standingWords(standing: RevocationStanding, host: RevocationHost, now: number): string | null {
  const name = hostCalled(host, true)
  switch (standing.state) {
    case 'active':
      return null
    case 'revoked':
      return `${name} lists this device as revoked.`
    case 'sent': {
      const sent = `Sent ${whenOf(standing.at_ms, now)}. ${name} has not acknowledged it yet.`
      return standing.host_lists_revoked ? `${sent} It already lists the device as revoked.` : sent
    }
    case 'acknowledged': {
      const at = `${name} ${host.route === 'direct' ? 'recorded' : 'acknowledged'} it ${whenOf(standing.at_ms, now)}`
      // A host that has not said how many sessions are left has not said that none are.
      const confirmed =
        standing.pending_workers !== null
          ? `, and ${sessions(standing.pending_workers)} had not confirmed it yet`
          : standing.host_lists_revoked
            ? ', and has not said that every session confirmed it'
            : ''
      return standing.host_lists_revoked
        ? `${at}${confirmed}.`
        : `${at}${confirmed}. Its own list does not show the device as revoked. Revoke it at the host.`
    }
    case 'done':
      return `${name} ${host.route === 'direct' ? 'revoked' : 'acknowledged'} it ${whenOf(standing.at_ms, now)}, and every session confirmed it.`
    case 'refused':
      return describeRefusal(standing.reason, name)
  }
}

/**
 * Whether a standing is one the host has yet to finish, so the screen asks again while it waits. The
 * host on this computer answers each revocation as it is asked, so nothing a look finds can change
 * what it said: its control is "Check again".
 */
export function isWaiting(standing: RevocationStanding, host: RevocationHost): boolean {
  return (
    standing.state === 'sent' || (standing.state === 'acknowledged' && host.route !== 'direct')
  )
}

/** Whether any device of any host is waiting for its host. */
export function anyWaiting(view: RevocationView): boolean {
  return view.hosts.some((host) => host.devices.some((device) => isWaiting(device.standing, host)))
}

/** How a host is reached, said under its name. */
export function describeRoute(host: RevocationHost, origin: string | null): string {
  if (host.route === 'direct') {
    return 'The host on this computer. Revocations go to it directly.'
  }
  const every = host.feed?.poll_interval_seconds
  const reads =
    host.feed?.removed === true
      ? ''
      : typeof every === 'number'
        ? ` The host reads its feed every ${every} seconds while it is online.`
        : ' The host reads its feed while it is online.'
  return origin === null
    ? `Reached through its feed.${reads}`
    : `Reached through its feed at ${origin}.${reads}`
}

/** What is known of whether the host answered, in a line. Null when it listed its devices. */
export function describeContact(host: RevocationHost, now: number = Date.now()): string | null {
  const name = hostCalled(host, true)
  switch (host.contact) {
    case 'answered':
      return null
    case 'refused':
      return `${name} will not list its devices to this computer.`
    case 'silent':
      return host.listed_at_ms === null
        ? `${name} is not answering, and this computer has no list of its devices yet.`
        : `${name} is not answering. These are the devices it listed ${whenOf(host.listed_at_ms, now)}.`
  }
}

/**
 * What a stop of the mailbox means for the person, or null when it was read. A host's answer is read
 * from its feed in any case, and the line says so, because a person who reads that announcements are
 * not arriving would otherwise take it for revocations not arriving.
 */
export function describeMailbox(mailbox: MailboxView): string | null {
  const still = 'Answers to revocations are still read from each feed.'
  switch (mailbox.stopped) {
    case null:
      return null
    case 'unreachable':
      return `This computer could not read its mailbox, where a host says that its feed changed. ${still}`
    case 'refused':
      return `The sync service turned back this computer's request for its mailbox. Check the sync service setting. ${still}`
    case 'waiting':
      return `The sync service asked this computer to wait before it reads its mailbox again. ${still}`
    case 'records':
      return `This computer could not use the records it reads its mailbox with, so it reads none. ${still}`
    case 'full':
      return `This computer's record of the mailbox items it has taken is full, so it takes no more until the oldest are due to be forgotten. ${still}`
    default:
      return null
  }
}

/** What the feed says, as lines. Each stands alone, and the first is the one that matters most. */
export function describeFeed(
  feed: RevocationFeed,
  host: RevocationHost,
  now: number = Date.now()
): readonly string[] {
  const lines: string[] = []
  if (!feed.read) {
    lines.push(
      `This computer could not read the feed${feed.problem === null ? '' : `: ${feed.problem}`}. A request sent earlier may be waiting there.`
    )
  }
  if (feed.removed) {
    lines.push(
      `The feed removed ${host.name}, so nothing published there reaches it. Revoke devices at the host itself.`
    )
  }
  if (feed.read) {
    const last = feed.last_acknowledgement
    lines.push(
      last === null
        ? `${host.name} has acknowledged no request in this feed yet.`
        : `${host.name} last acknowledged a request ${whenOf(last.at_ms, now)} (revision ${last.revision}).`
    )
    if (feed.outstanding > 0) {
      lines.push(
        feed.outstanding === 1
          ? '1 request is waiting for the host.'
          : `${feed.outstanding} requests are waiting for the host.`
      )
    }
  }
  if (host.host_synchronised_at_ms !== null) {
    lines.push(`${host.name} last read its feed ${whenOf(host.host_synchronised_at_ms, now)}.`)
  }
  if (host.host_feed_stale) {
    lines.push(`${host.name} says it could not reach its feed at its last check.`)
  }
  return lines
}

/** A device's second line: what it is, in a few words. */
export function describeDevice(device: RevocationDevice): string {
  const platform = {
    macos: 'Mac',
    windows: 'Windows',
    linux: 'Linux',
    ios: 'iPhone or iPad',
    android: 'Android'
  }[device.platform]
  const owner = device.manages_host ? ', an owner of the host' : ''
  return device.this_computer ? `${platform}${owner}. This computer.` : `${platform}${owner}.`
}

/**
 * The name of a revoke control, for a screen reader: its visible label first, then which device, on
 * which host. Null where this computer offers no ceremony.
 */
export function revokeName(
  device: RevocationDevice,
  host: RevocationHost,
  ceremony: CeremonyKind,
  again = false
): string | null {
  const label = revokeLabel(ceremony, again)
  return label === null ? null : `${label}: ${device.name} on ${hostCalled(host)}`
}

/** The name of the control that asks the host on this computer again, visible label first. */
export function checkAgainName(device: RevocationDevice, host: RevocationHost): string {
  return `Check again: has ${hostCalled(host)} finished revoking ${device.name}?`
}

/**
 * What changed between two views that a person should hear, as sentences: a request a host
 * acknowledged, finished or refused since the last view, and an acknowledgement whose host list
 * came to agree with it or to contradict it. Nothing is said for a request that is only still
 * waiting.
 */
export function announcements(before: RevocationView | null, after: RevocationView): readonly string[] {
  if (before === null) return []
  const said: string[] = []
  const mailbox = describeMailbox(after.mailbox)
  if (mailbox !== null && after.mailbox.stopped !== before.mailbox.stopped) said.push(mailbox)
  for (const host of after.hosts) {
    const earlier = before.hosts.find((each) => each.reference === host.reference)
    if (earlier === undefined) continue
    const name = hostCalled(host, true)
    for (const device of host.devices) {
      const was = earlier.devices.find((each) => each.reference === device.reference)
      if (was === undefined || !changedWhatIsDone(was.standing, device.standing)) continue
      switch (device.standing.state) {
        case 'done':
          said.push(
            host.route === 'direct'
              ? `${name} revoked ${device.name}, and every session confirmed it.`
              : `${name} acknowledged the revocation of ${device.name}, and every session confirmed it.`
          )
          break
        case 'acknowledged': {
          const heard = `${name} ${host.route === 'direct' ? 'recorded' : 'acknowledged'} the revocation of ${device.name}`
          const workers = device.standing.pending_workers
          said.push(
            device.standing.host_lists_revoked
              ? `${heard}, and ${workers !== null ? `${sessions(workers)} had not confirmed it yet` : 'has not said that every session confirmed it'}.`
              : `${heard}, but its own list does not show it revoked.`
          )
          break
        }
        case 'refused':
          said.push(`${name} refused the request to revoke ${device.name}.`)
          break
        default:
          break
      }
    }
  }
  return said
}

/** Whether a device's standing moved to another state, or an acknowledgement's host list changed. */
function changedWhatIsDone(was: RevocationStanding, now: RevocationStanding): boolean {
  if (was.state !== now.state) return true
  return (
    was.state === 'acknowledged' &&
    now.state === 'acknowledged' &&
    was.host_lists_revoked !== now.host_lists_revoked
  )
}
