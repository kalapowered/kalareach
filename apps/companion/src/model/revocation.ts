/**
 * Revoking a device, in the words the page uses for it.
 *
 * A revocation is done only when the host's acknowledgement has been read. Everything before that is
 * said as what it is: sent, with nobody having answered it, or acknowledged with some of the host's
 * sessions still running. Nothing here calls a request that has not been acknowledged revoked.
 */

import type {
  CeremonyKind,
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

/** A moment, said short for today and with its day for another. */
export function momentOf(ms: number, now: number = Date.now()): string {
  const at = new Date(ms)
  const time = at.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
  const today = new Date(now)
  const sameDay =
    at.getFullYear() === today.getFullYear() &&
    at.getMonth() === today.getMonth() &&
    at.getDate() === today.getDate()
  return sameDay
    ? time
    : `${at.toLocaleDateString([], { day: 'numeric', month: 'short' })}, ${time}`
}

/** How many sessions, counted: "1 session", "3 sessions". */
function sessions(count: number): string {
  return count === 1 ? '1 session' : `${count} sessions`
}

/** What a host's refusal of a request means, in words. */
export function describeRefusal(reason: RevocationRefusal, host: string): string {
  switch (reason) {
    case 'no_owner_authority':
      return `${host} does not take this computer as one of its owners, so it refused the request.`
    case 'unknown_target':
      return `${host} does not know this device, so it refused the request.`
    case 'superseded':
      return `${host} refused the request because an earlier revocation covers it.`
  }
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
 * acknowledged is not described as anything more than sent.
 */
export function describeStanding(
  standing: RevocationStanding,
  host: RevocationHost,
  now: number = Date.now()
): string | null {
  switch (standing.state) {
    case 'active':
      return null
    case 'revoked':
      return `${host.name} lists this device as revoked.`
    case 'sent': {
      const sent = `Sent ${momentOf(standing.at_ms, now)}. ${host.name} has not acknowledged it yet.`
      return standing.host_lists_revoked ? `${sent} It already lists the device as revoked.` : sent
    }
    case 'acknowledged': {
      const who = host.route === 'direct' ? "This computer's host recorded it" : `${host.name} acknowledged it`
      const at = `${who} ${momentOf(standing.at_ms, now)}`
      // A host that has not said how many sessions are left has not said that none are.
      const stopped =
        standing.pending_workers !== null
          ? `, and ${sessions(standing.pending_workers)} had not stopped yet`
          : standing.host_lists_revoked
            ? ', and has not said that every session stopped'
            : ''
      return standing.host_lists_revoked
        ? `${at}${stopped}.`
        : `${at}${stopped}. Its own list does not show the device as revoked. Revoke it at the host.`
    }
    case 'done':
      return host.route === 'direct'
        ? `This computer's host revoked it ${momentOf(standing.at_ms, now)}, with every session stopped.`
        : `${host.name} acknowledged it ${momentOf(standing.at_ms, now)}, with every session stopped.`
    case 'refused':
      return describeRefusal(standing.reason, host.name)
  }
}

/** Whether a standing is one the host has yet to finish, so the screen asks again while it waits. */
export function isWaiting(standing: RevocationStanding): boolean {
  return standing.state === 'sent' || standing.state === 'acknowledged'
}

/** Whether any device of any host is waiting for its host. */
export function anyWaiting(view: RevocationView): boolean {
  return view.hosts.some((host) => host.devices.some((device) => isWaiting(device.standing)))
}

/** How a host is reached, said under its name. */
export function describeRoute(host: RevocationHost, origin: string | null): string {
  if (host.route === 'direct') {
    return 'The host on this computer. A revocation takes effect here at once.'
  }
  const every = host.feed?.poll_interval_seconds
  const reads =
    typeof every === 'number'
      ? `The host reads its feed every ${every} seconds while it is online.`
      : 'The host reads its feed while it is online.'
  return origin === null
    ? `Reached through its feed. ${reads}`
    : `Reached through its feed at ${origin}. ${reads}`
}

/** What is known of whether the host answered, in a line. Null when it listed its devices. */
export function describeContact(host: RevocationHost, now: number = Date.now()): string | null {
  switch (host.contact) {
    case 'answered':
      return null
    case 'refused':
      return `${host.name} will not list its devices to this computer.`
    case 'silent':
      return host.listed_at_ms === null
        ? `${host.name} is not answering, and this computer has no list of its devices yet.`
        : `${host.name} is not answering. These are the devices it listed at ${momentOf(host.listed_at_ms, now)}.`
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
        ? `${host.name} has written nothing in this feed yet.`
        : `${host.name} last acknowledged a request at ${momentOf(last.at_ms, now)} (revision ${last.revision}).`
    )
    if (feed.outstanding > 0) {
      lines.push(
        feed.outstanding === 1
          ? '1 request is waiting for the host.'
          : `${feed.outstanding} requests are waiting for the host.`
      )
    }
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

/** The label of a revoke control, for a screen reader: which device, on which host, how. */
export function revokeName(
  device: RevocationDevice,
  host: RevocationHost,
  ceremony: CeremonyKind,
  again = false
): string | null {
  const how = by(ceremony)
  return how === null
    ? null
    : `${again ? 'Revoke again' : 'Revoke'} ${device.name} on ${host.name} ${how}`
}

/**
 * What changed between two views that a person should hear, as sentences: a request a host
 * acknowledged, finished or refused since the last view. Nothing is said for a request that is only
 * still waiting.
 */
export function announcements(before: RevocationView | null, after: RevocationView): readonly string[] {
  if (before === null) return []
  const said: string[] = []
  for (const host of after.hosts) {
    const earlier = before.hosts.find((each) => each.reference === host.reference)
    if (earlier === undefined) continue
    for (const device of host.devices) {
      const was = earlier.devices.find((each) => each.reference === device.reference)
      if (was === undefined || was.standing.state === device.standing.state) continue
      switch (device.standing.state) {
        case 'done':
          said.push(`${device.name} is revoked: ${host.name} acknowledged it.`)
          break
        case 'acknowledged':
          said.push(
            device.standing.host_lists_revoked
              ? `${host.name} acknowledged the revocation of ${device.name}, and some sessions have not stopped.`
              : `${host.name} acknowledged the revocation of ${device.name}, but its own list does not show it revoked.`
          )
          break
        case 'refused':
          said.push(`${host.name} refused the request to revoke ${device.name}.`)
          break
        default:
          break
      }
    }
  }
  return said
}
