/**
 * A service's address inside a sentence, bold for the eye and said as words to a screen reader.
 *
 * An address such as `reach.kala.to` is letters and dots: left as it stands, a screen reader runs
 * it together or spells it, and the phone's own accessibility audit refuses it as a label that is
 * not language. The address is drawn as it is written, and hidden from a screen reader, which reads
 * it as words in its place: "reach dot kala dot to".
 */

import type { ReactNode } from 'react'

/**
 * An address as a person says it aloud: each dot is the word "dot", each colon of an IPv6 literal
 * is the word "colon", and a port is "port" and its number.
 *
 * An IPv6 literal comes in either of two forms: with its brackets, and a port after them, as an
 * origin spells it, or bare, as the pairing service's host does. A name or an IPv4 address has one
 * colon at the most, before its port, and an IPv6 literal has two or more, so a bare literal's last
 * group is never read as a port.
 */
export function spokenAddress(host: string): string {
  const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(host)
  if (bracketed !== null) return withPort(sayColons(bracketed[1]), bracketed[2])
  if (host.split(':').length > 2) return sayColons(host)
  const named = /^(.*?)(?::(\d+))?$/.exec(host)
  return withPort((named?.[1] ?? host).split('.').join(' dot '), named?.[2])
}

function sayColons(groups: string): string {
  return groups.split(':').join(' colon ').replace(/\s+/g, ' ').trim()
}

function withPort(words: string, port: string | undefined): string {
  return port === undefined ? words : `${words} port ${port}`
}

/** The address, written for the eye and spoken for a screen reader. `testId` marks the written form. */
export function ServiceAddress({
  host,
  testId
}: {
  readonly host: string
  readonly testId: string
}): ReactNode {
  return (
    <strong>
      <span className="visually-hidden spoken-form">{spokenAddress(host)}</span>
      <span aria-hidden="true" data-testid={testId}>
        {host}
      </span>
    </strong>
  )
}
