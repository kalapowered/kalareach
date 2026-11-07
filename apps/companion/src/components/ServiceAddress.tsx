/**
 * A service's address inside a sentence, bold for the eye and said as words to a screen reader.
 *
 * An address such as `reach.kala.to` is letters and dots: left as it stands, a screen reader runs
 * it together or spells it, and the phone's own accessibility audit refuses it as a label that is
 * not language. The address is drawn as it is written, and hidden from a screen reader, which reads
 * it as words in its place: "reach dot kala dot to".
 */

import type { ReactNode } from 'react'

/** An address as a person says it aloud: each dot is the word "dot", and a port is "port" and its number. */
export function spokenAddress(host: string): string {
  return host.replace(/:(\d+)$/, ' port $1').split('.').join(' dot ')
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
