/**
 * The title a row shows: the host's own words, as it wrote them, or until the host has answered the
 * name of the session's directory, which is a technical word and breaks at its separators.
 */

import type { ReactNode } from 'react'

import { shownTitle, type Described } from '../model/describe'
import { TechnicalWord } from './TechnicalWord'

export function ShownTitle({
  directoryName,
  described
}: {
  readonly directoryName: string
  readonly described: Described | undefined
}): ReactNode {
  const title = shownTitle(directoryName, described)
  return title === directoryName ? <TechnicalWord text={title} /> : title
}
