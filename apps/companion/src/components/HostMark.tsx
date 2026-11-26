/**
 * A host's mark, drawn so that a line may break between its four groups and never inside one.
 *
 * The mark is sixteen hexadecimal characters in four groups, such as `3fa9-1c07-b2e4-77ab`. It tells
 * one host from another of the same name, and a person reads it group by group. Its text stays one
 * string, so copying or searching a line finds it as it is written.
 */

import { Fragment, type ReactNode } from 'react'

/** The mark of a host, group by group. */
export function HostMark({ mark }: { readonly mark: string }): ReactNode {
  return (
    <span className="host-mark">
      {mark.split('-').map((group, index) => (
        <Fragment key={index}>
          {index === 0 ? null : '-'}
          <span className="host-mark-group">{group}</span>
        </Fragment>
      ))}
    </span>
  )
}

/**
 * A sentence that holds a host's mark: the mark is drawn as {@link HostMark} wherever it stands in
 * the text, and the rest is text as it is. A sentence without a mark is the text itself.
 */
export function WithMark({
  text,
  mark
}: {
  readonly text: string
  readonly mark: string | null
}): ReactNode {
  if (mark === null || mark === '') return text
  return text.split(mark).map((piece, index) => (
    <Fragment key={index}>
      {index === 0 ? null : <HostMark mark={mark} />}
      {piece}
    </Fragment>
  ))
}
