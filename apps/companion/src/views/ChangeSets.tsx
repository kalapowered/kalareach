/**
 * Change sets, and the retained artefacts a privacy generation left behind.
 *
 * Both are lists of things the person may act on, and both have the same rule underneath: nothing
 * is removed because it looked stale. A change set stays until it is reviewed; a retained artefact
 * is deleted only by an action that is about that artefact.
 */

import { useCallback, useEffect, useState, type ReactNode } from 'react'

import { Badge, Banner, Button, Card, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import { failureMessage } from '../host/port'
import { outcomeMessage, receiptTone } from './Conversation'
import type { ChangeSets as ChangeSetList, RetainedArtefacts } from '../model/pending'

/** Change sets and retained artefacts. */
export function ChangeSets(): ReactNode {
  const { port, say } = useApp()
  const [sets, setSets] = useState<ChangeSetList | null>(null)
  const [retained, setRetained] = useState<RetainedArtefacts | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  const load = useCallback(() => {
    Promise.all([port.changesetRead({}), port.storageStatus({})])
      .then(([changes, storage]) => {
        setSets(changes as ChangeSetList)
        setRetained(storage as RetainedArtefacts)
        setFailure(null)
      })
      .catch((error: unknown) => {
        setFailure(failureMessage(error))
      })
  }, [port])

  useEffect(load, [load])

  const changesets = sets?.changesets ?? []
  const current = changesets.find((set) => set.changeset_id === selected) ?? changesets[0]

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Change sets</p>
          <h1>Changes</h1>
          <p>What each session changed, kept as it was captured.</p>
        </div>
      </header>

      {failure ? (
        <Banner
          tone="warning"
          title="This could not be read"
          detail={failure}
          action={<Button onClick={load}>Try again</Button>}
        />
      ) : null}

      {changesets.length === 0 ? (
        <div className="empty-state">
          <h2>No changes captured</h2>
          <p>A session that changes files records a change set here.</p>
        </div>
      ) : (
        <div className="review-layout">
          <Card className="file-nav">
            <div className="card-body">
              {changesets.map((set) => (
                <button
                  key={set.changeset_id}
                  type="button"
                  className="file-button"
                  aria-current={set.changeset_id === current?.changeset_id}
                  onClick={() => {
                    setSelected(set.changeset_id)
                  }}
                >
                  <span className="spacer">{set.title}</span>
                  {set.reviewed ? <Badge tone="success">Reviewed</Badge> : null}
                </button>
              ))}
            </div>
          </Card>
          <Card>
            <div className="card-header">
              <div className="spacer">
                <h2>{current?.title ?? ''}</h2>
                <p className="muted small">
                  {current?.files.length ?? 0} file
                  {(current?.files.length ?? 0) === 1 ? '' : 's'} changed
                </p>
              </div>
              <Button
                data-testid="mark-reviewed"
                onClick={() => {
                  say('Marked as reviewed.')
                }}
              >
                Mark reviewed
              </Button>
            </div>
            <div className="card-body">
              {(current?.files ?? []).map((file) => (
                <div key={file.path}>
                  <div className="divided-row">
                    <span className="mono spacer">{file.path}</span>
                    <span className="success-text small">+{file.added}</span>
                    <span className="danger-text small">-{file.removed}</span>
                  </div>
                  {file.hunks.map((hunk) => (
                    <pre className="diff-code" key={hunk.header}>
                      <span className="diff-line faint">{hunk.header}</span>
                      {hunk.lines.map((line, index) => (
                        <span className={`diff-line ${line.kind}`} key={`${hunk.header}-${index}`}>
                          {line.kind === 'add' ? '+' : line.kind === 'remove' ? '-' : ' '}
                          {line.text}
                        </span>
                      ))}
                    </pre>
                  ))}
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {retained ? (
        <section className="stack" data-testid="retained-artefacts">
          <header className="page-heading">
            <div>
              <p className="eyebrow">Privacy</p>
              <h2>What is still held</h2>
              <p>
                {retained.privacy_mode
                  ? `Privacy mode has been on since generation ${retained.privacy_generation}. Nothing new is retained. These were uploaded or delivered before that, and they are still there.`
                  : 'Privacy mode is off. New sessions retain their history.'}
              </p>
            </div>
          </header>
          <Card>
            <div className="card-body">
              {retained.artefacts.length === 0 ? (
                <p className="muted small">Nothing is held from before that point.</p>
              ) : null}
              {retained.artefacts.map((artefact) => (
                <div className="divided-row" key={artefact.object_id}>
                  <div className="spacer">
                    <strong>{artefact.description}</strong>
                    <p className="muted small">
                      {artefact.location} · {Math.round(artefact.byte_len / 1024)} KB
                    </p>
                    {artefact.held_by_other_party ? (
                      <p className="small warning-text" data-testid="held-elsewhere">
                        This copy is on someone else&apos;s device. Deleting here cannot reach it.
                      </p>
                    ) : null}
                  </div>
                  <CommitButton
                    tone="danger"
                    disabled={artefact.held_by_other_party}
                    data-testid={`delete-${artefact.object_id}`}
                    onCommit={() => {
                      port
                        .storageObjectDelete({ object_id: artefact.object_id }, {})
                        .then((result) => {
                          say(
                            outcomeMessage(
                              'Deleted, which removes the record rather than the physical bytes',
                              result.receipt
                            ),
                            receiptTone(result.receipt)
                          )
                          load()
                        })
                        .catch((error: unknown) => {
                          say(failureMessage(error), 'danger')
                        })
                    }}
                  >
                    Delete this one
                  </CommitButton>
                </div>
              ))}
              <p className="small faint">
                Each of these is deleted on its own. Nothing here removes a backup collection you
                did not name, and local deletion is a logical cleanup rather than a secure erase.
              </p>
            </div>
          </Card>
        </section>
      ) : null}
    </>
  )
}
