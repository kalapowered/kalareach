/**
 * Change sets, and the retained artefacts a privacy generation left behind.
 *
 * Both are lists of things the person may act on, and both have the same rule underneath: nothing
 * is removed because it looked stale. A change set is an immutable captured version: this shows
 * exactly what it holds and what it left out, every version of it beside the one read, and marking
 * one reviewed records that this version was reviewed and changes nothing else. A retained artefact
 * is deleted only by an action that is about that artefact.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'

import type { ChangesetReadResult, ReviewReadResult, ReviewState } from '@kalareach/protocol'

import { Badge, Banner, Button, Card, CommitButton } from '../components/ui'
import { useApp } from '../app/state'
import { failureCode, failureMessage, watch, type HostPort, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import { outcomeMessage, outcomeTone } from '../model/receipts'
import type { RetainedArtefacts } from '../model/pending'

/** The largest page of review state one read asks for. */
const PAGE_REVIEWS = '200'

/** The most pages of review state one read follows. */
const MAX_REVIEW_PAGES = 16

/**
 * Every review subject the host holds for this caller, page by page.
 *
 * Each page continues after the last subject of the one before, until the host says there is no
 * more or the bound is reached; the answer's `more` then says whether the host holds more than was
 * read. A subject can go between two pages, and the host refuses a page that continues after one
 * it no longer holds: the list is then read again from its start, once.
 */
async function readAllReviews(port: HostPort): Promise<ReviewReadResult> {
  const follow = async (): Promise<ReviewReadResult> => {
    let page = await port.reviewRead({
      session_id: null,
      subject: null,
      max_reviews: PAGE_REVIEWS,
      after: null
    })
    const reviews = [...page.reviews]
    for (let pages = 1; page.more && pages < MAX_REVIEW_PAGES; pages += 1) {
      const last = page.reviews.at(-1)
      if (last === undefined) break
      page = await port.reviewRead({
        session_id: null,
        subject: null,
        max_reviews: PAGE_REVIEWS,
        after: last.subject
      })
      reviews.push(...page.reviews)
    }
    return { ...page, reviews }
  }
  try {
    return await follow()
  } catch (failure: unknown) {
    if (failureCode(failure) !== 'DRAFT_CONFLICT') throw failure
    return await follow()
  }
}

/** A review subject that is a change set, with where it was captured. */
interface ChangeSetReview {
  readonly review: ReviewState
  readonly sessionId: string
  readonly changeSetId: string
}

/** The change sets among the subjects a review read listed. */
function changeSetsOf(reviews: ReviewReadResult | null): readonly ChangeSetReview[] {
  return (reviews?.reviews ?? []).flatMap((review) =>
    'change_set' in review.subject
      ? [
          {
            review,
            sessionId: review.subject.change_set.session_id,
            changeSetId: review.subject.change_set.change_set_id
          }
        ]
      : []
  )
}

/** What each consistency class promises, in words. */
const CONSISTENCY: Readonly<Record<ChangesetReadResult['version']['consistency'], string>> = {
  atomic_snapshot: 'Read from one atomic snapshot of the repository.',
  quiesced_capture: 'Read while the workspace was held still.',
  per_file_capture: 'Read file by file from a live working tree, which may have changed meanwhile.'
}

/** Why a path was left out, in words. */
const EXCLUDED: Readonly<Record<ChangesetReadResult['version']['exclusions'][number]['reason'], string>> =
  {
    policy: 'Left out by the capture policy',
    grant: 'Outside the paths the capture was allowed to read',
    secret_rule: 'Covered by a secret rule, so never read',
    unsupported: 'Not file content',
    deleted: 'Deleted in the working tree',
    unreadable: 'Could not be read'
  }

/** Change sets and retained artefacts. */
export function ChangeSets(): ReactNode {
  const { port, say } = useApp()
  const [reviews, setReviews] = useState<ReviewReadResult | null>(null)
  // Each listed change set's newest version, by its identifier.
  const [versions, setVersions] = useState<ReadonlyMap<string, ChangesetReadResult>>(new Map())
  const [retained, setRetained] = useState<RetainedArtefacts | null>(null)
  const [failure, setFailure] = useState<string | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  // Every read, on opening, after an action and on a retry, is made under one watch with no
  // listeners, so only the newest read's answer is shown, and none once the screen closes.
  const reads = useRef<Watch | null>(null)

  const load = useCallback(() => {
    const current = reads.current?.read() ?? null
    if (current === null) return
    ask(async () => {
      const listed = await readAllReviews(port)
      // Each change set is read at the version its review names, so what is shown, the review's
      // mark and what marking it reviewed acknowledges are all the same version, whatever was
      // captured since the list was read.
      const read = await Promise.all(
        changeSetsOf(listed).map(
          async (each) =>
            [
              each.changeSetId,
              await port.changesetRead({
                change_set_id: each.changeSetId,
                version: each.review.current_version
              })
            ] as const
        )
      )
      return { listed, read }
    })
      .then(({ listed, read }) => {
        if (!current()) return
        setReviews(listed)
        setVersions(new Map(read))
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure(failureMessage(error))
      })
    // What a privacy generation left behind is its own read, and one this host may not answer:
    // the change sets are shown whether or not it does.
    ask(() => port.storageStatus({}))
      .then((storage) => {
        if (!current()) return
        setRetained(storage as RetainedArtefacts)
      })
      .catch(() => {
        if (!current()) return
        setRetained(null)
      })
  }, [port])

  useEffect(() => {
    const reading = watch([], load)
    reads.current = reading
    return () => {
      reading.stop()
      if (reads.current === reading) reads.current = null
    }
  }, [load])

  const changeSets = changeSetsOf(reviews)
  const current = changeSets.find((each) => each.changeSetId === selected) ?? changeSets[0]
  const currentId = current?.changeSetId ?? null

  const shown = currentId === null ? null : (versions.get(currentId) ?? null)
  const version = shown?.version ?? null

  const markReviewed = (review: ChangeSetReview) => {
    ask(() =>
      port.reviewAcknowledge({
        session_id: review.sessionId,
        subject: review.review.subject,
        version: review.review.current_version
      })
    )
      .then((settled) => {
        say(outcomeMessage('Marked as reviewed', settled), outcomeTone(settled))
        load()
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
  }

  return (
    <>
      <header className="page-heading">
        <div>
          <p className="eyebrow">Change sets</p>
          <h1>Changes</h1>
          <p>What each session changed, kept exactly as it was captured.</p>
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

      {reviews?.more ? (
        <p className="small muted" data-testid="reviews-more">
          The host holds more change sets than this list shows.
        </p>
      ) : null}

      {changeSets.length === 0 ? (
        <div className="empty-state">
          <h2>{reviews === null ? 'Reading the change sets…' : 'No changes captured'}</h2>
          <p>A session that changes files records a change set here.</p>
        </div>
      ) : (
        <div className="review-layout">
          <Card className="file-nav">
            <div className="card-body">
              {changeSets.map((each) => (
                <button
                  key={each.changeSetId}
                  type="button"
                  className="file-button"
                  aria-current={each.changeSetId === currentId}
                  data-testid={`change-set-${each.changeSetId}`}
                  onClick={() => {
                    setSelected(each.changeSetId)
                  }}
                >
                  <span className="spacer">
                    {versions.get(each.changeSetId)?.version.label ?? 'Change set'}
                  </span>
                  {each.review.outstanding ? (
                    <Badge tone="warning">To review</Badge>
                  ) : (
                    <Badge tone="success">Reviewed</Badge>
                  )}
                </button>
              ))}
            </div>
          </Card>
          <Card data-testid="change-set">
            <div className="card-header">
              <div className="spacer">
                <h2>{version?.label ?? 'Reading this change set…'}</h2>
                {version ? (
                  <p className="muted small">
                    Version {version.version} of {shown?.versions.length ?? 1} · against{' '}
                    <span className="mono">
                      {version.base_reference ?? version.base_revision.slice(0, 12)}
                    </span>{' '}
                    · {Number(version.summary.total_paths).toLocaleString()} paths
                  </p>
                ) : null}
              </div>
              {current?.review.outstanding && version ? (
                <CommitButton
                  data-testid="mark-reviewed"
                  onCommit={() => {
                    markReviewed(current)
                  }}
                >
                  Mark version {current.review.current_version} reviewed
                </CommitButton>
              ) : null}
            </div>
            {version ? (
              <div className="card-body">
                <p className="small muted">{CONSISTENCY[version.consistency]}</p>
                <p className="small faint">{version.consistency_detail}</p>
                <h3>Changed</h3>
                {version.changes.map((path) => (
                  <div className="divided-row" key={path.path} data-change={path.change}>
                    <span className="mono spacer">{path.path}</span>
                    <span className="small muted">
                      {path.change === 'deleted'
                        ? 'Deleted'
                        : path.change === 'unmerged'
                          ? 'Unmerged'
                          : `${Number(path.byte_len).toLocaleString()} bytes${path.content === 'binary' ? ', binary' : ''}`}
                    </span>
                  </div>
                ))}
                {Number(version.omitted_changes) > 0 ? (
                  <p className="small faint">
                    And {version.omitted_changes} more changed paths this read does not list.
                  </p>
                ) : null}
                {version.exclusions.length > 0 ? (
                  <>
                    <h3>Left out</h3>
                    {version.exclusions.map((exclusion) => (
                      <div className="divided-row" key={exclusion.path}>
                        <span className="mono spacer">{exclusion.path}</span>
                        <span className="small muted">{EXCLUDED[exclusion.reason]}</span>
                      </div>
                    ))}
                  </>
                ) : null}
                {version.limitations.map((limitation) => (
                  <p className="small faint" key={limitation}>
                    {limitation}
                  </p>
                ))}
                <p className="small faint">
                  Marking a version reviewed records that you reviewed it. It approves nothing,
                  applies nothing and changes no file; a later version is new work to review.
                </p>
              </div>
            ) : null}
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
                              result
                            ),
                            outcomeTone(result)
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
