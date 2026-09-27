/**
 * The requests a session's agent is waiting on a person for, each answered with one of the decisions
 * its decoder offered.
 *
 * Section 11 makes an installed decoder part of the trust boundary: what it read is shown beside the
 * request the agent actually sent, with whose decoder it was, so a person can check the one against
 * the other before answering. The decisions are the upstream's own, in its order, and each commits
 * only on a completed action. What is allowed, the agent then does with its own permissions on the
 * host, and nothing here says otherwise.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'

import type {
  AgentApprovalInspectResult,
  AgentCapabilitiesResult,
  OfferedDecision,
  PendingResource
} from '@kalareach/protocol'
import { base64UrlToBytes } from '@kalareach/protocol'

import { Banner, Button, CommitButton } from '../components/ui'
import { AGENT_READ_CADENCE_MS } from '../app/agent'
import { readOnCadence } from '../app/cadence'
import { useConnectionRights } from '../app/rights'
import { useApp } from '../app/state'
import { failureMessage, watch, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import {
  actionableApprovals,
  capabilityRecords,
  composerOffers,
  subjectOf,
  targetOf
} from '../model/agent'
import { describeElapsed } from '../model/attention'
import { outcomeMessage, outcomeTone } from '../model/receipts'

/** How much of a request's original bytes is shown before the rest is counted instead. */
const SHOWN_SOURCE_CHARS = 4096

/** One request, with what its decoder read and what the instance can do now. */
interface Waiting {
  readonly resource: PendingResource
  readonly inspection: AgentApprovalInspectResult
  readonly facts: AgentCapabilitiesResult
}

/** The request the agent sent, as text a person can read, and how much of it is not shown. */
function sourceText(encoded: string): { readonly text: string; readonly more: number } {
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: false }).decode(base64UrlToBytes(encoded))
  } catch {
    return { text: 'These bytes could not be read as text.', more: 0 }
  }
  return text.length > SHOWN_SOURCE_CHARS
    ? { text: text.slice(0, SHOWN_SOURCE_CHARS), more: text.length - SHOWN_SOURCE_CHARS }
    : { text, more: 0 }
}

/** The approvals waiting in one session. */
export function ApprovalRequests({
  sessionId,
  onAnswered
}: {
  readonly sessionId: string
  /** Called once an answer has been taken, so what listed the request can read again. */
  readonly onAnswered?: () => void
}): ReactNode {
  const { port, say } = useApp()
  const rights = useConnectionRights()
  // This view of this session: nothing read in an earlier visit to it is shown on a return.
  const visit = useMemo(() => ({ sessionId }), [sessionId])
  // What the newest read found, in the visit it was read in, and when: how long ago each request
  // was made is measured to the read that listed it.
  const [waiting, setWaiting] = useState<{
    readonly visit: object
    readonly requests: readonly Waiting[]
    readonly atMs: number
  } | null>(null)
  const [failure, setFailure] = useState<{ readonly visit: object; readonly words: string } | null>(
    null
  )
  // The request whose answer is on its way: its controls stand still until the host has answered.
  const [answering, setAnswering] = useState<string | null>(null)
  // Every read, on opening, on the cadence, after an answer and on a retry, goes through one
  // cadence under one watch: one read at a time, only the newest read's answer shown.
  const reads = useRef<Watch | null>(null)
  const again = useRef<() => void>(() => undefined)

  const load = useCallback((): Promise<void> => {
    const current = reads.current?.read() ?? null
    if (current === null) return Promise.resolve()
    return ask(async (): Promise<readonly Waiting[]> => {
      const agents = await port.sessionAgents(sessionId)
      const open = actionableApprovals(agents.resources)
      const instances = [...new Set(open.map((resource) => resource.application_instance_id))]
      const facts = new Map(
        await Promise.all(
          instances.map(
            async (instance) =>
              [
                instance,
                await port.agentCapabilities({ subject: subjectOf(sessionId, instance) })
              ] as const
          )
        )
      )
      return await Promise.all(
        open.map(async (resource) => {
          const instanceFacts = facts.get(resource.application_instance_id)
          if (instanceFacts === undefined) throw new Error('an instance was not read')
          return {
            resource,
            facts: instanceFacts,
            inspection: await port.approvalInspect({
              subject: subjectOf(sessionId, resource.application_instance_id),
              resource_id: resource.resource_id
            })
          }
        })
      )
    })
      .then((requests) => {
        if (!current()) return
        setWaiting({ visit, requests, atMs: Date.now() })
        setFailure(null)
      })
      .catch((error: unknown) => {
        if (!current()) return
        setFailure({ visit, words: failureMessage(error) })
      })
  }, [port, sessionId, visit])

  useEffect(() => {
    const cadence = readOnCadence(load, AGENT_READ_CADENCE_MS)
    const reading = watch([], cadence.now)
    reads.current = reading
    again.current = cadence.now
    return () => {
      cadence.stop()
      reading.stop()
      if (reads.current === reading) reads.current = null
      again.current = () => undefined
    }
  }, [load])

  const readAgain = useCallback(() => {
    again.current()
  }, [])

  const answer = (request: Waiting, decision: OfferedDecision) => {
    setAnswering(request.resource.resource_id)
    ask(() =>
      port.approvalRespond({
        target: targetOf(sessionId, request.resource.application_instance_id, request.facts.binding),
        resource_id: request.resource.resource_id,
        option_id: decision.option_id
      })
    )
      .then((settled) => {
        // The completion feedback waits for the host: what it answered, not what the network did.
        say(outcomeMessage(`You chose “${decision.label}”`, settled), outcomeTone(settled))
      })
      .catch((error: unknown) => {
        say(failureMessage(error), 'danger')
      })
      .finally(() => {
        setAnswering(null)
        onAnswered?.()
        readAgain()
      })
  }

  const refusal = failure?.visit === visit ? failure.words : null
  const shown = waiting?.visit === visit ? waiting : null
  const requests = shown?.requests ?? null
  const now = shown?.atMs ?? 0

  if (refusal !== null) {
    return (
      <Banner
        tone="warning"
        title="The requests waiting here could not be read"
        detail={refusal}
        action={<Button onClick={readAgain}>Try again</Button>}
      />
    )
  }
  if (requests === null || requests.length === 0) return null

  return (
    <section className="approvals" aria-label="Waiting for your decision" data-testid="approvals">
      {requests.map((request) => {
        const { resource, inspection, facts } = request
        const decoding = inspection.decoding
        const offer = composerOffers({
          known: true,
          binding: facts.binding,
          capabilities: capabilityRecords(facts.capabilities.records),
          rights: rights === null ? null : new Set(rights)
        }).answer
        const source = sourceText(decoding.source_bytes)
        const busy = answering === resource.resource_id
        return (
          <article
            className="approval"
            key={resource.resource_id}
            data-resource={resource.resource_id}
            data-testid="approval"
          >
            <p className="eyebrow">Waiting for you</p>
            <h3>{decoding.projection.summary}</h3>
            <p className="small muted">
              Read by {decoding.plugin_id} from {decoding.publisher_id} · asked{' '}
              {describeElapsed(now - Number(resource.recorded_at))} ago
            </p>
            <details className="approval-source">
              <summary>What the agent sent</summary>
              <pre className="code-block" data-testid="approval-source">
                {source.text}
              </pre>
              {source.more > 0 ? (
                <p className="small faint">And {source.more} more characters.</p>
              ) : null}
              <p className="small faint">
                {decoding.method} · request {decoding.upstream_request_id}. The summary above is
                what the decoder made of this; the host does not prove it read it correctly.
              </p>
            </details>
            <p className="small faint" data-testid="approval-authority">
              What you allow, the agent does with its own permissions on this computer.
            </p>
            <div className="row wrap approval-decisions">
              {decoding.projection.decisions.map((decision) => (
                <CommitButton
                  key={decision.option_id}
                  data-option={decision.option_id}
                  disabled={!offer.offered || busy}
                  title={offer.reason ?? undefined}
                  onCommit={() => {
                    answer(request, decision)
                  }}
                >
                  {decision.label}
                </CommitButton>
              ))}
            </div>
            {offer.reason !== null ? (
              <p className="small warning-text" data-testid="approval-unavailable">
                {offer.reason}
              </p>
            ) : null}
          </article>
        )
      })}
    </section>
  )
}
