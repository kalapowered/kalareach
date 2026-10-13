/**
 * Keeps one session's agent read while a view of it is open.
 *
 * The session's own worker is the one source: which instance is live, what it can do now, the
 * requests it is waiting on a person for, and its semantic history. The history is an ordered log
 * with a number on every entry, and the host announces nothing when an entry is added, so the view
 * reads it again while it is shown, each time from the entry after the last one it holds. While an
 * instance runs, nothing falls between two reads, and nothing is read twice: an entry keeps its
 * identity, and a copy carrying more of its text than the one held replaces it. An instance's
 * history goes with it when it ends, so what it wrote after the last read is not read, and the
 * session's store records that instance as unfinished.
 *
 * What is read goes into the session's own store, so the conversation and the terminal, and a
 * change of view, share it, and a read that answers after the view moved on changes nothing.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type {
  AgentCapabilitiesResult,
  AgentCommandsResult,
  AgentSnapshotResult
} from '@kalareach/protocol'

import { readOnCadence } from './cadence'
import { useApp, useSession } from './state'
import { failureMessage, watch, type SessionAgents, type Watch } from '../host/port'
import { ask } from '../mobile/model/call'
import {
  agentEntry,
  capabilityRecords,
  foldWithheld,
  liveInstance,
  subjectOf
} from '../model/agent'
import { applyNodes, type ConversationItem } from '../model/conversation'

/**
 * How long after one read of the agent the next one starts while a view of it is shown.
 *
 * The host announces no new entry, so this is how soon an entry the agent wrote reaches the page.
 */
export const AGENT_READ_CADENCE_MS = 1_500

/** The most parts of the history one read follows; the next read continues from where it stopped. */
const MAX_PARTS_PER_READ = 16

/** What a view of the agent is told beyond what the session's store holds. */
export interface SessionAgentView {
  /** Why the newest read was refused, for this session, or null. */
  readonly unread: string | null
  /** Reads again now, as after an action the view took. */
  readonly refresh: () => void
}

/** Everything one read found. */
interface Read {
  readonly agents: SessionAgents
  readonly instance: string | null
  readonly facts: AgentCapabilitiesResult | null
  readonly commands: AgentCommandsResult | null
  /** Where the first part started. */
  readonly start: string | null
  readonly parts: readonly AgentSnapshotResult[]
  /** Where the next read starts. */
  readonly from: string | null
}

/**
 * The opening a view reads the agent under, when it has one.
 *
 * Every read carries the token, and reading goes on only while the host says the opening is open:
 * an opening that is over, refused or being taken up again reads nothing, and starts again, from
 * where the store left off, when it is open.
 */
export interface OpeningGate {
  /** The opening's token, or null before the screen has made one. */
  readonly token: string | null
  /** Whether the host says the opening is open. */
  readonly running: boolean
}

/** Keeps `sessionId`'s agent read while the calling view is mounted and the page is shown. */
export function useSessionAgent(
  sessionId: string,
  { cadenceMs = AGENT_READ_CADENCE_MS, gate }: { cadenceMs?: number; gate?: OpeningGate } = {}
): SessionAgentView {
  const token = gate === undefined ? undefined : (gate.token ?? undefined)
  const waiting = gate !== undefined && (gate.token === null || !gate.running)
  const { port, sessions } = useApp()
  const { update } = useSession(sessionId)
  // This view of this session: a refusal read in an earlier visit to it is not shown on a return,
  // until a read in this visit says so again.
  // The opening is part of the visit: what an earlier opening's read was refused with is not this one's.
  // Each time the opening stops being open and is open again starts another visit: what an earlier read
  // was refused with is not shown again before a read of this one has answered.
  const visit = useMemo(() => ({ sessionId, token, waiting }), [sessionId, token, waiting])
  const [unread, setUnread] = useState<{ readonly visit: object; readonly words: string } | null>(
    null
  )
  const again = useRef<() => void>(() => undefined)

  useEffect(() => {
    // An opening that is not open reads nothing; the effect runs again when it is.
    if (waiting) return
    let watching: Watch | null = null

    const once = async (): Promise<Read> => {
      const agents = await port.sessionAgents(sessionId, token)
      const live = liveInstance(agents.instances.instances)
      if (live === null) {
        return {
          agents,
          instance: null,
          facts: null,
          commands: null,
          start: null,
          parts: [],
          from: null
        }
      }
      const instance = live.application_instance_id
      const subject = subjectOf(sessionId, instance)
      const facts = await port.agentCapabilities({ subject }, token)
      const known = sessions.get(sessionId).agent
      const commands =
        known.commandsOf === instance ? null : await port.agentCommands({ subject }, token)
      const start = known.nextNode.get(instance) ?? null
      let from = start
      const parts: AgentSnapshotResult[] = []
      for (let part = 0; part < MAX_PARTS_PER_READ; part += 1) {
        const read = await port.agentSnapshot({ subject, from_node: from }, token)
        parts.push(read)
        if (read.continuation !== null) {
          from = read.continuation.from_node
          continue
        }
        const last = read.entries.at(-1)
        if (last === undefined) break
        // A part that found entries is read on from after the last of them, so that what it
        // counted as withheld beyond them is counted apart from what it withheld before them.
        from = String(BigInt(last.node) + 1n)
      }
      return { agents, instance, facts, commands, start, parts, from }
    }

    const fold = (found: Read) => {
      update((state) => {
        const { agents, instance, facts, commands, start, parts, from } = found
        // An instance this view was reading that is no longer the one it reads has taken what it
        // wrote since the last read with it.
        const previous = state.agent.instance
        const unfinished =
          previous !== null && previous !== instance
            ? new Set([...state.agent.unfinished, previous])
            : state.agent.unfinished
        if (instance === null || facts === null) {
          return {
            ...state,
            loaded: true,
            agent: {
              ...state.agent,
              instances: agents.instances.instances,
              resources: agents.resources,
              instance: null,
              binding: null,
              capabilities: null,
              unfinished
            }
          }
        }
        const items: ConversationItem[] = parts.flatMap((part) =>
          part.entries.map((entry) => ({ source: 'entry' as const, ...agentEntry(instance, entry) }))
        )
        const nextNode = new Map(state.agent.nextNode)
        if (from !== null) nextNode.set(instance, from)
        const withheld = new Map(state.agent.withheld)
        withheld.set(instance, foldWithheld(withheld.get(instance), start, parts))
        return {
          ...state,
          loaded: true,
          conversation: items.length > 0 ? applyNodes(state.conversation, items) : state.conversation,
          agent: {
            instances: agents.instances.instances,
            resources: agents.resources,
            instance,
            // The newest read's: the snapshot is read after the capabilities.
            binding: parts.at(-1)?.binding ?? facts.binding,
            capabilities: capabilityRecords(facts.capabilities.records),
            commands: commands?.commands ?? state.agent.commands,
            commandsOf: instance,
            nextNode,
            withheld,
            gap: state.agent.gap || parts.some((part) => part.history_gap),
            unfinished
          }
        }
      })
    }

    // One read at a time, and each answer shown only while it is the newest and the view is open.
    const cadence = readOnCadence(() => {
      const current = watching?.read() ?? null
      if (current === null) return Promise.resolve()
      return ask(once)
        .then((found) => {
          if (!current()) return
          fold(found)
          setUnread(null)
        })
        .catch((failure: unknown) => {
          if (!current()) return
          setUnread({ visit, words: failureMessage(failure) })
        })
    }, cadenceMs)

    watching = watch(
      [
        port.onConnection((state) => {
          if (state.connected) cadence.now()
        })
      ],
      cadence.now,
      (failure) => {
        setUnread({ visit, words: failureMessage(failure) })
      }
    )
    again.current = cadence.now
    const started = watching
    return () => {
      cadence.stop()
      started.stop()
      again.current = () => undefined
    }
  }, [port, sessions, sessionId, visit, update, cadenceMs, token, waiting])

  const refresh = useCallback(() => {
    again.current()
  }, [])

  // An opening that is not open reads nothing and says nothing of reading: what it read stays shown.
  return { unread: !waiting && unread?.visit === visit ? unread.words : null, refresh }
}
