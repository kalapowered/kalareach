/**
 * What a session's semantic archive carries: every entry of each live agent's history, as the
 * session's own worker gives it, and what the archive leaves out, declared.
 *
 * Section 25's export carries timestamps and declared omissions. Each entry keeps the identity, the
 * time, and the binding revision and turn the worker gave it. An entry the host's history filter
 * withheld from this device is not in the archive and is counted; so is an entry whose text did not
 * fit what one read carries, and a range the host no longer kept.
 */

import type { AgentSnapshotResult } from '@kalareach/protocol'

import type { ArchivedNode, HostPort, Omission } from '../host/port'
import { subjectOf } from './agent'

/** The most parts of one instance's history an archive follows. */
const MAX_ARCHIVE_PARTS = 256

/** The entries and the omissions of one session's semantic archive. */
export interface SemanticArchive {
  readonly nodes: readonly ArchivedNode[]
  readonly omissions: readonly Omission[]
}

/** Reads every live agent's whole history in `sessionId`, as its worker gives it. */
export async function readSemanticArchive(
  port: HostPort,
  sessionId: string
): Promise<SemanticArchive> {
  const agents = await port.sessionAgents(sessionId)
  const nodes: ArchivedNode[] = []
  let withheld = 0
  let cut = 0
  let gaps = 0
  let unfinished = 0
  for (const instance of agents.instances.instances) {
    if (instance.ended_at !== null) continue
    const id = instance.application_instance_id
    let from: string | null = null
    let finished = false
    for (let part = 0; part < MAX_ARCHIVE_PARTS; part += 1) {
      const read: AgentSnapshotResult = await port.agentSnapshot({
        subject: subjectOf(sessionId, id),
        from_node: from
      })
      withheld += Number(read.withheld_entries)
      if (read.history_gap) gaps += 1
      for (const entry of read.entries) {
        if (Number(entry.omitted_text_bytes) > 0) cut += 1
        nodes.push({
          id: `${id}:${entry.node}`,
          revision: '1',
          body: {
            instance: id,
            kind: entry.kind,
            text: entry.text,
            omitted_text_bytes: entry.omitted_text_bytes,
            // What the worker recorded the entry under, which can differ from what it is read
            // under.
            binding_revision: entry.binding_revision,
            turn_id: entry.turn_id
          },
          at_ms: Number(entry.observed_at)
        })
      }
      if (read.continuation === null) {
        finished = true
        break
      }
      from = read.continuation.from_node
    }
    if (!finished) unfinished += 1
  }
  const omissions: Omission[] = []
  if (withheld > 0) {
    omissions.push({
      kind: 'withheld_entries',
      detail: "Entries outside what this device's authority lets it read",
      count: withheld
    })
  }
  if (cut > 0) {
    omissions.push({
      kind: 'cut_entries',
      detail: 'Entries whose whole text did not fit what one read carries; each says how much is missing',
      count: cut
    })
  }
  if (gaps > 0) {
    omissions.push({
      kind: 'history_gap',
      detail: 'A range of entries the host no longer kept',
      count: gaps
    })
  }
  if (unfinished > 0) {
    omissions.push({
      kind: 'unfinished_history',
      detail: `An agent history longer than ${MAX_ARCHIVE_PARTS} reads carry; the rest is not in this archive`,
      count: unfinished
    })
  }
  return { nodes, omissions }
}
