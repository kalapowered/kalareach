/**
 * The pairing screen: this computer joins a host.
 *
 * Issuing an invitation stays with the host (`kr pair invite`); this screen is the other side. The
 * column is `PairingFlow`, which draws what native code reports and holds no secret but the code a
 * person types.
 */

import type { ReactNode } from 'react'

import { PairingFlow } from '../pairing/PairingFlow'

/** The pairing screen. */
export function Pairing(): ReactNode {
  return <PairingFlow />
}
