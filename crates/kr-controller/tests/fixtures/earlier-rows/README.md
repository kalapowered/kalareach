# Rows an earlier build wrote

Six stored payloads, each as canonical CBOR in hexadecimal, encoded by the build at `1f2d55fe68e5`
with its own types. That build named approvals in a grant, a pairing proposal and a sharing
preview by an upstream's text identifier; this one names them by the broker's resource identity
and reads no other shape.

| Key | What the column holds |
| --- | --- |
| `network_devices.grant` | The grant device `d1d1…` was paired with |
| `pairing_invitations.proposed_grant` | The rights the pairing invitation proposed |
| `pairing_commitments.commitment` | What the pairing of invitation `1111…` committed |
| `grants.grant` | Grant `6262…`, sharing session `5353…` with device `d1d1…` |
| `authority_receipts.result` | The retained answer to the `grant.create` that wrote that grant |
| `session_invitations.preview` | What invitation `1313…`'s issuer was shown |

Each comes in two forms. `empty` names no approval, as every build wrote it. `named` names the
approval `1` by that text. Nothing regenerates these rows: they change only by a deliberate
re-encoding at a named commit.
