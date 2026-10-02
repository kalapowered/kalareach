# Signing keys and who rotates them

KalaReach keeps four families of signing key apart: the keys that sign releases and updates, the
catalogue's trust roles, the service's admission key and each organisation's policy key. No key
serves two of them. This page names each key, where its private half is held, where its public half
is pinned, who rotates it and how it is recovered. The owners are roles, as they are in the
website's record of what an operator supplies; the person who holds a role is the operator's to
name.

| Key | What it signs | Where the private half is held | Where the public half is pinned | Rotation owner | Rotation and recovery |
| --- | --- | --- | --- | --- | --- |
| Update channel root keys and release keys | The manifest of each host release, by a threshold of the release keys the root names for its targets role, and the next version of the root | The release keys in hardware-backed signing services, the channel roots on offline media | `share/update-root.json` in each release: a host trusts the root of the release it runs | Release owner | A release carries the root or the next one, signed by a threshold of the current root's keys as well as its own ([Updating a host](../host/updates.md)). A host whose current release carries no root has no key to check another release against, and `kr host update` refuses every archive there |
| Windows code-signing identity | Every Windows executable and PowerShell package a release publishes | Azure Artifact Signing, in hardware security modules that do not give the key up; no secret or certificate credential exists | The Authenticode chain to the Microsoft root, with each signature timestamped; the identifiers are public | The Azure subscription owner for the profile and its role, the Entra application administrator for the application and its federated credential, the GitHub repository administrator for the environment | [Rotation and recovery](windows-signing.md#rotation-and-recovery) names each case, the incident steps and the recovery of a lost account |
| Release matrix signing key | The matrix of client, relay and discovery versions that work together, which the website publishes | The website's Worker secret `RELEASE_MATRIX_SIGNING_KEY` | The public half is published beside the matrix at `GET /api/release-matrix`, for whatever verifies it | Release owner | The website's deployment record, under "The release matrix" and "Credential rotation" |
| The catalogue's root, targets, snapshot and timestamp keys | Each generation of the signed plugin catalogue | Generated where they are held and never kept in a repository: the pipeline refuses to sign with a key it finds in a tree. The development generation committed in the catalogue repository is a fixture signed with development keys that anybody can generate | `root.json` of a generation, which a host adopts out of band; the bundled package's lock names the root it was verified against, which is the development generation's | Release owner | A new root is signed by the root it replaces, and a host carries verification forward from the root a sync ended on ([Repositories and the catalogue](../plugins/catalogue.md)). A key that reached a commit is rotated by publishing a new root |
| The service admission key | Every relay lease the website signs | The website's Worker secret `RELAY_ADMISSION_SIGNING_KEY` | `RELAY_ISSUER_KEYS` on each relay, and `GET /api/relay/issuer` | Network operator | Pin the new key on the relays, replace the secret with a higher revision, let installed leases expire or be revised, then unpin the old key; the website's deployment record gives the four steps under "Rotating it" |
| An organisation's policy-signing key | The organisation's membership leases, its policy and the links of its key chain | The organisation's own authority object in the website's service, generated there and never leaving it | The chain a host verifies when it enrols with the organisation: the host anchors at the last revision that chain carries and follows later revisions forward from it | The organisation's owner, through `POST /api/account/organisations/:id/policy-authority/rotate` | Rotation signs the successor with the key it retires and destroys the retired private half in the same transaction, so hosts follow the chain forward. The key is in no export. If the authority object's state were lost, its next use would create a new first revision, and each host would enrol with the new chain. A host that never saw a rotation cannot tell a retained retired key's statement from a legitimate one, so a host that must detect a compromised predecessor needs evidence from outside the chain ([Account authority objects](../protocol/README.md#account-authority-objects)) |

Each key is generated, held and pinned on its own, and none can sign what another signs. A host
checks an update only against the channel root of the release it runs, a catalogue only against the
root it adopted, a relay lease only against the issuer keys the relay pins, and an organisation's
lease or policy only against the chain the host enrolled for that organisation. A catalogue root
that named one key for all four of its roles is refused by the pipeline that builds it.

No private key or official credential is written in a repository. `scripts/check-release-secrets.py
scan --tracked` refuses a private key, a raw key seed or an official credential in this repository's
tracked files on every change, the catalogue pipeline refuses to sign with a key inside its own
tree, and the website's `pnpm records:check` refuses a private-key block, a live provider key and
files named for key material in the commits and the bundle it sends.
