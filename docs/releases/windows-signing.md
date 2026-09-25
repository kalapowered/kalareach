# Signing the Windows release

Every Windows executable and PowerShell package KalaReach publishes is signed and timestamped before
it leaves the runner that built it, and a run that cannot prove that of every artefact publishes
nothing at all.

The production signing key lives inside Azure Artifact Signing, in hardware security modules that
will not give it up, and what comes back over the wire is a signature. No copy of the private key
exists in this repository, on a runner, or on any development machine. Nor is there a stored client
secret or certificate credential. The runner authenticates with an OpenID Connect token that GitHub
mints for the repository's `release-signing` environment, and Microsoft Entra exchanges that token
for short-lived Azure access tokens scoped only to signing. Short-lived tokens exist in runner memory
while the job runs, and Azure CLI caches transient session state; for that reason, every run requires
human environment approval and the service principal's role is scoped strictly to the certificate
profile. The separate gate job generates an isolated, non-exportable throwaway key in the runner's
user store that is deleted before that job finishes and never reaches the release environment. Neither
job stores long-lived secrets or private keys in the repository or on development machines.

## What signs

| | |
| --- | --- |
| Tenant | `8f5831f4-a1eb-4e5c-b367-3718b4f21948` |
| Subscription | `00958301-c134-4669-8ed1-2d45d7d4c783` |
| Resource group | `kalareach-signing` |
| Artifact Signing account | `kalareach`, East US, endpoint `https://eus.codesigning.azure.net/` |
| Certificate profile | `kalareach-public-trust`, Public Trust |
| Certificate subject | `CN=Kala Holdings Inc., O=Kala Holdings Inc., L=Newark, S=Delaware, C=US` |
| Application that signs | `kalareach-release-signing`, client `a16af479-e47f-4033-860a-40170217a87f` |
| Role held, and where | Artifact Signing Certificate Profile Signer, on the certificate profile and nowhere above it |

Every identifier in that table is public. None of them is a secret, none of them is stored as one,
and knowing all of them gets nobody a signature: the trust is in the federated subject below, not in
the numbers.

The profile issues a fresh certificate every three days, valid for those three days and no longer.
A signature made under it keeps verifying indefinitely because it carries an RFC 3161 timestamp
proving the certificate was valid when the signature was made. Which is why an executable or
PowerShell script here is never signed without a timestamp, and why the gate refuses one that is.

The certificates chain to the `Microsoft Identity Verification Root Certificate Authority 2020`,
which is included in the Microsoft Trusted Root Certificate Program, so Windows accepts them with
nothing installed. Timestamps come from `Microsoft Public RSA Time Stamping Authority` and chain
through `Microsoft Public RSA Timestamping CA 2020` to the same root. That is the chain observed
when this was written, and Microsoft can change it, so each release's own record is what counts:
`signtool verify /pa /v` prints the whole chain it walked, and `signatures.txt` records the signer
certificate chain root-first and the timestamp certificate subject from the release run.

## What a release carries

`.github/workflows/release-windows.yml` builds on a GitHub-hosted `windows-2025` runner and signs
every executable and PowerShell payload it staged: `kr.exe`, `kr-attach-guard.exe`, `kr-worker.exe`
and `kr-controller.exe`, the PowerShell module scripts (`KalaReach.ShellBridge.psd1`,
`KalaReach.ShellBridge.psm1`, `KrBridge.ps1`, `KrCbor.ps1`, `KrReader.ps1`), and the startup script
`shells/psreadline/startup/kr-profile.ps1`. PowerShell will not load any of those under an all-signed
execution policy unless every one of them carries a signature, so they are signed together or not at
all.

The archive also carries `LICENSE`, the package manifest `shells/psreadline/manifest.json`, and
`shells/psreadline/LICENSE`. These files are data rather than executable code; they are not sent to
SignTool. The archive itself (`.zip`), the gate receipt (`signatures.txt`), and the checksum file
(`SHA256SUMS`) are likewise unsigned data files.

The workflow builds the four explicit `--bin` targets with the MSVC toolchain, verifies against
workspace package metadata that the built list matches what the three crates declare, and copies each
executable by exact name from `target\release` into staging, rather than sweeping up whatever the
directory holds. This prevents obsolete cached binaries from entering the archive.

The archive holds a `signatures.txt` written by the verification step, not by the build. It records
one line per artefact: the SHA-256 of the bytes that were verified, the certificate that signed
them, its thumbprint, when it expires, the timestamping authority that countersigned, and the
certificate chain from the root. It also records the SHA-256 digests of the data files. Beside the
archive is a `SHA256SUMS` covering the archive itself.

Both records end every line in a line feed alone, although the runner that writes them is Windows.
A carriage return would break the sum on macOS: `shasum` and the `sha256sum` macOS ships read it as
part of the file name and report the archive missing, while GNU `sha256sum` drops it and passes.
Before anything is uploaded, the release job holds both records to line feeds and runs
`sha256sum -c` over the archive (`scripts/check-release-sums.sh`). The gate job first drives that
check with records made to fail, a carriage return among them.

Checking the archive takes one command on Linux or macOS, in the directory that holds both files:

```bash
sha256sum -c SHA256SUMS        # or: shasum -a 256 -c SHA256SUMS
```

Checking a signature after unpacking takes two commands:

```powershell
Get-AuthenticodeSignature .\kr.exe | Format-List
signtool verify /pa /v .\kr.exe
```

The first prints `Valid` and names the timestamper. The second walks the chain against the policy
Windows applies when a person opens the file.

## How a release is signed

A release is one commit's output, and the tag is what says which commit:

```bash
commit=$(git rev-parse HEAD)
version=$(cargo metadata --format-version 1 --no-deps --locked \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "kr-cli"))')
git tag "host/v${version}+${commit:0:12}" "$commit"
git push origin "host/v${version}+${commit:0:12}"
```

The version comes out of the workspace rather than being typed, and the workflow reads it again on
the runner and refuses a tag that names either the version or the commit wrongly. That refusal
happens before anything is built.

Pushing the tag starts the run. The initial `gate` job settles the exact 40-character commit SHA
from `github.sha` (or `inputs.ref`), records it in the job summary and outputs, and the `release`
job checks out that exact SHA and verifies it matches. The release job waits, because it declares the
`release-signing` environment and that environment has a required reviewer, so a person approves every
signature this project ever makes. Approve it and the run builds, signs, verifies, packs, and
publishes a release carrying the archive and its sum.

To sign a commit without releasing it, start the workflow by hand and give it a ref. The gate job
settles that commit and records it in the Step Summary. The reviewer in the `release-signing`
environment must check that exact commit SHA in the summary before approving. A run started that way
signs and keeps the archive as a workflow artefact; it creates no release, because the step that
publishes one runs on a tag push and on nothing else.

One tag is one run at a time. A second run for a tag already being released waits for the first
rather than running beside it, and the run under way is never cancelled for the one waiting. When the
waiting run's turn comes it finds whatever the run before it made, and refuses to go on if that is a
release or a draft. `docs/releases/packages.md` describes the same arrangement at more length; this
workflow follows it.

## The refusal

`scripts/verify-windows-signatures.ps1` runs between signing and everything that could publish. It
takes every file under the staging directory, at any depth, runs `signtool verify /pa /v` over it,
prints the whole of that output into the run's log, and then holds it to four conditions. A file that
fails any of them is named in the log with the condition it failed, and the job stops.

**unsigned.** The file carries no signature at all. Usually this means a file reached the staging
directory after the signing step ran, or the signing step skipped it.

**untrusted.** The signature exists but the default Authenticode policy will not accept it. The
message carries the status and the reason. A chain ending in a root nobody trusts reads this way, and
so does a file that was altered after it was signed, because from the policy's side those are the same
answer: this signature does not hold for this file.

**wrong-publisher.** The signature is valid and trusted, but made by a publisher other than
`CN=Kala Holdings Inc., O=Kala Holdings Inc., L=Newark, S=Delaware, C=US`. A trusted signature from
another party has no business in this release.

**untimestamped.** The file is signed and the signature is good, but nothing countersigned it. The
certificate expires in three days and the signature dies with it. A file can be refused for this and
for being untrusted or having the wrong publisher at once, and all are reported.

An empty staging directory is refused as well. A build that produced nothing must not read as a run
that verified everything it built.

What the gate accepts, it records, and the step that builds the archive works only from that record:
it hashes each file after copying it into the payload, holds it to the digest the gate wrote down,
and stops if the number of files copied does not match the number the gate accepted. Unsigned data
files are copied through an explicit inventory and added to the record. The finished archive is
opened, and every entry is hashed and verified against the inventory before anything can upload it.
So an artefact that did not pass through the gate has no route into an archive, and a file that
changed between steps stops the run.

`scripts/check-windows-signature-gate.ps1` is the gate's own test. It verifies an empty directory
refusal, requires positive controls for signed executables and PowerShell files, tests an unsigned
executable, tests an untrusted signature, tests wrong-publisher refusal, tests untimestamped refusal,
tests an altered file starting from an accepted signed executable, and tests a signed PowerShell
module. It runs in its own job at the start of every release run, before anything is built and on a
runner that cannot reach the signing service at all. A gate that has stopped refusing stops the
release.

## The identity, and what the operator set up once

Four things exist outside this repository. None of them is a secret, and none of them was created by
a build.

1. An application registration, `kalareach-release-signing`, with no client secret and no certificate
   credential. It has never had either.
2. A federated credential on that application, `github-release-signing`: issuer
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, subject
   `repo:kalapowered@290383971/kalareach@1371146076:environment:release-signing`. GitHub puts the
   owner's and the repository's numeric IDs in the subject beside their names, and those IDs are
   never given to anything else.
3. The GitHub environment `release-signing`, with a required reviewer and deployment branch and tag
   policies allowing `main` and `host/v*`.
4. The Artifact Signing Certificate Profile Signer role, granted to that application's service
   principal at the scope of the certificate profile and nowhere wider. It can sign with
   `kalareach-public-trust`. It cannot read the account, create a profile, or touch anything else in
   the subscription.

Together those mean a signature is possible only from a workflow run in this repository, in the
`release-signing` environment, which a person approved. A fork cannot get one. A stolen copy of the
repository cannot get one, because there is no private key or secret in the repository to steal.

Environment protection applies to the `release` job referencing the `release-signing` environment,
requiring human reviewer approval and enforcing deployment branch and tag policies (`main` or `host/v*`)
on the workflow run's ref before that job can execute or mint environment-bound OIDC tokens. The separate
`gate` job has no environment restriction and runs first on an isolated runner without signing access.
When the workflow is triggered by `workflow_dispatch`, the deployment branch policy evaluates the branch
or tag from which the workflow was dispatched, but `inputs.ref` allows checking out an arbitrary commit
or branch for the build. The environment protection ensures that a human reviewer must approve the
`release` job, but GitHub environment policies do not constrain `inputs.ref`. For that reason, the `gate`
job resolves the full 40-character commit SHA to job outputs and the GitHub Step Summary; the `release`
job asserts that its checkout matches `needs.gate.outputs.commit`; and the human reviewer in
`release-signing` must inspect that exact commit SHA in the step summary before approving deployment.

The three identifiers the login needs are repository variables, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`
and `AZURE_SUBSCRIPTION_ID`. They are variables and not secrets on purpose: GitHub prints a variable
on request, which is exactly the test of whether something needed to be a secret.

## When the subject stops matching

The federated subject names the environment, not the branch, so changing which branches or tags may
release does not break it. Change the environment's name, or move the signing job to a different
environment or a different repository, and it breaks immediately: Entra refuses the exchange and
`azure/login` fails with the subject it was offered.

The fix is to make the credential's subject match again. Either put the job back in the
`release-signing` environment, or add a federated credential whose subject is the new one. The
subject a run presents is
`repo:<owner>@<owner id>/<repository>@<repository id>:environment:<environment>`, and the failure
names what it presented, so the value to add is in the log. Nothing is regenerated and nothing is
copied anywhere: a federated credential is a statement about which token to trust, and editing it is
editing that statement.

Renaming the repository or moving it to another owner changes the subject too, because it carries
the names beside the IDs, so either one needs the credential's subject updated. What the IDs add is
that a repository that later takes this name, under this owner or any other, presents different IDs
and cannot sign. GitHub's
[immutable subject claims](https://docs.github.com/en/actions/reference/security/oidc#immutable-subject-claims)
reference describes the format.

## Rotation and recovery

The leaf certificates rotate themselves, every three days, with no human involved and nothing to do
in this repository. Artefacts already signed keep verifying because they are timestamped.

Responsibility is divided across three roles:
- The Azure subscription owner or User Access Administrator / Role Based Access Control Administrator
  owns the Artifact Signing account `kalareach`, the certificate profile `kalareach-public-trust`, and
  the `Artifact Signing Certificate Profile Signer` role assignment for the service principal. (A resource
  group contributor cannot grant or revoke RBAC assignments).
- The Entra application administrator owns the application registration `kalareach-release-signing`
  and its federated identity credentials.
- The GitHub repository administrator owns the `release-signing` environment, its required reviewers,
  deployment policies, and repository variables.

What a person rotates is the profile and the identity behind it, in three separate cases:

**The certificate profile.** The Azure subscription owner creates a new profile on the `kalareach`
account, grants the signing application the Certificate Profile Signer role on it, and updates
`certificate-profile-name` in the workflow. Artefacts signed under the old profile keep verifying;
their timestamps say when they were signed and the chain is unchanged. Retire the old profile after
the change has shipped, not before.

**The identity validation.** A Public Trust profile depends on a validated organisation identity.
Microsoft re-verifies it periodically and a lapsed validation stops new certificates being issued,
which shows up as a signing failure and not as a bad signature. Renewing it is an Azure portal task
against the same account, owned by the Azure subscription holder.

**The federated credential.** The Entra application administrator deletes the federated credential
and adds another. If the environment's protection is ever compromised or changed in a way that
widens who can approve a run, follow the incident response steps below.

**Incident response and federation recovery.** If environment protection is weakened, an unauthorized
run is suspected, or signing access must be revoked immediately:
1. Suspension of federation and signing access:
   - The Entra application administrator deletes the federated credential `github-release-signing` on
     application `kalareach-release-signing` to cut off Entra ID token exchanges.
   - The Azure subscription owner or User Access Administrator removes the `Artifact Signing Certificate
     Profile Signer` role assignment on the certificate profile. Role assignment changes must propagate
     across Azure Resource Manager and service endpoint caches; never assume instantaneous revocation.
   - Any Azure access token already minted prior to suspension remains valid until its cryptographic
     expiration timestamp; deleting the application or role assignment does not instantly revoke cached
     access tokens at Azure service endpoints.
2. Terminate and confirm cancellation of active jobs:
   - The GitHub repository administrator cancels all in-progress and queued workflow runs in the
     repository (`gh run list` / `gh run cancel`) and verifies via `gh run list` that all runs have
     reached a confirmed terminated status (`completed`, `cancelled`).
3. Repair environment policy:
   - The GitHub repository administrator audits and restores required reviewers and deployment branch and
     tag policies on the `release-signing` environment.
4. Investigate signatures and revoke compromised certificates or releases:
   - Review the Artifact Signing service's signing history in the Azure portal (or diagnostic logs in
     Log Analytics if configured) for data-plane signing requests during the incident window.
   - Review Azure Activity Logs for control-plane role, profile, or account modifications.
   - Audit GitHub Actions workflow run histories and release assets.
   - If unauthorized signatures were produced:
     - The Azure subscription owner immediately retires the compromised certificate profile (revoking
       the profile or requesting certificate revocation from Microsoft PKI Services) and provisions a
       replacement certificate profile on the account once identity validation is confirmed.
     - The GitHub repository administrator deletes any compromised release draft or published release,
       purges published artefacts from distribution, and notifies downstream consumers.
5. Controlled restoration via identity and subject rotation (Required):
   - A GitHub Actions OIDC token assertion (`iss`, `aud`, `sub`) is bound to the repository and
     environment subject, not the Azure Client ID. Restoring under the same subject or reusing the old
     application would allow an attacker holding an unexpired stolen OIDC assertion (valid up to 60 minutes)
     or unexpired Azure access token to sign again.
   - Therefore, safe restoration requires rotating both the GitHub environment subject and the Azure
     application identity:
     1. The GitHub repository administrator creates a new, distinct GitHub environment (for example
        `release-signing-v2`) with fresh required reviewers and deployment branch/tag policies, and
        deletes or archives the compromised environment `release-signing`.
     2. The Entra application administrator creates a new application registration and service principal,
        configured with a federated credential scoped strictly to the new environment subject
        (`repo:kalapowered@290383971/kalareach@1371146076:environment:release-signing-v2`). The old
        application registration and service principal are deleted. Because the new federated
        credential requires the new subject, any stolen OIDC token minted under the old environment
        subject is rejected by Entra ID.
     3. The Azure subscription owner or User Access Administrator grants `Artifact Signing Certificate
        Profile Signer` to the *new* service principal at the certificate profile scope.
     4. The GitHub repository administrator updates the `AZURE_CLIENT_ID` repository variable to the new
        application ID, and updates the workflow `environment` name to the new environment.
     5. The operator completes explicit denial verification before initiating production releases under
        the new environment:
        - Verify that OIDC token exchange requests using the old environment subject are rejected by
          both the old and replacement application identities.
        - Verify that previously issued Azure access tokens are rejected at the Artifact Signing service
          endpoint. (An OIDC exchange failure alone does not prove that an existing Azure token cannot sign;
          if data-plane denial verification remains incomplete, keep production releases suspended).

Recovery, if the signing account or the profile is lost: the Azure subscription owner creates the
account and a Public Trust profile in the same region, completes identity validation, grants the role
at the new profile's scope, and updates the endpoint, account name, and profile name in the workflow.
Published artefacts are unaffected. Identity validation takes days, so a profile is retired only after
its replacement has signed something.

## What is never done

Never create a client secret for `kalareach-release-signing`. Never add a certificate credential to
the Entra application. Never export a signing key from Azure Artifact Signing. Never put a production
signing credential on a build machine, a developer machine or the Windows test machine. Public signer
and timestamp certificates necessarily accompany signed artefacts, but the production private key
never leaves the Azure service.

If a change seems to need one of those, the change is wrong. Federation exists so that the answer to
"where do we keep the signing secret" can be that there is not one.
