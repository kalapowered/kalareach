# Signing the Windows release

Every Windows artefact KalaReach publishes is signed and timestamped before it leaves the runner
that built it, and a run that cannot prove that of every artefact publishes nothing at all.

The signature comes from Azure Artifact Signing. There is no private key in this repository, in any
build, or on any machine anyone here owns. The key lives inside the service, in hardware that will
not give it up, and what comes back over the wire is a signature. There is no client secret either:
the runner proves who it is with a token GitHub mints for one environment of one repository, and
Microsoft Entra will exchange that token and nothing else. So there is nothing to leak, nothing to
rotate in a hurry, and nothing an attacker could take from a checkout, a log, or a laptop.

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

The profile issues a fresh certificate every three days, and each one is valid for those three days
and no longer. That sounds alarming until you see what it is for. A stolen certificate is worth
almost nothing if it expires on Thursday, and a signature made under it keeps verifying for as long
as the timestamp says the certificate was valid when the signature was made. Which is why a Windows
artefact here is never signed without a timestamp, and why the gate refuses one that is.

The certificates chain to a Microsoft root that ships in the Windows trusted root program, so
Windows accepts them with nothing installed. `signtool verify /pa /v` prints the whole chain it
walked, and that print is the authority on what the chain was on the day the artefact was signed.

## What a release carries

`.github/workflows/release-windows.yml` builds on a GitHub-hosted `windows-2025` runner and signs
every file it staged: `kr.exe`, `kr-attach-guard.exe`, `kr-worker.exe` and `kr-controller.exe`, and
the PowerShell package's module, which is a manifest, a module and the three scripts the module
dot-sources. PowerShell will not load any of those under an all-signed execution policy unless every
one of them carries a signature, so they are signed together or not at all.

Nothing in the staging directory is exempt. The signing step is pointed at the directory rather than
at a list of names, with no filter on it, so a binary added to one of those crates is signed because
it is there. The four executables above are also checked by name, so a build that quietly produced
none of them stops instead of publishing an empty archive.

The archive holds a `signatures.txt` written by the verification step, not by the build. It records
one line per artefact: the SHA-256 of the bytes that were verified, the certificate that signed
them, its thumbprint, when it expires, and the timestamping authority that countersigned. Beside the
archive is a `SHA256SUMS` covering the archive itself.

Checking a downloaded copy takes two commands:

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

Pushing the tag starts the run. It waits, because the job that signs declares the `release-signing`
environment and that environment has a required reviewer, so a person approves every signature this
project ever makes. Approve it and the run builds, signs, verifies, packs, and publishes a release
carrying the archive and its sum.

To sign a commit without releasing it, start the workflow by hand and give it a ref. A run started
that way signs and keeps the archive as a workflow artefact; it creates no release, because the step
that publishes one runs on a tag push and on nothing else.

One tag is one run at a time. A second run for a tag already being released waits for the first
rather than running beside it, and the run under way is never cancelled for the one waiting. When
the waiting run's turn comes it finds whatever the run before it made, and refuses to go on if that
is a release or a draft. `docs/releases/packages.md` describes the same arrangement at more length;
this workflow follows it.

## The refusal

`scripts/verify-windows-signatures.ps1` runs between signing and everything that could publish. It
takes every file under the staging directory, at any depth, runs `signtool verify /pa /v` over it,
prints the whole of that output into the run's log, and then holds it to three conditions. A file
that fails any of them is named in the log with the condition it failed, and the job stops.

**unsigned.** The file carries no signature at all. Usually this means a file reached the staging
directory after the signing step ran, or the signing step skipped it.

**untrusted.** The signature exists but the default Authenticode policy will not accept it. The
message carries the status and the reason. A chain ending in a root nobody trusts reads this way,
and so does a file that was altered after it was signed, because from the policy's side those are
the same answer: this signature does not hold for this file.

**untimestamped.** The file is signed and the signature is good, but nothing countersigned it. The
certificate expires in three days and the signature dies with it. A file can be refused for this and
for being untrusted at once, and both are reported.

An empty staging directory is refused as well. A build that produced nothing must not read as a run
that verified everything it built.

What the gate accepts, it records, and the step that builds the archive works only from that record:
it hashes each file again, holds it to the digest the gate wrote down, and stops if the number of
files it copied does not match the number the gate accepted. So an artefact that did not pass
through the gate has no route into an archive, and a file that changed between the two steps stops
the run.

`scripts/check-windows-signature-gate.ps1` is the gate's own test. It builds an unsigned executable,
one signed by a throwaway certificate it makes and deletes, one signed without a timestamp, one
altered after signing, and a signed PowerShell module, and it fails if the gate lets any of them
through. It runs in its own job at the start of every release run, before anything is built and on a
runner that cannot reach the signing service at all. A gate that has stopped refusing stops the
release.

## The identity, and what the operator set up once

Four things exist outside this repository. None of them is a secret, and none of them was created by
a build.

1. An application registration, `kalareach-release-signing`, with no client secret and no
   certificate. It has never had either.
2. A federated credential on that application, `github-release-signing`: issuer
   `https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, subject
   `repo:kalapowered/kalareach:environment:release-signing`.
3. The GitHub environment `release-signing`, with a required reviewer and deployment branch and tag
   policies allowing `main` and `host/v*`.
4. The Artifact Signing Certificate Profile Signer role, granted to that application's service
   principal at the scope of the certificate profile and nowhere wider. It can sign with
   `kalareach-public-trust`. It cannot read the account, create a profile, or touch anything else in
   the subscription.

Together those mean a signature is possible only from a workflow run in this repository, in the
`release-signing` environment, which a person approved. A fork cannot get one. A branch outside the
environment's policy cannot get one. A stolen copy of the repository cannot get one, because there
is nothing in the repository to steal.

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
subject a run presents is `repo:<owner>/<repository>:environment:<environment>`, and the failure
names what it presented, so the value to add is in the log. Nothing is regenerated and nothing is
copied anywhere: a federated credential is a statement about which token to trust, and editing it is
editing that statement.

The same applies to renaming the repository or moving it to another organisation. The subject
carries the owner and the name.

## Rotation and recovery

The leaf certificates rotate themselves, every three days, with no human involved and nothing to do
in this repository. Artefacts already signed keep verifying because they are timestamped.

What a person rotates is the profile and the identity behind it, and there are three separate cases.

**The certificate profile.** Create a new profile on the `kalareach` account, grant the signing
application the Certificate Profile Signer role on it, and change `certificate-profile-name` in the
workflow. Artefacts signed under the old profile keep verifying; their timestamps say when they were
signed and the chain is unchanged. Retire the old profile after the change has shipped, not before.

**The identity validation.** A Public Trust profile depends on a validated organisation identity.
Microsoft re-verifies it periodically and a lapsed validation stops new certificates being issued,
which shows up as a signing failure and not as a bad signature. Renewing it is an Azure portal task
against the same account.

**The federated credential.** Delete it and add another. There is no key to roll, so this is
instantaneous and costs nothing. Do it if the environment's protection is ever changed in a way that
widens who can approve a run.

The owner of all three is whoever holds the Azure subscription that carries the `kalareach-signing`
resource group. That is the only party who can rotate them, and the only party who needs to.

Recovery, if the signing account or the profile is lost: create the account and a Public Trust
profile in the same region, complete identity validation, grant the role at the new profile's scope,
and change the endpoint, account name and profile name in the workflow. Nothing has to be restored
from a backup, because nothing about the signing identity is held here to back up. Published
artefacts are unaffected. The one thing that cannot be recovered quickly is identity validation,
which takes days, so a profile is retired only after its replacement has signed something.

## What is never done

Never create a client secret for `kalareach-release-signing`. Never add a certificate to it. Never
export a certificate or a key from the signing account. Never put a signing credential on a build
machine, a developer machine or the Windows test machine.

If a change seems to need one of those, the change is wrong. Federation exists so that the answer to
"where do we keep the signing secret" can be that there is not one.
