# Independently signed builds

An independently signed build is a build of the companion app that somebody other than the project
signs and distributes: an Android package signed with the builder's own key, for example. It is the
same source and a different signer, and it holds no credential of the official build.

## The rule

Native push credentials belong only to the corresponding official build. The official apps use
KalaReach's Firebase project. The push gateway sends through it with the project's own credentials,
and Firebase forwards iOS messages through APNs with the APNs key registered in that project. An
independently signed build uses its own Firebase project, its own APNs credentials and a gateway it is
configured for.

## What a builder supplies

- **A Firebase project of its own.** Its configuration file goes into the build as any Firebase app's
  does: `google-services.json` for Android and `GoogleService-Info.plist` for iOS.
- **An APNs authentication key of its own**, uploaded to that Firebase project. Firebase uses it to
  reach iOS devices, so the key is the project's and never the app's.
- **A gateway origin.** The app is configured with the origin of the gateway it talks to, an
  `https://host[:port]` origin. Each request is bound to the exact origin it was addressed to, so a
  signature made for one deployment cannot be replayed against another, and a gateway refuses a
  request authorised for somebody else's origin.

The official gateway sends through the official Firebase project, so it reaches the apps registered
in that project and no others. A host that is self-hosted forwards encrypted envelopes through the
official gateway without a KalaReach account, and an independently signed app receives through the
gateway of its own configuration.

## What the repository holds

No official credential: no Firebase configuration file, no APNs key, no service-account document, no
provisioning profile and no key store. `scripts/check-release-secrets.py` refuses each of them, by
what it contains and by what it is called (`google-services.json`, `GoogleService-Info.plist`,
`AuthKey_*.p8`, a PKCS #12 or Java key store), in the tracked files of a checkout, in a release tree
and in a release archive. `release-checks.yml` runs it over the tracked files, and the jobs that
build a release tree run it over the tree and the archive, after putting it through a planted example
of every kind it refuses.

A package built from the source is read as raw bytes by the same scan when it is given one (`.apk`,
`.aab` and `.ipa` are not opened): a credential written into it in the clear is found, and one inside
its compressed entries is not. The builder's own configuration file is therefore a file of the
builder's checkout and never of this repository.
