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
- **A gateway origin.** The build input `KR_PUSH_GATEWAY_ORIGIN` names the push gateway the app
  registers with. The value is an origin in its canonical form: `https://`, a host in lower-case
  ASCII (an international name in its `xn--` spelling), a port only when it is not 443, and nothing
  after that, so no path and no trailing slash. The whole text is at most 128 bytes. An Android
  build takes it from the environment, beside `KR_GOOGLE_SERVICES_JSON`. An iOS build takes it from
  `apps/companion/src-tauri/gen/apple/Local.xcconfig`, beside `KR_GOOGLE_SERVICE_INFO`, because
  `tauri ios build` does not hand its environment to the Xcode build; `//` starts a comment in that
  file, so the line reads `KR_PUSH_GATEWAY_ORIGIN = https:/$()/push.builder.example`. A debug
  simulator build (`tauri ios build --debug --target aarch64-sim`) with that line printed the
  warning described below; a device archive takes the same route and has not been built with the
  line. A build given no value uses the official gateway, `https://reach.kala.to`, and sends the
  same requests as the official build. A value that is not such an origin stops the build. A build
  given one prints `this build registers with the push gateway at <origin>` among its cargo
  warnings, which is the sign that the input reached the build. The app takes its gateway from what
  the build accepted, so the warning and the app cannot name different gateways. A
  Cargo configuration file's `[env]` table reaches the build as the environment does. A debug build
  also reads an origin from a device test's file in its data directory; a release build has no
  other way to change the origin. The input moves only the push gateway: the account the app signs
  in to and its other services stay where they are. Each request is bound to the exact origin it
  was addressed to, so a signature made for one deployment cannot be replayed against another, and
  a gateway refuses a request authorised for somebody else's origin. The gateway compares the
  origin as exact text, so its setting `PUSH_GATEWAY_ORIGIN` is the same text as the build input.

The official build takes no gateway of its own. The store scripts start it with
`KR_OFFICIAL_BUILD=1` and without `KR_PUSH_GATEWAY_ORIGIN`, and a build marked that way stops when
the gateway input reaches it by any route, a Cargo configuration file's `[env]` table included.
The store bundle check then reads the gateway back from the library in the package and refuses a
bundle whose library names one. A builder of an independently signed app does not set the mark.

The official gateway sends through the official Firebase project, so it reaches the apps registered
in that project and no others. A host that is self-hosted forwards encrypted envelopes through the
official gateway without a KalaReach account.

## What a host does with a gateway

A host delivers notifications only through the official gateway. The origin a credential names is
where the host sends every notification, status question and renewal under it, so a paired device
does not get to choose that address: a host refuses, when a device registers, a credential that
names another gateway. An independently signed app that registers with its own gateway is therefore
reached by no host.

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
