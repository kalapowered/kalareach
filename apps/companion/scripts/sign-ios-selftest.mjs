#!/usr/bin/env node
// Holds the signer to the answers it must give.
//
// What it decides is whether a bundle is signed inside out, with the entitlements its source file
// asks for and a profile that allows them, and whether a signature that is wrong in one way is told
// apart from one that holds. A real certificate and a real profile are not in the repository, so the
// signing here is ad hoc, on a bundle built for the purpose from a program compiled on the spot, and
// the profile is one written for the purpose; a real profile is read only when `KR_TEST_PROFILE`
// names one, and the case is reported as not run otherwise. The signing tools are `codesign`,
// `plutil` and `clang`, which only macOS with its command line tools has: where they are missing the
// cases that need them are not run, and the exit status says so.
import { spawnSync } from 'node:child_process'
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  entitlementsFor,
  nestedCode,
  problemsInDescription,
  problemsOfCertificate,
  problemsInSignatures,
  problemsOfFit,
  readProfile,
  signAll,
  signingPlan
} from './sign-ios.mjs'

const work = mkdtempSync(join(tmpdir(), 'kr-sign-ios-'))
let failures = 0
let notRun = 0

function held(what, expected, answer) {
  const same = JSON.stringify(answer) === JSON.stringify(expected)
  if (same) {
    console.log(`ok    ${what}`)
    return
  }
  failures += 1
  console.error(`FAIL  ${what}\n        expected: ${JSON.stringify(expected)}\n        answered: ${JSON.stringify(answer)}`)
}

function skipped(what, why) {
  notRun += 1
  console.log(`NOT RUN ${what}: ${why}`)
}

const TEAM = 'ABCDE12345'
const profile = (entitlements, over = {}) => ({
  path: join(work, 'profile.mobileprovision'),
  name: 'Fixture',
  uuid: 'u',
  team: TEAM,
  expires: new Date('2099-01-01'),
  devices: ['00008140-0000'],
  certificates: ['A'.repeat(40)],
  entitlements: {
    'application-identifier': `${TEAM}.to.example.app`,
    'com.apple.developer.team-identifier': TEAM,
    'get-task-allow': true,
    'keychain-access-groups': [`${TEAM}.*`, 'com.apple.token'],
    'aps-environment': 'development',
    'com.apple.developer.associated-domains': '*',
    ...entitlements
  },
  ...over
})

// -- the entitlements a bundle is signed with ---------------------------------------------------

const source = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>aps-environment</key><string>development</string>
<key>keychain-access-groups</key><array><string>$(AppIdentifierPrefix)to.example.app</string><string>$(AppIdentifierPrefix)to.example.app.shared</string></array>
</dict></plist>`

function entitlementsOfFixture() {
  const probe = spawnSync('plutil', ['-help'])
  return probe.error ? null : entitlementsFor({ source, team: TEAM, bundleIdentifier: 'to.example.app', profile: profile({}) })
}

const wanted = entitlementsOfFixture()
if (wanted === null) {
  skipped('the entitlements a bundle is signed with', 'plutil is missing')
} else {
  held('the team prefix replaces the placeholder in every group, in order', [`${TEAM}.to.example.app`, `${TEAM}.to.example.app.shared`], wanted['keychain-access-groups'])
  held('the application identifier, the team and the debugger entitlement are added', [`${TEAM}.to.example.app`, TEAM, true], [
    wanted['application-identifier'],
    wanted['com.apple.developer.team-identifier'],
    wanted['get-task-allow']
  ])
  held('a profile that does not allow the debugger leaves it out', false, 'get-task-allow' in entitlementsFor({ source, team: TEAM, bundleIdentifier: 'to.example.app', profile: profile({ 'get-task-allow': false }) }))
  held('with no source file only the three it adds are there', ['application-identifier', 'com.apple.developer.team-identifier', 'get-task-allow'].sort(), Object.keys(entitlementsFor({ source: null, team: TEAM, bundleIdentifier: 'to.example.app', profile: profile({}) })).sort())
}

// -- what a profile allows ----------------------------------------------------------------------

const fits = (entitlements, over = {}) => problemsOfFit(entitlements, profile(over))
held('groups under the profile prefix, the domains and the push environment fit', [], fits({
  'application-identifier': `${TEAM}.to.example.app`,
  'keychain-access-groups': [`${TEAM}.to.example.app`, `${TEAM}.to.example.app.shared`],
  'aps-environment': 'development',
  'com.apple.developer.associated-domains': ['applinks:example.com'],
  'get-task-allow': true
}))
held('a keychain group under another team is refused', ['the profile allows no keychain group OTHER12345.to.example.app'], fits({ 'keychain-access-groups': ['OTHER12345.to.example.app'] }))
held('an entitlement the profile does not list is refused', ['the profile allows no com.apple.developer.healthkit'], fits({ 'com.apple.developer.healthkit': true }))
held('a different push environment is refused', ['aps-environment is "production" and the profile says "development"'], fits({ 'aps-environment': 'production' }))
held('a domain the profile does not name is refused when it names some', ['the profile does not allow com.apple.developer.associated-domains applinks:b.example'], fits({ 'com.apple.developer.associated-domains': ['applinks:b.example'] }, { 'com.apple.developer.associated-domains': ['applinks:a.example'] }))
held('a profile that does not allow the debugger refuses a build that asks for it', ['get-task-allow is true and the profile says false'], fits({ 'get-task-allow': true }, { 'get-task-allow': false }))

// -- what a signature says ----------------------------------------------------------------------

const description = (authorities, team = TEAM, identifier = 'to.example.app') =>
  `Identifier=${identifier}\nTeamIdentifier=${team}\n${authorities.map((each) => `Authority=${each}`).join('\n')}\n`
const chain = ['Apple Development: Someone (X1)', 'Apple Worldwide Developer Relations Certification Authority', 'Apple Root CA']
held('a development certificate under the team and Apple’s root passes', [], problemsInDescription(description(chain), { identifier: 'to.example.app', team: TEAM }))
held('another team is told', [`its team is OTHER12345, expected ${TEAM}`], problemsInDescription(description(chain, 'OTHER12345'), { identifier: 'to.example.app', team: TEAM }))
held('another identifier is told', [`its identifier is to.example.other, expected to.example.app`], problemsInDescription(description(chain, TEAM, 'to.example.other'), { identifier: 'to.example.app', team: TEAM }))
held('a chain of two is told', ['its chain has 2 certificates, expected three'], problemsInDescription(description(chain.slice(0, 2)), { identifier: 'to.example.app', team: TEAM }))
held('a distribution certificate is told', [`its chain is Apple Distribution: X > ${chain[1]} > ${chain[2]}, expected an Apple Development certificate under Apple's root`], problemsInDescription(description(['Apple Distribution: X', chain[1], chain[2]]), { identifier: 'to.example.app', team: TEAM }))

// -- the certificate a bundle is signed with ------------------------------------------------------

const WANTED = 'A'.repeat(40)
const OTHER = 'B'.repeat(40)
const later = new Date('2099-01-01')
const certificate = (sha1, notAfter = later) => ({ sha1, notAfter })
held('the wanted certificate, listed by the profile and valid, passes', [], problemsOfCertificate(certificate(WANTED), { identity: WANTED, profile: profile({}) }))
held('no certificate at all is told', ['it is signed with no certificate'], problemsOfCertificate(null, { identity: WANTED, profile: profile({}) }))
held('another certificate than the one named is told', [`it is signed with ${OTHER}, not with ${WANTED}`, `the profile Fixture does not list the certificate ${OTHER}, so iOS would refuse to install it`], problemsOfCertificate(certificate(OTHER), { identity: WANTED, profile: profile({}) }))
held('a certificate the profile does not list is told even when it is the one named', [`the profile Fixture does not list the certificate ${WANTED}, so iOS would refuse to install it`], problemsOfCertificate(certificate(WANTED), { identity: WANTED, profile: profile({}, { certificates: [OTHER] }) }))
held('a library, which no profile covers, is held to the named certificate only', [], problemsOfCertificate(certificate(WANTED), { identity: WANTED, profile: null }))
held('an unreadable end of validity is told, not passed', [`the end of the certificate ${WANTED}'s validity cannot be read`], problemsOfCertificate({ sha1: WANTED, notAfter: null }, { identity: WANTED, profile: profile({}) }))
held('an end of validity that does not parse is told, not passed', [`the end of the certificate ${WANTED}'s validity cannot be read`], problemsOfCertificate({ sha1: WANTED, notAfter: new Date('not a date') }, { identity: WANTED, profile: profile({}) }))
held('an expired certificate is told', [`the certificate ${WANTED} has expired`], problemsOfCertificate(certificate(WANTED, new Date('2000-01-01')), { identity: WANTED, profile: profile({}) }))

// -- the order, and a real round trip with an ad hoc signature ----------------------------------

const clang = spawnSync('xcrun', ['--find', 'clang'], { encoding: 'utf8' })
const codesignHere = spawnSync('codesign', ['--help'], { encoding: 'utf8' })
if (clang.status !== 0 || codesignHere.error) {
  skipped('the order of signing and an ad hoc round trip', 'clang or codesign is missing')
} else {
  const program = join(work, 'main.c')
  writeFileSync(program, 'int main(void) { return 0; }\n')
  const binary = join(work, 'fixture')
  const compiled = spawnSync('xcrun', ['clang', '-arch', 'arm64', '-o', binary, program])
  if (compiled.status !== 0) {
    skipped('the order of signing and an ad hoc round trip', 'a program could not be compiled')
  } else {
    const info = (identifier, executable) =>
      `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${identifier}</string><key>CFBundleExecutable</key><string>${executable}</string></dict></plist>`
    function build(name) {
      const app = join(work, `${name}.app`)
      mkdirSync(join(app, 'Frameworks', 'Lib.framework'), { recursive: true })
      mkdirSync(join(app, 'PlugIns', 'Ext.appex'), { recursive: true })
      mkdirSync(join(app, 'Frameworks', 'Deep.framework', 'Frameworks', 'Inner.framework'), { recursive: true })
      writeFileSync(join(app, 'Info.plist'), info('to.example.app', 'App'))
      copyFileSync(binary, join(app, 'App'))
      writeFileSync(join(app, 'Frameworks', 'Lib.framework', 'Info.plist'), info('to.example.lib', 'Lib'))
      copyFileSync(binary, join(app, 'Frameworks', 'Lib.framework', 'Lib'))
      writeFileSync(join(app, 'Frameworks', 'Deep.framework', 'Info.plist'), info('to.example.deep', 'Deep'))
      copyFileSync(binary, join(app, 'Frameworks', 'Deep.framework', 'Deep'))
      writeFileSync(join(app, 'Frameworks', 'Deep.framework', 'Frameworks', 'Inner.framework', 'Info.plist'), info('to.example.inner', 'Inner'))
      copyFileSync(binary, join(app, 'Frameworks', 'Deep.framework', 'Frameworks', 'Inner.framework', 'Inner'))
      writeFileSync(join(app, 'PlugIns', 'Ext.appex', 'Info.plist'), info('to.example.app.ext', 'Ext'))
      copyFileSync(binary, join(app, 'PlugIns', 'Ext.appex', 'Ext'))
      return app
    }
    const app = build('order')
    const relatives = nestedCode(app).map((path) => path.slice(app.length + 1))
    held(
      'nested code is listed deepest first, frameworks before the extensions that follow them',
      ['Frameworks/Deep.framework/Frameworks/Inner.framework', 'Frameworks/Deep.framework', 'Frameworks/Lib.framework', 'PlugIns/Ext.appex'],
      relatives
    )
    let refused = ''
    try {
      signingPlan(app, {})
    } catch (failure) {
      refused = failure.message
    }
    held('an extension with no profile is refused, not signed as a library', 'PlugIns/Ext.appex has no profile to be signed with', refused)
    const plan = signingPlan(app, { 'PlugIns/Ext.appex': { profile: profile({}), entitlements: {} }, '': { profile: profile({}), entitlements: {} } })
    held('the bundle itself is signed last', '', plan[plan.length - 1].relative)

    // A real round trip: sign, then change one thing at a time.
    const profileFile = join(work, 'profile.mobileprovision')
    writeFileSync(profileFile, 'a profile')
    const appProfile = profile({})
    const extensionProfile = profile({ 'application-identifier': `${TEAM}.to.example.app.ext` })
    const entitlements = (identifier) => ({
      'application-identifier': `${TEAM}.${identifier}`,
      'com.apple.developer.team-identifier': TEAM,
      'get-task-allow': true,
      ...(identifier === 'to.example.app' ? { 'keychain-access-groups': [`${TEAM}.to.example.app`] } : {})
    })
    const covered = {
      '': { profile: appProfile, entitlements: entitlements('to.example.app') },
      'PlugIns/Ext.appex': { profile: extensionProfile, entitlements: entitlements('to.example.app.ext') }
    }
    const identifiers = { '': 'to.example.app', 'PlugIns/Ext.appex': 'to.example.app.ext' }
    const check = (bundle, over = {}) => {
      const signed = signingPlan(bundle, covered)
      return problemsInSignatures(signed, { team: TEAM, adHoc: true, identifiers, ...over })
    }

    const good = build('good')
    signAll(signingPlan(good, covered), { identity: '-', keychain: null })
    held('a bundle signed inside out with its entitlements and profile holds', [], check(good))

    const tampered = build('tampered')
    signAll(signingPlan(tampered, covered), { identity: '-', keychain: null })
    writeFileSync(join(tampered, 'Frameworks', 'Lib.framework', 'Lib'), 'changed after signing')
    held('a library changed after signing is told', true, check(tampered).some((each) => each.startsWith('the bundle does not verify') || each.includes('does not verify')))

    const other = build('other')
    signAll(signingPlan(other, covered), { identity: '-', keychain: null })
    const asked = { ...covered, '': { ...covered[''], entitlements: { ...covered[''].entitlements, 'keychain-access-groups': [`${TEAM}.to.example.app`, `${TEAM}.to.example.app.shared`] } } }
    held('entitlements other than the ones sealed are told', true,
      problemsInSignatures(signingPlan(other, asked), { team: TEAM, adHoc: true, identifiers }).some((each) => each.includes('is sealed with'))
    )

    const swapped = build('swapped')
    signAll(signingPlan(swapped, covered), { identity: '-', keychain: null })
    writeFileSync(profileFile, 'another profile')
    held('a profile other than the one embedded is told', true, check(swapped).some((each) => each.includes('does not carry the profile')))
    writeFileSync(profileFile, 'a profile')

    const unsigned = build('unsigned')
    held('a bundle that was never signed is told', true, check(unsigned).some((each) => each.includes('does not verify')))

    // Verified as a real signature would be, an ad hoc one has no certificate and is told so.
    held('a signature with no certificate is told when one was asked for', true,
      problemsInSignatures(signingPlan(good, covered), { team: TEAM, identifiers, identity: WANTED }).some((each) => each.includes('it is signed with no certificate')))
    held('a profile that has expired is told', true, check(good, { now: new Date('2100-01-01') }).some((each) => each.includes('has expired')))
    held('a phone the profile does not list is told', true, check(good, { device: '00008140-1111' }).some((each) => each.includes('does not list the phone')))
    held('a bundle that names an identifier it was not given is told', true, check(good, { identifiers: { '': 'to.example.wrong' } }).some((each) => each.includes('its identifier is to.example.app')))
  }
}

// -- a real profile -----------------------------------------------------------------------------

if (process.env.KR_TEST_PROFILE && existsSync(process.env.KR_TEST_PROFILE)) {
  const real = readProfile(process.env.KR_TEST_PROFILE)
  held('a real profile names its team, its UUID, an expiry in the future, an application identifier under the team and a certificate', true,
    /^[A-Z0-9]{10}$/.test(real.team) && real.uuid.length === 36 && real.expires > new Date() && real.entitlements['application-identifier'].startsWith(`${real.team}.`) &&
      real.certificates.length > 0 && real.certificates.every((each) => /^[0-9A-F]{40}$/.test(each)))
} else {
  skipped('reading a real profile', 'KR_TEST_PROFILE names no profile')
}

rmSync(work, { recursive: true, force: true })
if (failures > 0) {
  console.error(`${failures} case(s) failed`)
  process.exit(1)
}
if (notRun > 0) {
  console.error(`${notRun} case(s) were not run`)
  process.exit(3)
}
console.log('every case held')
