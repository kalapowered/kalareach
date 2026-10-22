buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:8.11.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.25")
    }
}

/*
 * The platform TLS verifier's Kotlin half is published as a Maven artefact by the verifier's own
 * project, and the companion's platform plugin depends on it. The Rust side calls the Kotlin side
 * by name and layout, so the two are one component: the version linked is the one `Cargo.lock`
 * holds for the crate that carries it, and a lock that holds two of them has no single answer, so
 * the build stops. The application's build checks the bytes of what it links as well.
 *
 * The repository is the project's archive branch at one commit, and serves the verifier's group
 * and nothing else: no other repository can supply that group, and the archive supplies no other.
 *
 * Why 0.2.0 and not the 0.1.1 that shipped in the crate: Android's check of a certificate's
 * revocation status, inside the verifier's Kotlin half, fetches the revocation list a certificate
 * authority publishes over plain HTTP, and a release build allows no cleartext traffic. Let's
 * Encrypt, Google Trust Services and SSL.com no longer publish OCSP, so the certificates Cloudflare
 * serves for the deployed service name a list and nothing else; the refused fetch was reported as a
 * revoked certificate, and a release build could reach no such service (a debug build allows
 * cleartext and was unaffected). 0.2.0 merges a network security configuration into the
 * application that permits cleartext only to the hosts the library lists (the hosts the public
 * authorities publish their revocation lists on, some of them general web hosts) and leaves it off
 * everywhere else. https://github.com/rustls/rustls-platform-verifier/issues/221
 */
extra["rustlsPlatformVerifierKotlinVersion"] = run {
    val lines = file("../../../../../Cargo.lock").readLines()
    val locked = lines.indices.filter { lines[it].trim() == "name = \"rustls-platform-verifier-android\"" }
        .map { at -> lines.drop(at + 1).first { it.trimStart().startsWith("version = ") }.substringAfter('"').substringBefore('"') }
    check(locked.size == 1) {
        "Cargo.lock holds ${locked.size} versions of rustls-platform-verifier-android: this build links one Kotlin half"
    }
    locked.single()
}

allprojects {
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    url = uri("https://github.com/rustls/rustls-platform-verifier/raw/1aa691352a5e0c215210dfc9a3c2f2078639dc91/android-release-support/maven/")
                    metadataSources { mavenPom(); artifact() }
                }
            }
            filter { includeGroup("org.rustls") }
        }
        google()
        mavenCentral()
    }
}

tasks.register("clean").configure {
    delete("build")
}

