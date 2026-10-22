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
 * project, and the companion's platform plugin depends on it. The application resolves the plugin's
 * dependencies through its own repositories, so the repository is declared here for every project,
 * limited to the verifier's group. The artefact's version is the Rust crate's (the two must be the
 * same, so the application's build checks it against `Cargo.lock`), and its bytes are pinned there
 * as well as its version.
 *
 * Why version 0.2.0 and not the 0.1.1 that shipped in the crate: Android's check of a certificate's
 * revocation status, inside the verifier's Kotlin half, fetches the revocation list a certificate
 * authority publishes over plain HTTP, and a release build allows no cleartext traffic. Let's
 * Encrypt, Google Trust Services and SSL.com no longer publish OCSP, so the certificates Cloudflare
 * serves for the deployed service name a list and nothing else; the refused fetch was reported as a
 * revoked certificate, and a release build could reach no such service (a debug build allows
 * cleartext and was unaffected). 0.2.0 merges a network security configuration into the
 * application that permits cleartext only to the public authorities' revocation-list hosts and
 * leaves it off everywhere else. https://github.com/rustls/rustls-platform-verifier/issues/221
 */
allprojects {
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri("https://github.com/rustls/rustls-platform-verifier/raw/maven-archive/android-release-support/maven/")
            metadataSources { mavenPom(); artifact() }
            content { includeGroup("org.rustls") }
        }
    }
}

tasks.register("clean").configure {
    delete("build")
}

