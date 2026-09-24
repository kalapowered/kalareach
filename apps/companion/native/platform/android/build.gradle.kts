/*
 * The Android half of the companion's platform plugin: the Auth Tab and Custom Tab sign-in
 * session, the Keystore-sealed secret store and the TLS verifier's start. Its decisions live in the
 * plugin's Rust crate and in the plain Kotlin module `:krnative`, where tests reach them without a
 * device.
 */

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "to.kala.reach.platform"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

/*
 * The platform TLS verifier's Kotlin half ships inside its Rust crate as a local Maven repository,
 * so the crate's place on disk is asked of Cargo rather than assumed.
 */
val rustlsPlatformVerifierRepository: File by lazy {
    val metadata = providers.exec {
        workingDir = file("../../../../..")
        commandLine(
            "cargo", "metadata", "--format-version", "1", "--filter-platform", "aarch64-linux-android"
        )
    }.standardOutput.asText.get()
    @Suppress("UNCHECKED_CAST")
    val packages = (groovy.json.JsonSlurper().parseText(metadata) as Map<String, Any>)["packages"]
        as List<Map<String, Any>>
    val manifest = packages.first { it["name"] == "rustls-platform-verifier-android" }["manifest_path"]
        as String
    File(File(manifest).parentFile, "maven")
}

repositories {
    maven {
        url = uri(rustlsPlatformVerifierRepository)
        metadataSources { mavenPom(); artifact() }
    }
}

dependencies {
    implementation(project(":tauri-android"))
    // The decisions and the sealed-file rules, as plain Kotlin with their own tests.
    implementation(project(":krnative"))
    implementation("androidx.browser:browser:1.9.0")
    implementation("rustls:rustls-platform-verifier:0.1.1")
}
