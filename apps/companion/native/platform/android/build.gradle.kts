/*
 * The Android half of the companion's platform plugin: the Auth Tab and Custom Tab sign-in
 * session, the Keystore-sealed secret store, the TLS verifier's start, the scanner that reads a
 * QR code and the prompt that confirms the owner is present. Its decisions live in the
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
        minSdk = 29
        consumerProguardFiles("consumer-rules.pro")
        // The secret store's device tests, which need the Android Keystore.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation(project(":tauri-android"))
    // The decisions and the sealed-file rules, as plain Kotlin with their own tests.
    implementation(project(":krnative"))
    // The activity results the Auth Tab and the Custom Tab return through, at the application's
    // own version.
    implementation("androidx.activity:activity:1.10.1")
    implementation("androidx.browser:browser:1.9.0")
    // The camera behind the scanner that reads a pairing code. The application's Kotlin is 1.9, which
    // reads library metadata up to 2.0, and CameraX 1.5 and later carry 2.1: this is the newest of
    // the line that fits. The library with the native code is pinned by version here and by bytes in
    // the application's build.
    implementation("androidx.camera:camera-core") { version { strictly("1.4.2") } }
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    // The prompt the system draws to confirm that the phone's owner is in front of it, at the version
    // the application and its voice ceremony use.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // The platform TLS verifier's Kotlin half, from the Maven repository its project publishes,
    // which the application's root build declares for every project. It carries the network
    // security configuration that lets the verifier fetch the revocation lists certificate
    // authorities publish over HTTP: without it a release build, which allows no cleartext traffic,
    // reports a certificate whose authority publishes only such a list as revoked.
    implementation("org.rustls:rustls-platform-verifier:0.2.0")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
