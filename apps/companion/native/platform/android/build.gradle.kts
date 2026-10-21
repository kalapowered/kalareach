/*
 * The Android half of the companion's platform plugin: the Auth Tab and Custom Tab sign-in
 * session, the Keystore-sealed secret store, the TLS verifier's start and the scanner that reads a
 * QR code. Its decisions live in the
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
    // The camera behind the scanner that reads a pairing code. The library with the native code is
    // pinned by version here and by bytes in the application's build.
    implementation("androidx.camera:camera-core") { version { strictly("1.4.2") } }
    implementation("androidx.camera:camera-camera2:1.4.2")
    implementation("androidx.camera:camera-lifecycle:1.4.2")
    implementation("androidx.camera:camera-view:1.4.2")
    // The platform TLS verifier's Kotlin half, from the local Maven repository inside its Rust
    // crate, which the application's root build declares for every project.
    implementation("rustls:rustls-platform-verifier:0.1.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
