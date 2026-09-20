import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

/**
 * The application's hand-written Android sources -- the push receiver, the background worker, the
 * keystore reader and everything else that needs the framework -- kept outside this generated
 * directory so regenerating the project never touches them.
 *
 * The directory is checked here, at configuration time, because Gradle treats a source directory
 * that does not exist as an empty one. A path that resolves nowhere compiles nothing, packages
 * nothing and still reports a successful build, so a mistake in it is otherwise silent: the
 * application loses its push receiver and no build output says so. A wrong path fails here, by
 * name, instead.
 */
val handWrittenNativeSources = file("../../../../native/android/android/src/main/java")
check(handWrittenNativeSources.isDirectory) {
    "The application's hand-written Android sources are not at $handWrittenNativeSources"
}

android {
    compileSdk = 36
    // Android 15 and later run with 16 KB memory pages, and a library linked for 4 KB pages is
    // refused. This is the first toolchain whose linker aligns to 16 KB by default, so it is named
    // rather than left to whichever one happens to be installed.
    ndkVersion = "28.2.13676358"
    namespace = "to.kala.reach.companion"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "to.kala.reach.companion"
        minSdk = 24
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
    sourceSets {
        getByName("main").java.srcDir(handWrittenNativeSources)
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    // The decisions the receiver and the worker make, as plain Kotlin with its own tests.
    implementation(project(":krnative"))
    // Native WebRTC. Section 15 paragraph 2 requires native WebRTC and native platform audio to own
    // capture and playback, so the application links the library itself rather than reaching a
    // WebView's `getUserMedia`. The constraint is strict rather than a plain version: a checksum
    // verifies bytes, and only a strict constraint stops conflict resolution raising the version
    // that is fetched. This artefact's PT_LOAD segments align to 16 KiB, which is what Android 15
    // and later require.
    implementation("io.github.webrtc-sdk:android") { version { strictly("150.7871.01") } }
    // The device-owner ceremony an unlocked-screen confirmation needs, with the device-credential
    // fallback for a device that has no biometric enrolled.
    implementation("androidx.biometric:biometric:1.4.0")
    // Push, and the scheduler that runs what a message callback cannot finish in its budget.
    implementation("com.google.firebase:firebase-messaging:24.1.2")
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    // Keys wrapped by the hardware-backed keystore, which is where a preview key belongs.
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

/*
 * What this build is allowed to link.
 *
 * A version number selects an artefact; it does not establish that the same bytes arrive next
 * time. The media library carries native code into the packaged application, so its bytes are
 * checked as well as its version. Gradle's own `verification-metadata.xml` is deliberately not
 * used: once that file exists Gradle verifies every artefact in the graph and fails on any without
 * an entry, which would make one pinned library the whole build's problem. This checks the one
 * artefact this task pinned, and says plainly when it cannot find it.
 */
val voiceMediaSha256 = "0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0"

val verifyVoiceMedia by tasks.registering {
    description = "Checks the native media library's bytes against the digest this build pins."
    doLast {
        val artefact = configurations.getByName("debugRuntimeClasspath")
            .resolvedConfiguration
            .resolvedArtifacts
            .firstOrNull {
                it.moduleVersion.id.group == "io.github.webrtc-sdk" &&
                    it.moduleVersion.id.name == "android"
            }
            ?: throw GradleException(
                "the native media library io.github.webrtc-sdk:android was not resolved, so its " +
                    "bytes could not be checked"
            )
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(artefact.file.readBytes())
            .joinToString("") { "%02x".format(it) }
        if (digest != voiceMediaSha256) {
            throw GradleException(
                "the native media library's bytes are not the ones this build pins: expected " +
                    "$voiceMediaSha256, found $digest"
            )
        }
    }
}

tasks.named("preBuild") { dependsOn(verifyVoiceMedia) }

apply(from = "tauri.build.gradle.kts")